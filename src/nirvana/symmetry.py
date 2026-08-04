from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Iterable

from .models import CodeLocation, Hypothesis


@dataclass(frozen=True, slots=True)
class OperationSummary:
    """Language-neutral facts supplied by a dialect frontend.

    Frontends normalize their native syntax into state, guard, and effect facts.
    The analyzer deliberately does not infer evidence strength from the frontend:
    every result remains a hypothesis until independently verified.
    """

    operation_id: str
    dialect: str
    module: str
    name: str
    location: CodeLocation
    entry_point: bool
    state_reads: frozenset[str] = frozenset()
    state_writes: frozenset[str] = frozenset()
    guards: frozenset[str] = frozenset()
    effects: frozenset[str] = frozenset()
    graph_slice: tuple[str, ...] = ()
    frontend: str = "dialect-frontend"


@dataclass(frozen=True, slots=True)
class InverseRelation:
    left_verb: str
    right_verb: str
    label: str


INVERSE_RELATIONS: tuple[InverseRelation, ...] = (
    InverseRelation("deposit", "withdraw", "deposit/withdraw"),
    InverseRelation("deposit", "redeem", "deposit/redeem"),
    InverseRelation("supply", "withdraw", "supply/withdraw"),
    InverseRelation("mint", "burn", "mint/burn"),
    InverseRelation("mint", "redeem", "mint/redeem"),
    InverseRelation("borrow", "repay", "borrow/repay"),
    InverseRelation("stake", "unstake", "stake/unstake"),
    InverseRelation("lock", "unlock", "lock/unlock"),
    InverseRelation("wrap", "unwrap", "wrap/unwrap"),
    InverseRelation("buy", "sell", "buy/sell"),
    InverseRelation("add", "remove", "add/remove"),
    InverseRelation("increase", "decrease", "increase/decrease"),
    InverseRelation("credit", "debit", "credit/debit"),
    InverseRelation("escrow", "release", "escrow/release"),
    InverseRelation("open", "close", "open/close"),
    InverseRelation("enter", "exit", "enter/exit"),
    InverseRelation("grant", "revoke", "grant/revoke"),
    InverseRelation("enable", "disable", "enable/disable"),
    InverseRelation("pause", "unpause", "pause/unpause"),
    InverseRelation("send", "receive", "send/receive"),
)


PARITY_GUARDS = frozenset(
    {
        "authority",
        "pause",
        "reentrancy",
        "deadline",
        "nonce-replay",
        "oracle-integrity",
    }
)
ACCOUNTING_WORDS = (
    "asset",
    "balance",
    "cash",
    "collateral",
    "credit",
    "debt",
    "deposit",
    "escrow",
    "fee",
    "liability",
    "liquidity",
    "position",
    "principal",
    "reserve",
    "reward",
    "share",
    "stake",
    "supply",
    "total",
)
SECURITY_EFFECTS = frozenset(
    {
        "asset-transfer",
        "asset-supply",
        "authority-change",
        "external-control",
        "delegated-execution",
    }
)


class SymmetryAnalyzer:
    """Compare inverse operations after dialect-specific semantic normalization."""

    def __init__(
        self,
        max_hypotheses: int = 512,
        max_pair_comparisons: int = 250_000,
    ):
        if max_hypotheses < 1 or max_pair_comparisons < 1:
            raise ValueError("symmetry analysis limits must be positive")
        self.max_hypotheses = max_hypotheses
        self.max_pair_comparisons = max_pair_comparisons
        self.truncated = False

    def analyze(self, operations: Iterable[OperationSummary]) -> list[Hypothesis]:
        self.truncated = False
        grouped: dict[tuple[str, str], list[OperationSummary]] = {}
        for operation in operations:
            if operation.entry_point:
                grouped.setdefault((operation.dialect, operation.module), []).append(operation)

        hypotheses: list[Hypothesis] = []
        seen: set[str] = set()
        comparisons = 0
        for group in grouped.values():
            ordered = sorted(group, key=lambda item: (item.name.lower(), item.operation_id))
            for index, left in enumerate(ordered):
                for right in ordered[index + 1 :]:
                    comparisons += 1
                    if comparisons > self.max_pair_comparisons:
                        self.truncated = True
                        return hypotheses
                    match = _inverse_match(left.name, right.name)
                    if match is None:
                        continue
                    relation, _, _ = match
                    self._compare_pair(relation, left, right, hypotheses, seen)
                    if len(hypotheses) >= self.max_hypotheses:
                        return hypotheses
        return hypotheses

    def _compare_pair(
        self,
        relation: InverseRelation,
        left: OperationSummary,
        right: OperationSummary,
        hypotheses: list[Hypothesis],
        seen: set[str],
    ) -> None:
        shared_state = (
            left.state_reads | left.state_writes
        ) & (right.state_reads | right.state_writes)
        shared_effects = (left.effects & right.effects) & SECURITY_EFFECTS
        has_security_context = bool(shared_state or shared_effects)

        left_accounting = _accounting_state(left.state_writes)
        right_accounting = _accounting_state(right.state_writes)
        state_difference = left_accounting ^ right_accounting
        one_sided_accounting = bool(left_accounting) != bool(right_accounting)
        both_move_assets = "asset-transfer" in left.effects and "asset-transfer" in right.effects
        if state_difference and (
            bool(shared_state & (left_accounting | right_accounting))
            or (both_move_assets and one_sided_accounting)
        ):
            detail = _side_difference(left.name, right.name, left_accounting, right_accounting)
            self._append(
                hypotheses,
                seen,
                relation,
                left,
                right,
                category="state-parity",
                threat_lens="accounting",
                security_property=(
                    f"Inverse {relation.label} paths must preserve the same coupled accounting state"
                ),
                violation=f"The paired operations have asymmetric accounting writes: {detail}",
                assets=sorted(shared_state | state_difference) or ["coupled protocol accounting"],
                capabilities=[
                    f"exercise both {left.name} and {right.name}",
                    "choose an amount or sequence that accumulates the asymmetric state transition",
                ],
                plan=[
                    "Confirm the declaration-resolved writes and internal-call closure on both paths",
                    "Derive the conservation equation for the paired operations and identify the omitted term",
                    "Execute the shortest alternating sequence that makes recorded and realizable state diverge",
                    "Patch the missing update and retain the sequence as a negative control",
                ],
            )

        guard_difference = (left.guards ^ right.guards) & PARITY_GUARDS
        if guard_difference and has_security_context:
            detail = _side_difference(left.name, right.name, left.guards, right.guards, guard_difference)
            self._append(
                hypotheses,
                seen,
                relation,
                left,
                right,
                category="guard-parity",
                threat_lens="access-control",
                security_property=(
                    f"Inverse {relation.label} paths must apply equivalent safety gates unless the asymmetry is intentional"
                ),
                violation=f"The paired operations have asymmetric security guards: {detail}",
                assets=sorted(shared_state) or ["paired state transition"],
                capabilities=[f"reach the less-restricted side of the {relation.label} pair"],
                plan=[
                    "Resolve inherited modifiers and dominating branch conditions on both operations",
                    "Explain each one-sided authority, pause, replay, oracle, or callback guard from protocol invariants",
                    "Exercise the less-restricted path in the state where the counterpart is blocked",
                    "Reject the candidate if the asymmetry is required and cannot change a security outcome",
                ],
            )

        left_security_effects = left.effects & SECURITY_EFFECTS
        right_security_effects = right.effects & SECURITY_EFFECTS
        effect_difference = left_security_effects ^ right_security_effects
        if effect_difference and shared_state and (
            not left_security_effects or not right_security_effects
        ):
            detail = _side_difference(
                left.name,
                right.name,
                left_security_effects,
                right_security_effects,
            )
            self._append(
                hypotheses,
                seen,
                relation,
                left,
                right,
                category="effect-parity",
                threat_lens="callback-and-sequencing",
                security_property=(
                    f"Inverse {relation.label} paths must realize complementary security-sensitive effects"
                ),
                violation=f"Only one side exposes a normalized security-sensitive effect: {detail}",
                assets=sorted(shared_state),
                capabilities=[f"invoke both sides of the {relation.label} pair"],
                plan=[
                    "Resolve indirect calls and asset movements on both paths",
                    "Compare the before/after state and external balance deltas for the same principal amount",
                    "Determine whether the missing effect locks value, creates unbacked claims, or is an intentional internal-only transition",
                ],
            )

    def _append(
        self,
        hypotheses: list[Hypothesis],
        seen: set[str],
        relation: InverseRelation,
        left: OperationSummary,
        right: OperationSummary,
        *,
        category: str,
        threat_lens: str,
        security_property: str,
        violation: str,
        assets: list[str],
        capabilities: list[str],
        plan: list[str],
    ) -> None:
        stable = "\0".join(
            (
                "symmetry-v1",
                category,
                relation.label,
                left.operation_id,
                right.operation_id,
                violation,
            )
        ).encode()
        digest = hashlib.sha256(stable).hexdigest().upper()
        hypothesis_id = f"H-SYM-{digest[:16]}"
        if hypothesis_id in seen or len(hypotheses) >= self.max_hypotheses:
            return
        seen.add(hypothesis_id)
        assumptions = [
            f"{left.frontend} and {right.frontend} summaries correspond to the captured target",
            "name pairing indicates intended inverse behavior; protocol documentation may prove otherwise",
            "the normalized asymmetry is a review lead, not vulnerability evidence",
        ]
        hypotheses.append(
            Hypothesis(
                hypothesis_id=hypothesis_id,
                security_property=security_property,
                suspected_violation=violation,
                affected_assets=assets,
                required_attacker_capabilities=capabilities,
                assumptions=assumptions,
                candidate_locations=[left.location, right.location],
                verification_plan=plan,
                threat_lens=threat_lens,
                generator=f"symmetry-analysis:{category}",
                graph_slice=sorted(set(left.graph_slice) | set(right.graph_slice)),
                unresolved_assumptions=list(assumptions),
                proposed_next_experiment=plan[0],
            )
        )


def operation_summaries_from_graph(graph: object) -> list[OperationSummary]:
    """Project syntax-only SSG slices into the same frontend-neutral contract.

    Typed dialects are intentionally skipped: their compiler frontend supplies
    declaration-resolved summaries and should not be diluted by lexical facts.
    """

    graph_nodes = list(getattr(graph, "nodes", []))
    graph_edges = list(getattr(graph, "edges", []))
    maturity = {
        str(item.dialect): str(item.maturity.value)
        for item in getattr(graph, "support", [])
    }
    nodes = {str(item.node_id): item for item in graph_nodes}
    outgoing: dict[str, list[object]] = {}
    modules: dict[str, str] = {}
    for edge in graph_edges:
        outgoing.setdefault(str(edge.source), []).append(edge)
        source = nodes.get(str(edge.source))
        target = nodes.get(str(edge.target))
        if (
            str(edge.kind) == "contains"
            and source is not None
            and target is not None
            and str(source.kind) == "module"
        ):
            modules[str(target.node_id)] = str(source.label)

    summaries: list[OperationSummary] = []
    for node in graph_nodes:
        if str(node.kind) not in {"symbol", "entry_point"} or node.location is None:
            continue
        dialect = str(node.dialect)
        if maturity.get(dialect) != "syntax_only":
            continue
        children: list[tuple[object, object]] = []
        for edge in outgoing.get(str(node.node_id), []):
            child = nodes.get(str(edge.target))
            if child is not None:
                children.append((edge, child))
        state_reads = frozenset(
            _normalise_fact(str(child.label))
            for edge, child in children
            if str(child.kind) == "state" and str(edge.kind) in {"reads", "reaches"}
        )
        state_writes = frozenset(
            _normalise_fact(str(child.label))
            for edge, child in children
            if str(child.kind) == "state" and str(edge.kind) == "writes"
        )
        guards: set[str] = set()
        effects: set[str] = set()
        for edge, child in children:
            child_kind = str(child.kind)
            label = str(child.label)
            edge_kind = str(edge.kind)
            if child_kind in {"invariant", "authority"} or edge_kind in {
                "guards",
                "administers",
            }:
                guards.update(classify_guard_text(label))
                if child_kind == "authority":
                    guards.add("authority")
            effects.update(classify_effect_text(label, child_kind, edge_kind))
        location = CodeLocation(**dict(node.location))
        summaries.append(
            OperationSummary(
                operation_id=str(node.node_id),
                dialect=dialect,
                module=modules.get(str(node.node_id), location.path),
                name=str(node.label),
                location=location,
                entry_point=str(node.kind) == "entry_point",
                state_reads=state_reads,
                state_writes=state_writes,
                guards=frozenset(guards),
                effects=frozenset(effects),
                graph_slice=tuple(
                    [str(node.node_id), *[str(child.node_id) for _, child in children[:32]]]
                ),
                frontend="security-semantic-graph:syntax_only",
            )
        )
    return summaries


def classify_guard_text(value: str) -> frozenset[str]:
    text = _normalise_fact(value)
    categories: set[str] = set()
    if any(word in text for word in ("owner", "admin", "auth", "role", "govern", "permission", "sender", "caller", "signer")):
        categories.add("authority")
    if "paus" in text or "emergency stop" in text:
        categories.add("pause")
    if any(word in text for word in ("nonreentrant", "reentr", "mutex", "entered")):
        categories.add("reentrancy")
    if any(word in text for word in ("deadline", "expiry", "expired", "timestamp", "timeout")):
        categories.add("deadline")
    if any(word in text for word in ("nonce", "replay", "signature", "domain separator")):
        categories.add("nonce-replay")
    if any(word in text for word in ("oracle", "price", "round", "updated", "stale", "heartbeat")):
        categories.add("oracle-integrity")
    return frozenset(categories)


def classify_effect_text(value: str, kind: str = "", edge_kind: str = "") -> frozenset[str]:
    text = _normalise_fact(value)
    categories: set[str] = set()
    if edge_kind == "transfers" or any(
        word in text
        for word in ("transfer", "withdraw", "deposit", "send", "receive", "payout")
    ):
        categories.add("asset-transfer")
    if any(word in text for word in ("mint", "burn", "issue", "redeem")):
        categories.add("asset-supply")
    if kind == "trust_boundary" or any(
        word in text for word in ("external call", "callback", "staticcall")
    ):
        categories.add("external-control")
    if "delegatecall" in text or kind == "upgrade":
        categories.add("delegated-execution")
    if any(word in text for word in ("set owner", "grant", "revoke", "admin", "role")):
        categories.add("authority-change")
    return frozenset(categories)


def _inverse_match(
    left_name: str, right_name: str
) -> tuple[InverseRelation, str, str] | None:
    left_tokens = _name_tokens(left_name)
    right_tokens = _name_tokens(right_name)
    for relation in INVERSE_RELATIONS:
        left_verb = relation.left_verb
        right_verb = relation.right_verb
        if _same_operation_shape(left_tokens, right_tokens, left_verb, right_verb):
            return relation, left_verb, right_verb
        if _same_operation_shape(left_tokens, right_tokens, right_verb, left_verb):
            return relation, right_verb, left_verb
    return None


def _same_operation_shape(
    left: tuple[str, ...],
    right: tuple[str, ...],
    left_verb: str,
    right_verb: str,
) -> bool:
    if left_verb not in left or right_verb not in right:
        return False
    left_shape = list(left)
    right_shape = list(right)
    left_shape[left_shape.index(left_verb)] = "<inverse>"
    right_shape[right_shape.index(right_verb)] = "<inverse>"
    return left_shape == right_shape


def _name_tokens(value: str) -> tuple[str, ...]:
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return tuple(item.lower() for item in re.findall(r"[A-Za-z0-9]+", separated))


def _normalise_fact(value: str) -> str:
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    return " ".join(re.findall(r"[A-Za-z0-9]+", separated.lower()))


def _accounting_state(values: frozenset[str]) -> frozenset[str]:
    return frozenset(
        value
        for value in values
        if any(word in value.lower() for word in ACCOUNTING_WORDS)
    )


def _side_difference(
    left_name: str,
    right_name: str,
    left_values: frozenset[str],
    right_values: frozenset[str],
    restrict: frozenset[str] | None = None,
) -> str:
    selected = restrict if restrict is not None else left_values ^ right_values
    left_only = sorted((left_values - right_values) & selected)
    right_only = sorted((right_values - left_values) & selected)
    parts: list[str] = []
    if left_only:
        parts.append(f"{left_name} only [{', '.join(left_only)}]")
    if right_only:
        parts.append(f"{right_name} only [{', '.join(right_only)}]")
    return "; ".join(parts) or "normalized sets differ"
