from __future__ import annotations

import os
import json
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .contracts import validate_contract
from .intake import FileRecord, ScopeManifest
from .models import CodeLocation, Hypothesis, SupportMaturity
from .symmetry import SymmetryAnalyzer, operation_summaries_from_graph
from .util import canonical_json, jsonable, sha256_bytes, sha256_file, utc_now


MAX_GRAPH_SOURCE_BYTES = 5_000_000
MAX_SYMBOLS_PER_FILE = 2_000
MAX_CONCEPTS_PER_FILE = 1_000
MAX_GRAPH_NODES = 250_000
MAX_GRAPH_EDGES = 500_000
MAX_GRAPH_HYPOTHESES = 10_000


@dataclass(frozen=True, slots=True)
class DialectDefinition:
    name: str
    suffixes: frozenset[str]
    concepts: tuple[str, ...]
    runtime_adapters: tuple[str, ...] = ()


DIALECTS: tuple[DialectDefinition, ...] = (
    DialectDefinition(
        "evm",
        frozenset({".sol", ".vy", ".yul"}),
        (
            "storage",
            "delegatecall",
            "proxy implementation",
            "calldata",
            "sender/value",
            "reentrancy",
            "gas",
            "transaction ordering",
        ),
        ("forge-test", "echidna", "medusa", "halmos"),
    ),
    DialectDefinition(
        "solana",
        frozenset({".rs"}),
        (
            "account owner",
            "signer",
            "writable account",
            "PDA seeds",
            "CPI",
            "remaining accounts",
            "account aliasing",
            "Token-2022 extensions",
        ),
    ),
    DialectDefinition(
        "move-sui",
        frozenset({".move"}),
        (
            "objects",
            "abilities",
            "capabilities",
            "shared objects",
            "ownership transfer",
            "dynamic fields",
            "transaction blocks",
        ),
    ),
    DialectDefinition(
        "rust-native",
        frozenset({".rs", ".c", ".cc", ".cpp", ".h", ".hpp"}),
        (
            "borrowing",
            "unsafe blocks",
            "lifetimes",
            "FFI",
            "memory layout",
            "concurrency",
            "integer and pointer semantics",
        ),
        ("cargo-test",),
    ),
    DialectDefinition(
        "jvm",
        frozenset({".java", ".kt", ".kts", ".scala"}),
        ("reflection", "serialisation", "class loading", "taint", "exceptions", "concurrency"),
    ),
    DialectDefinition(
        "wasm",
        frozenset({".wasm", ".wat"}),
        ("linear memory", "host imports", "sandbox assumptions", "indirect calls"),
    ),
    DialectDefinition(
        "dlt-consensus",
        frozenset({".go", ".rs", ".java", ".kt", ".py"}),
        ("replicas", "quorums", "message ordering", "partitions", "leader changes", "equivocation", "finality"),
    ),
    DialectDefinition(
        "web-api",
        frozenset({".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".php"}),
        ("authentication", "authorisation", "request flows", "sessions", "deserialisation", "databases", "browser trust boundaries"),
        ("pytest", "node-test"),
    ),
)


@dataclass(slots=True)
class SemanticNode:
    node_id: str
    kind: str
    label: str
    dialect: str
    location: dict[str, Any] | None
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class SemanticEdge:
    source: str
    target: str
    kind: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class DialectSupport:
    dialect: str
    maturity: SupportMaturity
    frontends: list[str]
    runtime_adapters: list[str]
    concepts: list[str]
    limitations: list[str]


@dataclass(slots=True)
class SecuritySemanticGraph:
    schema_version: str
    created_at: str
    target_snapshot_sha256: str
    nodes: list[SemanticNode]
    edges: list[SemanticEdge]
    support: list[DialectSupport]
    warnings: list[str]

    def to_dict(self) -> dict[str, Any]:
        value = jsonable(self)
        validate_contract(value, "semantic-graph.schema.json")
        return value

    def sha256(self) -> str:
        return sha256_bytes(canonical_json(self.to_dict()).encode("utf-8"))

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "SecuritySemanticGraph":
        validate_contract(value, "semantic-graph.schema.json")
        return cls(
            schema_version=str(value["schema_version"]),
            created_at=str(value["created_at"]),
            target_snapshot_sha256=str(value["target_snapshot_sha256"]),
            nodes=[SemanticNode(**item) for item in value["nodes"]],
            edges=[SemanticEdge(**item) for item in value["edges"]],
            support=[
                DialectSupport(
                    dialect=str(item["dialect"]),
                    maturity=SupportMaturity(item["maturity"]),
                    frontends=[str(entry) for entry in item["frontends"]],
                    runtime_adapters=[str(entry) for entry in item["runtime_adapters"]],
                    concepts=[str(entry) for entry in item["concepts"]],
                    limitations=[str(entry) for entry in item["limitations"]],
                )
                for item in value["support"]
            ],
            warnings=[str(item) for item in value["warnings"]],
        )


_SYMBOL_PATTERNS: dict[str, re.Pattern[str]] = {
    "evm": re.compile(
        r"\b(?:function|modifier|constructor)\s+([A-Za-z_$][A-Za-z0-9_$]*)?\s*\([^;{}]*\)[^{;]*\{",
        re.MULTILINE,
    ),
    "move-sui": re.compile(r"\b(?:public\s+)?(?:entry\s+)?fun\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]"),
    "rust-native": re.compile(r"\b(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]"),
    "solana": re.compile(r"\b(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]"),
    "jvm": re.compile(r"(?m)^\s*(?:public|protected|private|static|final|synchronized|abstract|native|\s)+\s*[A-Za-z_$][\w$<>, ?\[\]]*\s+([A-Za-z_$][\w$]*)\s*\([^;]*\)\s*(?:throws[^\{]+)?\{"),
    "web-api": re.compile(r"(?m)^\s*(?:async\s+)?(?:def|function)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\("),
    "dlt-consensus": re.compile(r"(?m)^\s*(?:pub\s+)?(?:async\s+)?(?:fn|def|func)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("),
    "wasm": re.compile(r"\(func\s+(\$[A-Za-z0-9_.-]+)"),
}


_CONCEPT_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("asset", "asset", re.compile(r"\b(?:asset|balance|token|vault|collateral|share|liquidity|amount|funds?|escrow)\b", re.I)),
    ("authority", "authority", re.compile(r"\b(?:owner|admin|governance|authority|authori[sz]ed|signer|capability|role|multisig|pda)\b", re.I)),
    ("trust_boundary", "external call", re.compile(r"\b(?:delegatecall|staticcall|call\s*\{|call\s*\(|invoke_signed|invoke\s*\(|cpi|ffi|fetch\s*\(|requests?\.|http|deserialize|external)\b", re.I)),
    ("upgrade", "upgrade path", re.compile(r"\b(?:upgrade|implementation|proxy|migrat(?:e|ion)|governance|setcode|classloader)\b", re.I)),
    ("invariant", "security check", re.compile(r"\b(?:require|assert|revert|ensure|invariant|has_role|onlyOwner|onlyRole|is_signer|writable|owner\s*==)\b", re.I)),
    ("state", "persistent state", re.compile(r"\b(?:storage|mapping|state|account|object|database|ledger|slot|persistent|global)\b", re.I)),
    ("effect", "security-sensitive effect", re.compile(r"\b(?:transfer|withdraw|mint|burn|approve|execute|settle|liquidat|borrow|repay|update|setOwner|selfdestruct|suicide|write|delete)\w*\b", re.I)),
    ("external_dependency", "external dependency", re.compile(r"\b(?:import|require\s*\(|use\s+|extern\s+crate|dependency|oracle|bridge|rpc|database|client)\b", re.I)),
)


_ENTRY_PATTERN = re.compile(
    r"\b(?:public|external|entry|handler|endpoint|route|instruction|program|callable|export)\b",
    re.I,
)


class SemanticGraphBuilder:
    """Build a bounded, language-neutral graph without executing target content.

    The generic frontend deliberately claims syntax-only maturity. Compiler-native
    artefacts can raise a dialect to ``typed`` when their hash is separately
    recorded by the workflow; lexical edges never masquerade as sound data flow.
    """

    def __init__(self, max_file_bytes: int = MAX_GRAPH_SOURCE_BYTES):
        if max_file_bytes < 1:
            raise ValueError("graph max_file_bytes must be positive")
        self.max_file_bytes = max_file_bytes

    def build(
        self,
        root: Path,
        scope: ScopeManifest,
        solc_ast: Path | None = None,
    ) -> SecuritySemanticGraph:
        target = root.resolve(strict=True)
        compiler_dialects: set[str] = set()
        nodes: dict[str, SemanticNode] = {}
        edges: dict[tuple[str, str, str], SemanticEdge] = {}
        dialects_seen: set[str] = set()
        symbol_names: dict[str, list[str]] = {}
        source_cache: dict[str, str] = {}
        warnings: list[str] = []

        for record in scope.files:
            if len(nodes) >= MAX_GRAPH_NODES:
                warnings.append(
                    f"semantic graph reached the {MAX_GRAPH_NODES}-node safety limit"
                )
                break
            if record.kind == "symlink" or record.sha256 is None:
                continue
            path = target / record.path
            dialect = _dialect_for(path, scope.frameworks)
            if dialect is None:
                continue
            dialects_seen.add(dialect)
            module_id = _node_id("module", dialect, record.path)
            nodes[module_id] = SemanticNode(
                module_id,
                "module",
                record.path,
                dialect,
                {"path": record.path, "line_start": 1, "line_end": 1, "symbol": None},
                {"sha256": record.sha256, "size": record.size},
            )
            if path.suffix.lower() == ".wasm":
                continue
            source = _read_scoped_text(path, record, min(self.max_file_bytes, scope.max_analysis_file_bytes))
            if source is None:
                continue
            source_cache[record.path] = source
            symbols = _symbols(source, dialect)
            remaining_nodes = max(0, MAX_GRAPH_NODES - len(nodes))
            for index, (name, start, end, declaration) in enumerate(
                symbols[: min(MAX_SYMBOLS_PER_FILE, remaining_nodes)]
            ):
                symbol_kind = (
                    "entry_point"
                    if _ENTRY_PATTERN.search(declaration) or _entry_point_name(name)
                    else "symbol"
                )
                symbol_id = _node_id(symbol_kind, dialect, record.path, str(start), name, str(index))
                nodes[symbol_id] = SemanticNode(
                    symbol_id,
                    symbol_kind,
                    name,
                    dialect,
                    {"path": record.path, "line_start": start, "line_end": end, "symbol": name},
                    {"declaration": declaration[:500]},
                )
                edges[(module_id, symbol_id, "contains")] = SemanticEdge(module_id, symbol_id, "contains")
                symbol_names.setdefault(name, []).append(symbol_id)

            concepts = 0
            for kind, label, pattern in _CONCEPT_PATTERNS:
                for match in pattern.finditer(source):
                    if concepts >= MAX_CONCEPTS_PER_FILE or len(nodes) >= MAX_GRAPH_NODES:
                        break
                    concepts += 1
                    line = source.count("\n", 0, match.start()) + 1
                    value = match.group(0)
                    concept_id = _node_id(kind, dialect, record.path, str(line), value.lower())
                    if concept_id not in nodes:
                        nodes[concept_id] = SemanticNode(
                            concept_id,
                            kind,
                            value,
                            dialect,
                            {"path": record.path, "line_start": line, "line_end": line, "symbol": None},
                            {"category": label},
                        )
                    owner = _enclosing_symbol(nodes.values(), record.path, line)
                    edge_source = owner.node_id if owner is not None else module_id
                    edge_kind = _edge_for_concept(kind, source, match.start())
                    if len(edges) < MAX_GRAPH_EDGES:
                        edges[(edge_source, concept_id, edge_kind)] = SemanticEdge(
                            edge_source,
                            concept_id,
                            edge_kind,
                            {"line": line},
                        )

        # Resolve only unambiguous intra-repository calls. This is a syntactic
        # relation and is labelled as such in graph properties.
        for node in list(nodes.values()):
            if len(edges) >= MAX_GRAPH_EDGES:
                warnings.append(
                    f"semantic graph reached the {MAX_GRAPH_EDGES}-edge safety limit"
                )
                break
            if node.kind not in {"symbol", "entry_point"} or node.location is None:
                continue
            source = source_cache.get(str(node.location["path"]))
            if source is None:
                continue
            start = max(0, int(node.location["line_start"]) - 1)
            end = int(node.location.get("line_end") or node.location["line_start"])
            body = "\n".join(source.splitlines()[start:end])
            for name in sorted(set(re.findall(r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(", body))):
                targets = symbol_names.get(name, [])
                if len(targets) == 1 and targets[0] != node.node_id:
                    edges[(node.node_id, targets[0], "calls")] = SemanticEdge(
                        node.node_id,
                        targets[0],
                        "calls",
                        {"resolution": "syntax-only"},
                    )

        if solc_ast is not None and _augment_evm_from_solc_ast(
            nodes, edges, target, scope, solc_ast
        ):
            compiler_dialects.add("evm")
            dialects_seen.add("evm")
        if len(nodes) >= MAX_GRAPH_NODES and not any("node safety limit" in item for item in warnings):
            warnings.append(f"semantic graph reached the {MAX_GRAPH_NODES}-node safety limit")
        if len(edges) >= MAX_GRAPH_EDGES and not any("edge safety limit" in item for item in warnings):
            warnings.append(f"semantic graph reached the {MAX_GRAPH_EDGES}-edge safety limit")
        support = [_support_record(name, compiler_dialects) for name in sorted(dialects_seen)]
        return SecuritySemanticGraph(
            schema_version="1.0.0",
            created_at=utc_now(),
            target_snapshot_sha256=scope.target_snapshot_sha256,
            nodes=sorted(nodes.values(), key=lambda item: item.node_id),
            edges=sorted(edges.values(), key=lambda item: (item.source, item.target, item.kind)),
            support=support,
            warnings=warnings,
        )


def graph_hypotheses(
    graph: SecuritySemanticGraph,
    root: Path,
    existing: Iterable[Hypothesis] = (),
    incident_templates: list[dict[str, Any]] | None = None,
) -> list[Hypothesis]:
    """Run diverse recall-oriented generators over concise graph slices."""

    existing_fingerprints = {
        _hypothesis_fingerprint(item.security_property, item.suspected_violation, item.candidate_locations)
        for item in existing
    }
    generated: list[Hypothesis] = []
    outgoing: dict[str, list[SemanticEdge]] = {}
    nodes = {node.node_id: node for node in graph.nodes}
    for edge in graph.edges:
        outgoing.setdefault(edge.source, []).append(edge)

    # Inverse-operation parity is evaluated before broad per-node recall so a
    # large repository cannot crowd the higher-context candidates out of the
    # bounded hypothesis budget. Typed dialects use their compiler frontend;
    # this projection covers every syntax-only dialect through the same model.
    symmetry_analyzer = SymmetryAnalyzer(max_hypotheses=MAX_GRAPH_HYPOTHESES)
    symmetry_candidates = symmetry_analyzer.analyze(operation_summaries_from_graph(graph))
    if symmetry_analyzer.truncated:
        graph.warnings.append(
            "symmetry analysis reached its 250000-pair safety limit"
        )
    for candidate in symmetry_candidates:
        if len(generated) >= MAX_GRAPH_HYPOTHESES:
            break
        fingerprint = _hypothesis_fingerprint(
            candidate.security_property,
            candidate.suspected_violation,
            candidate.candidate_locations,
        )
        if fingerprint in existing_fingerprints:
            continue
        existing_fingerprints.add(fingerprint)
        generated.append(candidate)

    test_text = _test_index(root)
    for node in graph.nodes:
        if len(generated) >= MAX_GRAPH_HYPOTHESES:
            if not any("hypothesis safety limit" in item for item in graph.warnings):
                graph.warnings.append(
                    f"graph candidate generation reached the {MAX_GRAPH_HYPOTHESES}-hypothesis safety limit"
                )
            break
        if node.kind not in {"symbol", "entry_point"} or node.location is None:
            continue
        children = [nodes[edge.target] for edge in outgoing.get(node.node_id, []) if edge.target in nodes]
        kinds = {child.kind for child in children}
        labels = " ".join(child.label.lower() for child in children)
        sensitive = bool(kinds & {"effect", "upgrade", "asset"})
        guarded = "invariant" in kinds or any(edge.kind == "guards" for edge in outgoing.get(node.node_id, []))
        boundary = "trust_boundary" in kinds
        location = CodeLocation(**node.location)

        if sensitive and not guarded:
            _append_candidate(
                generated,
                existing_fingerprints,
                generator="semantic-graph-query",
                lens="access-control",
                prop="Security-sensitive effects must be dominated by an explicit authority or invariant check",
                violation=f"{node.label} reaches a sensitive effect without a syntactically visible guard",
                location=location,
                assets=[child.label for child in children if child.kind == "asset"] or ["security-sensitive state"],
                capabilities=["reach the exposed operation"],
                assumptions=["the generic graph edge requires compiler or runtime confirmation"],
                graph_slice=[node.node_id, *[child.node_id for child in children[:8]]],
                plan=["confirm dispatch and authority edges with a compiler frontend", "construct an unauthorized negative-control test"],
            )
        if node.kind == "entry_point" and boundary and sensitive:
            _append_candidate(
                generated,
                existing_fingerprints,
                generator="attacker-sequence",
                lens="callback-and-sequencing",
                prop="External control must not invalidate state or authority assumptions before a sensitive effect",
                violation=f"{node.label} exposes a path containing both an external trust boundary and a sensitive effect",
                location=location,
                assets=[child.label for child in children if child.kind == "asset"] or ["state transition"],
                capabilities=["invoke the entry point", "control or influence the external dependency"],
                assumptions=["edge order and feasibility remain to be established"],
                graph_slice=[node.node_id, *[child.node_id for child in children[:8]]],
                plan=["derive the exact call/effect ordering", "search for a profitable or authority-escalating multi-step sequence", "verify with a stateful harness"],
            )
        if sensitive and "invariant" not in kinds:
            _append_candidate(
                generated,
                existing_fingerprints,
                generator="specification-inference",
                lens="invariant",
                prop=f"The intended preconditions and postconditions of {node.label} must preserve assets and authority",
                violation=f"No explicit local invariant was indexed around the security-sensitive effects of {node.label}",
                location=location,
                assets=[child.label for child in children if child.kind == "asset"] or ["persistent state"],
                capabilities=["exercise boundary values or alternate call sequences"],
                assumptions=["the property may be enforced by a caller, callee, type, or undocumented protocol rule"],
                graph_slice=[node.node_id, *[child.node_id for child in children[:8]]],
                plan=["infer pre/postconditions from tests and documentation", "retain conflicting interpretations", "encode the strongest plausible conservation or authority property"],
            )
        if sensitive and node.label.lower() not in test_text:
            _append_candidate(
                generated,
                existing_fingerprints,
                generator="test-gap-analysis",
                lens="test-gap",
                prop=f"Security-relevant behaviour in {node.label} must be covered by a targeted regression or invariant test",
                violation=f"No test reference to {node.label} was found in the scoped test corpus",
                location=location,
                assets=["verification coverage"],
                capabilities=["exercise an untested branch or configuration"],
                assumptions=["test indirection or generated tests may not mention the symbol by name"],
                graph_slice=[node.node_id],
                plan=["measure branch and state-transition coverage", "add a harness that targets the uncovered effect", "do not report without a security impact"],
            )

        for template in incident_templates or []:
            keywords = [str(item).lower() for item in template.get("keywords", [])]
            if keywords and not any(keyword in labels or keyword in node.label.lower() for keyword in keywords):
                continue
            template_id = str(template.get("id", "historical-variant"))
            retrieval = template.get("retrieval") is True
            _append_candidate(
                generated,
                existing_fingerprints,
                generator=("retrieval-analogy" if retrieval else "historical-variant-miner"),
                lens=str(template.get("threat_lens", "variant")),
                prop=str(template.get("security_property", "A historically broken security assumption must not recur")),
                violation=(
                    f"A provenance-bearing analogy ({template_id}) suggests reviewing {node.label}"
                    if retrieval
                    else f"{node.label} matches the semantic cues of template {template_id}"
                ),
                location=location,
                assets=[
                    "retrieval-guided review surface"
                    if retrieval
                    else "historical variant surface"
                ],
                capabilities=[str(item) for item in template.get("attacker_capabilities", ["reach the candidate path"])],
                assumptions=(
                    [
                        f"retrieval provenance: {template.get('provenance', 'unrecorded')}",
                        "retrieval is never evidence and must be disabled when it reveals blind-benchmark ground truth",
                    ]
                    if retrieval
                    else ["historical semantic matches guide validation and are not evidence"]
                ),
                graph_slice=(
                    [node.node_id, f"retrieval:{template_id}"]
                    if retrieval
                    else [node.node_id, *[child.node_id for child in children[:8]]]
                ),
                plan=(
                    [
                        "exclude the source from temporal blind evaluation if post-cutoff",
                        "compare causal graphs",
                        "verify independently without relying on the retrieved report",
                    ]
                    if retrieval
                    else [
                        "compare root-cause graph rather than report wording",
                        "prove path feasibility",
                        "construct a benign negative case",
                    ]
                ),
            )
    return generated


def bind_hypotheses_to_graph(
    graph: SecuritySemanticGraph, hypotheses: Iterable[Hypothesis]
) -> None:
    """Attach deterministic/AST candidates to stable graph nodes in place."""

    located = [node for node in graph.nodes if node.location is not None]
    for hypothesis in hypotheses:
        if hypothesis.graph_slice:
            continue
        matches: list[tuple[int, str]] = []
        for location in hypothesis.candidate_locations:
            for node in located:
                node_location = node.location or {}
                if node_location.get("path") != location.path:
                    continue
                start = int(node_location.get("line_start", 1))
                end = int(node_location.get("line_end") or start)
                distance = 0 if start <= location.line_start <= end else min(
                    abs(location.line_start - start), abs(location.line_start - end)
                )
                matches.append((distance, node.node_id))
        if matches:
            best = min(item[0] for item in matches)
            hypothesis.graph_slice = sorted(
                {node_id for distance, node_id in matches if distance == best}
            )[:16]


def default_historical_templates() -> list[dict[str, Any]]:
    return [
        {
            "id": "VAR-REENTRANCY-EFFECT-ORDER",
            "keywords": ["external call", "transfer", "withdraw"],
            "threat_lens": "reentrancy",
            "security_property": "External control transfer must not permit reuse of stale accounting state",
            "provenance": "built-in semantic class SWC-107; no target-specific report text",
        },
        {
            "id": "VAR-AUTHORITY-CONFUSION",
            "keywords": ["owner", "admin", "signer", "capability", "upgrade"],
            "threat_lens": "access-control",
            "security_property": "Authority-sensitive effects must be bound to the intended principal and lifecycle",
            "provenance": "built-in authorization semantic class; no target-specific report text",
        },
        {
            "id": "VAR-ORACLE-TRUST",
            "keywords": ["oracle", "price", "quote"],
            "threat_lens": "oracle",
            "security_property": "Economic decisions must use manipulation-resistant and freshness-checked observations",
            "provenance": "built-in oracle-manipulation semantic class; no target-specific report text",
        },
        {
            "id": "VAR-SHARE-ACCOUNTING",
            "keywords": ["share", "vault", "balance", "amount"],
            "threat_lens": "accounting",
            "security_property": "Share and asset accounting must preserve value across boundary and donation states",
            "provenance": "built-in vault-accounting semantic class; no target-specific report text",
        },
    ]


def semantic_fingerprint(
    security_property: str,
    root_cause: str,
    graph_slice: Iterable[str],
    attacker_prerequisites: Iterable[str] = (),
    impact: str = "",
) -> str:
    normalized = {
        "security_property": _normalise_words(security_property),
        "root_cause": _normalise_words(root_cause),
        "graph_slice": sorted(set(graph_slice)),
        "attacker_prerequisites": sorted(_normalise_words(item) for item in attacker_prerequisites),
        "impact": _normalise_words(impact),
    }
    return sha256_bytes(canonical_json(normalized).encode("utf-8"))


def _append_candidate(
    candidates: list[Hypothesis],
    fingerprints: set[str],
    *,
    generator: str,
    lens: str,
    prop: str,
    violation: str,
    location: CodeLocation,
    assets: list[str],
    capabilities: list[str],
    assumptions: list[str],
    graph_slice: list[str],
    plan: list[str],
) -> None:
    if len(candidates) >= MAX_GRAPH_HYPOTHESES:
        return
    fingerprint = _hypothesis_fingerprint(prop, violation, [location])
    if fingerprint in fingerprints:
        return
    fingerprints.add(fingerprint)
    candidates.append(
        Hypothesis(
            hypothesis_id=f"H-SSG-{fingerprint[:16]}",
            security_property=prop,
            suspected_violation=violation,
            affected_assets=sorted(set(assets)),
            required_attacker_capabilities=capabilities,
            assumptions=assumptions,
            candidate_locations=[location],
            verification_plan=plan,
            threat_lens=lens,
            generator=generator,
            graph_slice=graph_slice,
            unresolved_assumptions=list(assumptions),
            proposed_next_experiment=plan[0],
        )
    )


def _hypothesis_fingerprint(
    prop: str, violation: str, locations: Iterable[CodeLocation]
) -> str:
    return sha256_bytes(
        canonical_json(
            {
                "property": _normalise_words(prop),
                "violation": _normalise_words(violation),
                "locations": [
                    (
                        item.path,
                        item.symbol,
                        None if item.symbol else item.line_start,
                        None if item.symbol else item.line_end,
                    )
                    for item in locations
                ],
            }
        ).encode("utf-8")
    )


def _dialect_for(path: Path, frameworks: list[str]) -> str | None:
    suffix = path.suffix.lower()
    text_name = path.name.lower()
    if suffix == ".sol" or suffix in {".vy", ".yul"}:
        return "evm"
    if suffix == ".move":
        return "move-sui"
    if suffix in {".wasm", ".wat"}:
        return "wasm"
    if suffix in {".java", ".kt", ".kts", ".scala"}:
        return "jvm"
    if suffix == ".rs":
        if "anchor" in frameworks or any(part.lower() in {"programs", "solana"} for part in path.parts):
            return "solana"
        return "rust-native"
    if suffix in {".c", ".cc", ".cpp", ".h", ".hpp"}:
        return "rust-native"
    if suffix == ".go" and any(word in text_name for word in ("consensus", "raft", "validator", "quorum")):
        return "dlt-consensus"
    if suffix in {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".php"}:
        return "web-api"
    return None


def _read_scoped_text(path: Path, record: FileRecord, limit: int) -> str | None:
    data = _read_scoped_bytes(path, record, limit)
    if data is None:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _read_scoped_bytes(path: Path, record: FileRecord, limit: int) -> bytes | None:
    if record.size > limit:
        return None
    try:
        item_stat = path.lstat()
        if not stat.S_ISREG(item_stat.st_mode) or item_stat.st_size != record.size:
            return None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            data = os.read(descriptor, limit + 1)
        finally:
            os.close(descriptor)
        if len(data) > limit or sha256_bytes(data) != record.sha256:
            return None
        return data
    except OSError:
        return None


def _augment_evm_from_solc_ast(
    nodes: dict[str, SemanticNode],
    edges: dict[tuple[str, str, str], SemanticEdge],
    target: Path,
    scope: ScopeManifest,
    artifact: Path,
) -> bool:
    """Add compiler-resolved declarations and references to the generic graph."""

    artifact_stat = artifact.lstat()
    if not stat.S_ISREG(artifact_stat.st_mode) or stat.S_ISLNK(artifact_stat.st_mode):
        raise ValueError("solc AST graph input must be a regular non-symlink file")
    path = artifact.resolve(strict=True)
    if path.stat().st_size > 100 * 1024 * 1024:
        raise ValueError("solc AST graph input must be a non-symlink file no larger than 100 MB")
    document = json.loads(path.read_text(encoding="utf-8"))
    sources = document.get("sources") if isinstance(document, dict) else None
    if not isinstance(sources, dict):
        raise ValueError("solc AST graph input lacks its sources object")
    scoped = {item.path: item for item in scope.files}
    augmented = False
    for source_name, source_record in sorted(sources.items()):
        if not isinstance(source_name, str) or not isinstance(source_record, dict):
            continue
        ast = source_record.get("ast")
        if not isinstance(ast, dict):
            continue
        relative = _scoped_source_name(target, source_name)
        file_record = scoped.get(relative)
        if file_record is None or file_record.sha256 is None or file_record.kind == "symlink":
            raise ValueError(f"solc AST source is outside the captured scope: {source_name}")
        source_bytes = _read_scoped_bytes(
            target / relative, file_record, scope.max_analysis_file_bytes
        )
        if source_bytes is None:
            raise ValueError(f"solc AST source no longer matches the captured scope: {source_name}")
        ast_nodes = list(_walk_compiler_ast(ast))
        declarations: dict[int, str] = {}
        functions: list[tuple[dict[str, Any], str]] = []
        for item in ast_nodes:
            declaration_id = item.get("id")
            if not isinstance(declaration_id, int):
                continue
            node_type = item.get("nodeType")
            if node_type == "VariableDeclaration" and item.get("stateVariable") is True:
                if len(nodes) >= MAX_GRAPH_NODES:
                    continue
                name = str(item.get("name") or f"state-{declaration_id}")
                line = _compiler_line(item, source_bytes)
                state_id = _node_id("state", "evm", relative, str(declaration_id), name)
                type_description = item.get("typeDescriptions")
                nodes[state_id] = SemanticNode(
                    state_id,
                    "state",
                    name,
                    "evm",
                    {"path": relative, "line_start": line, "line_end": line, "symbol": name},
                    {
                        "declaration_id": declaration_id,
                        "type": (
                            type_description.get("typeString")
                            if isinstance(type_description, dict)
                            else None
                        ),
                        "resolution": "solc-standard-json",
                    },
                )
                declarations[declaration_id] = state_id
                augmented = True
            elif node_type == "FunctionDefinition":
                name = str(item.get("name") or item.get("kind") or "function")
                line = _compiler_line(item, source_bytes)
                candidates = [
                    node
                    for node in nodes.values()
                    if node.dialect == "evm"
                    and node.kind in {"symbol", "entry_point"}
                    and node.label == name
                    and node.location is not None
                    and node.location.get("path") == relative
                    and int(node.location.get("line_start", 0)) == line
                ]
                if candidates:
                    function_id = candidates[0].node_id
                    function_node = candidates[0]
                else:
                    if len(nodes) >= MAX_GRAPH_NODES:
                        continue
                    function_id = _node_id(
                        "entry_point", "evm", relative, str(declaration_id), name
                    )
                    function_node = SemanticNode(
                        function_id,
                        "entry_point"
                        if str(item.get("visibility")) in {"public", "external"}
                        else "symbol",
                        name,
                        "evm",
                        {"path": relative, "line_start": line, "line_end": line, "symbol": name},
                    )
                    nodes[function_id] = function_node
                function_node.properties.update(
                    {
                        "declaration_id": declaration_id,
                        "visibility": item.get("visibility"),
                        "state_mutability": item.get("stateMutability"),
                        "resolution": "solc-standard-json",
                    }
                )
                declarations[declaration_id] = function_id
                functions.append((item, function_id))
                augmented = True
        for function, function_id in functions:
            body = function.get("body")
            if not isinstance(body, dict):
                continue
            body_nodes = list(_walk_compiler_ast(body))
            state_references = {
                int(item["referencedDeclaration"])
                for item in body_nodes
                if isinstance(item.get("referencedDeclaration"), int)
                and int(item["referencedDeclaration"]) in declarations
                and nodes[declarations[int(item["referencedDeclaration"])]].kind == "state"
            }
            written: set[int] = set()
            for item in body_nodes:
                if item.get("nodeType") not in {"Assignment", "UnaryOperation"}:
                    continue
                target_value = item.get("leftHandSide", item.get("subExpression"))
                written.update(
                    int(reference["referencedDeclaration"])
                    for reference in _walk_compiler_ast(target_value)
                    if isinstance(reference.get("referencedDeclaration"), int)
                    and int(reference["referencedDeclaration"]) in state_references
                )
            for declaration_id in sorted(state_references):
                if len(edges) >= MAX_GRAPH_EDGES:
                    break
                state_id = declarations[declaration_id]
                kind = "writes" if declaration_id in written else "reads"
                edges[(function_id, state_id, kind)] = SemanticEdge(
                    function_id,
                    state_id,
                    kind,
                    {"resolution": "solc-reference"},
                )
            for call in body_nodes:
                if call.get("nodeType") != "FunctionCall":
                    continue
                expression = call.get("expression")
                referenced = [
                    int(item["referencedDeclaration"])
                    for item in _walk_compiler_ast(expression)
                    if isinstance(item.get("referencedDeclaration"), int)
                ]
                targets = {
                    declarations[item]
                    for item in referenced
                    if item in declarations and nodes[declarations[item]].kind in {"symbol", "entry_point"}
                }
                for called_id in targets:
                    if called_id != function_id and len(edges) < MAX_GRAPH_EDGES:
                        edges[(function_id, called_id, "calls")] = SemanticEdge(
                            function_id,
                            called_id,
                            "calls",
                            {"resolution": "solc-reference"},
                        )
    return augmented


def _walk_compiler_ast(value: Any) -> Iterable[dict[str, Any]]:
    stack = [value]
    visited = 0
    while stack:
        current = stack.pop()
        visited += 1
        if visited > 2_000_000:
            raise ValueError("solc AST graph input exceeds the two-million-node limit")
        if isinstance(current, dict):
            yield current
            stack.extend(reversed(list(current.values())))
        elif isinstance(current, list):
            stack.extend(reversed(current))


def _scoped_source_name(target: Path, source_name: str) -> str:
    candidate = Path(source_name)
    if candidate.is_absolute():
        try:
            candidate = candidate.relative_to(target)
        except ValueError as error:
            raise ValueError(f"solc AST source escapes the audited target: {source_name}") from error
    if any(part in {"", ".", ".."} for part in candidate.parts):
        raise ValueError(f"solc AST source has unsafe traversal: {source_name}")
    return candidate.as_posix()


def _compiler_line(node: dict[str, Any], source: bytes) -> int:
    value = node.get("src")
    try:
        offset = int(str(value).split(":", maxsplit=1)[0])
    except (TypeError, ValueError):
        offset = 0
    return source.count(b"\n", 0, max(0, min(offset, len(source)))) + 1


def _symbols(source: str, dialect: str) -> list[tuple[str, int, int, str]]:
    pattern = _SYMBOL_PATTERNS.get(dialect)
    if pattern is None:
        return []
    matches = list(pattern.finditer(source))
    result: list[tuple[str, int, int, str]] = []
    for index, match in enumerate(matches):
        name = match.group(1) or "constructor"
        start = source.count("\n", 0, match.start()) + 1
        next_start = matches[index + 1].start() if index + 1 < len(matches) else len(source)
        end = source.count("\n", 0, next_start) + 1
        result.append((name, start, max(start, end), match.group(0).strip()))
    return result


def _enclosing_symbol(nodes: Iterable[SemanticNode], path: str, line: int) -> SemanticNode | None:
    candidates = [
        node
        for node in nodes
        if node.kind in {"symbol", "entry_point"}
        and node.location is not None
        and node.location.get("path") == path
        and int(node.location.get("line_start", 0)) <= line <= int(node.location.get("line_end") or line)
    ]
    return max(candidates, key=lambda item: int(item.location["line_start"])) if candidates else None


def _edge_for_concept(kind: str, source: str, offset: int) -> str:
    if kind == "invariant":
        return "guards"
    if kind == "trust_boundary":
        return "crosses"
    if kind == "upgrade":
        return "upgrades"
    if kind == "authority":
        return "administers"
    if kind == "external_dependency":
        return "depends_on"
    if kind == "asset":
        return "transfers" if re.search(r"\b(?:transfer|withdraw|mint|burn)\b", source[max(0, offset - 120): offset + 120], re.I) else "reads"
    if kind in {"effect", "state"}:
        return "writes"
    return "reaches"


def _support_record(dialect: str, compiler_dialects: set[str]) -> DialectSupport:
    definition = next(item for item in DIALECTS if item.name == dialect)
    typed = dialect in compiler_dialects
    return DialectSupport(
        dialect=dialect,
        maturity=SupportMaturity.TYPED if typed else SupportMaturity.SYNTAX_ONLY,
        frontends=["compiler-native-artifact", "bounded-generic-index"] if typed else ["bounded-generic-index"],
        runtime_adapters=list(definition.runtime_adapters),
        concepts=list(definition.concepts),
        limitations=(
            ["compiler artefact supplies declarations, types, direct references, and bounded internal-call summaries; path-sensitive data/effect flow remains incomplete"]
            if typed
            else ["syntax indexing only; types, dispatch, feasibility, and data flow are unproven"]
        ),
    )


def _node_id(kind: str, *parts: str) -> str:
    digest = sha256_bytes("\0".join((kind, *parts)).encode("utf-8"))
    return f"N-{kind[:4]}-{digest[:20]}"


def _normalise_words(value: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", value.lower()))


def _entry_point_name(value: str) -> bool:
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    tokens = {item.lower() for item in re.findall(r"[A-Za-z0-9]+", separated)}
    return bool(tokens & {"entry", "endpoint", "handler", "instruction", "route"})


def _test_index(root: Path) -> str:
    fragments: list[str] = []
    total = 0
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = [item for item in sorted(directories) if item not in {".git", "node_modules", "target", "out", "build", "dist"}]
        for name in sorted(files):
            relative = (Path(current) / name).relative_to(root).as_posix().lower()
            if not any(part in relative for part in ("test", "spec", "invariant")):
                continue
            path = Path(current) / name
            try:
                item_stat = path.lstat()
                if not stat.S_ISREG(item_stat.st_mode) or item_stat.st_size > 1_000_000:
                    continue
                descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    value = os.read(descriptor, 1_000_001)
                finally:
                    os.close(descriptor)
                if len(value) > 1_000_000:
                    continue
                text = value.decode("utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            fragments.append(text.lower())
            total += len(text)
            if total >= 5_000_000:
                return "\n".join(fragments)
    return "\n".join(fragments)
