from __future__ import annotations

import hashlib
import json
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from .models import CodeLocation, Hypothesis
from .symmetry import (
    OperationSummary,
    SymmetryAnalyzer,
    classify_effect_text,
    classify_guard_text,
)


MAX_INTERNAL_CALL_SUMMARY_PASSES = 128


@dataclass(frozen=True, slots=True)
class SolidityRule:
    rule_id: str
    pattern: re.Pattern[str]
    security_property: str
    suspected_violation: str
    threat_lens: str
    verification_plan: tuple[str, ...]
    benign_conditions: tuple[str, ...]


RULES = (
    SolidityRule(
        "EVM-AUTH-TX-ORIGIN",
        re.compile(r"\btx\s*\.\s*origin\b"),
        "Authorization must bind to the intended caller identity",
        "tx.origin participates in a security-sensitive decision and may allow call-chain impersonation",
        "access-control",
        (
            "Trace the value into every branch and authority-sensitive effect",
            "Construct an intermediary caller and compare direct versus relayed behavior",
            "Reject the hypothesis if the value is used only for non-security telemetry",
        ),
        ("telemetry-only use", "explicitly documented compatibility check without authority effects"),
    ),
    SolidityRule(
        "EVM-CALL-REENTRANCY",
        re.compile(r"\.\s*(?:call|send|transfer)\s*(?:\{|\()"),
        "External interactions must not expose partially updated state to callbacks",
        "A value or control transfer may occur before state is finalized and permit reentrancy",
        "reentrancy",
        (
            "Use the compiler AST to order the external interaction and state effects",
            "Build a callback receiver and re-enter every reachable state-changing function",
            "Reject the hypothesis when state is finalized first or a complete guard dominates the path",
        ),
        ("checks-effects-interactions ordering", "complete non-reentrant guard"),
    ),
    SolidityRule(
        "EVM-ORACLE-SPOT-STATE",
        re.compile(r"\.\s*(?:getReserves|slot0)\s*\("),
        "Security-sensitive pricing must resist same-transaction reserve manipulation",
        "A raw pool reserve or slot0 observation may be used as a manipulable spot-price oracle",
        "oracle",
        (
            "Trace the observation into every asset, collateral, mint, burn, or liquidation calculation",
            "Compare the path against a time-weighted or independently anchored price",
            "Simulate a same-transaction reserve distortion and unwind",
        ),
        ("observation is telemetry only", "independent manipulation-resistant validation"),
    ),
    SolidityRule(
        "EVM-SHARE-INFLATION-MATH",
        re.compile(
            r"\b(?:totalSupply|totalAssets|convertToShares|previewDeposit)\b[^;\n]{0,240}/"
            r"|/[^;\n]{0,240}\b(?:totalSupply|totalAssets)\b"
        ),
        "Share issuance must not let donations or rounding capture depositor assets",
        "Share conversion arithmetic may permit first-depositor or donation inflation",
        "accounting",
        (
            "Evaluate zero-supply, one-unit, donation, and rounding boundary states",
            "Compare assets-to-shares and shares-to-assets rounding directions",
            "Demonstrate whether an attacker can capture or strand a later deposit",
        ),
        ("virtual shares/assets offset", "minimum-liquidity burn with bounded rounding loss"),
    ),
    SolidityRule(
        "EVM-EFFECT-DELEGATECALL",
        re.compile(r"\.\s*delegatecall\s*\("),
        "Delegated execution must target trusted code under explicit authority controls",
        "A delegatecall site may permit untrusted code execution or storage corruption",
        "callback",
        (
            "Resolve every possible target and the authority controlling it",
            "Trace storage effects in the caller context",
            "Test an unauthorized or malicious implementation target",
        ),
        ("immutable trusted implementation", "validated upgrade path with storage compatibility"),
    ),
    SolidityRule(
        "EVM-LIFECYCLE-SELFDESTRUCT",
        re.compile(r"\bselfdestruct\s*\("),
        "Contract lifecycle operations must not violate availability or asset custody",
        "A selfdestruct operation may violate lifecycle or forced-value assumptions",
        "privilege",
        (
            "Resolve reachability and caller authority",
            "Check chain-version semantics and proxy context",
            "Demonstrate an observable state, code, or balance impact",
        ),
        ("unreachable legacy code", "semantics make the suspected impact impossible on the target chain"),
    ),
    SolidityRule(
        "EVM-REVIEW-INLINE-ASSEMBLY",
        re.compile(r"\bassembly\s*\{"),
        "Memory, storage, and control-flow invariants must survive low-level operations",
        "Inline assembly bypasses Solidity safety checks and requires effect-level review",
        "memory-safety",
        (
            "Map every memory, storage, calldata, and control-flow effect",
            "Compare the block against compiler-level semantics",
            "Generate boundary tests for pointer, length, and return-data assumptions",
        ),
        ("compiler-generated or audited library routine with matching version and tests",),
    ),
    SolidityRule(
        "EVM-CRYPTO-ECRECOVER",
        re.compile(r"\becrecover\s*\("),
        "Signature verification must enforce signer, domain, nonce, and canonical signature constraints",
        "Raw ecrecover use may omit zero-address, malleability, domain-separation, or replay checks",
        "cryptography",
        (
            "Trace message construction, domain separator, nonce, deadline, and recovered signer checks",
            "Test zero-address and non-canonical signature cases",
            "Test replay across contracts, chains, users, and protocol epochs",
        ),
        ("well-reviewed wrapper enforces canonical signatures and complete replay protection",),
    ),
    SolidityRule(
        "EVM-TIME-BLOCK-TIMESTAMP",
        re.compile(r"\bblock\s*\.\s*timestamp\b"),
        "Time-dependent transitions must tolerate permitted timestamp control and boundary behavior",
        "Timestamp-dependent logic may become exploitable at boundary conditions",
        "sequencing",
        (
            "Identify the threshold, asset, or authority decision influenced by time",
            "Test values immediately before, at, and after every boundary",
            "Reject the hypothesis when allowed timestamp variance cannot change a security outcome",
        ),
        ("non-security metadata", "wide timing tolerance with no extractable outcome"),
    ),
)


class SolidityCandidateScanner:
    """A recall-oriented baseline. Every result remains an unconfirmed hypothesis."""

    def __init__(self, max_file_bytes: int = 5_000_000):
        if max_file_bytes < 1:
            raise ValueError("max_file_bytes must be positive")
        self.max_file_bytes = max_file_bytes

    def scan_repository(self, root: Path) -> list[Hypothesis]:
        hypotheses: list[Hypothesis] = []
        for path in sorted(root.rglob("*.sol")):
            if any(part in {".git", "node_modules", "out", "build"} for part in path.parts):
                continue
            if not path.is_file() or path.is_symlink():
                continue
            try:
                if path.stat().st_size > self.max_file_bytes:
                    continue
            except OSError:
                continue
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            hypotheses.extend(self.scan_source(source, path.relative_to(root).as_posix()))
        return hypotheses

    def scan_source(self, source: str, relative_path: str) -> list[Hypothesis]:
        searchable = _mask_comments_and_strings(source)
        hypotheses: list[Hypothesis] = []
        for rule in RULES:
            for match in rule.pattern.finditer(searchable):
                line = searchable.count("\n", 0, match.start()) + 1
                stable = f"{rule.rule_id}\0{relative_path}\0{line}".encode()
                hypothesis_id = "H-" + hashlib.sha256(stable).hexdigest()[:16].upper()
                hypotheses.append(
                    Hypothesis(
                        hypothesis_id=hypothesis_id,
                        security_property=rule.security_property,
                        suspected_violation=rule.suspected_violation,
                        affected_assets=["requires semantic asset-flow analysis"],
                        required_attacker_capabilities=["requires verification"],
                        assumptions=list(rule.benign_conditions),
                        candidate_locations=[CodeLocation(relative_path, line, line)],
                        verification_plan=list(rule.verification_plan),
                        threat_lens=rule.threat_lens,
                        generator=f"deterministic:{rule.rule_id}",
                        unresolved_assumptions=list(rule.benign_conditions),
                        proposed_next_experiment=rule.verification_plan[0],
                    )
                )
        return hypotheses


def _mask_comments_and_strings(source: str) -> str:
    """Mask Solidity comments and string bodies while preserving offsets and lines."""

    output = list(source)
    index = 0
    state = "code"
    quote = ""
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "/" and following == "/":
                output[index] = output[index + 1] = " "
                index += 2
                state = "line-comment"
                continue
            if char == "/" and following == "*":
                output[index] = output[index + 1] = " "
                index += 2
                state = "block-comment"
                continue
            if char in {'"', "'"}:
                quote = char
                output[index] = " "
                state = "string"
        elif state == "line-comment":
            if char == "\n":
                state = "code"
            else:
                output[index] = " "
        elif state == "block-comment":
            if char == "*" and following == "/":
                output[index] = output[index + 1] = " "
                index += 2
                state = "code"
                continue
            if char != "\n":
                output[index] = " "
        else:
            if char == "\\" and following:
                if char != "\n":
                    output[index] = " "
                if following != "\n":
                    output[index + 1] = " "
                index += 2
                continue
            if char == quote:
                output[index] = " "
                state = "code"
            elif char != "\n":
                output[index] = " "
        index += 1
    return "".join(output)


class SolcAstCandidateScanner:
    """Contextual candidate generation from Solidity standard-JSON compiler AST output.

    The compiler output is treated as untrusted analysis input. Findings still need
    independent evidence; AST candidates never raise the evidence ceiling.
    """

    def __init__(self) -> None:
        self.warnings: list[str] = []

    def scan_file(self, path: Path, target_root: Path) -> list[Hypothesis]:
        self.warnings = []
        if stat.S_ISLNK(path.lstat().st_mode):
            raise ValueError("solc AST output must not be a symlink")
        resolved = path.resolve(strict=True)
        root = target_root.resolve(strict=True)
        if resolved.stat().st_size > 100 * 1024 * 1024:
            raise ValueError("solc AST output exceeds the 100 MB safety limit")
        try:
            document = json.loads(resolved.read_text(encoding="utf-8"))
        except RecursionError as error:
            raise ValueError("solc AST output exceeds the nesting limit") from error
        if not isinstance(document, dict):
            raise ValueError("solc AST output must be one JSON object")
        sources = document.get("sources")
        if not isinstance(sources, dict):
            raise ValueError("solc AST output lacks its sources object")
        hypotheses: list[Hypothesis] = []
        source_units: list[tuple[str, dict[str, object], bytes]] = []
        for source_name, source_record in sorted(sources.items()):
            if not isinstance(source_name, str) or not isinstance(source_record, dict):
                continue
            ast = source_record.get("ast")
            if not isinstance(ast, dict):
                continue
            source_path = _regular_source_path(root, source_name)
            source_bytes = source_path.read_bytes()
            source_units.append((source_name, ast, source_bytes))
            hypotheses.extend(self._scan_source_ast(ast, source_name, source_bytes))
        summaries, closure_truncated = _compiler_operation_summaries(source_units)
        if closure_truncated:
            self.warnings.append(
                "Solidity internal-call summaries reached the 128-pass safety limit"
            )
        symmetry_analyzer = SymmetryAnalyzer()
        hypotheses.extend(symmetry_analyzer.analyze(summaries))
        if symmetry_analyzer.truncated:
            self.warnings.append(
                "Solidity symmetry analysis reached the 250000-pair safety limit"
            )
        unique: dict[str, Hypothesis] = {}
        for hypothesis in hypotheses:
            unique.setdefault(hypothesis.hypothesis_id, hypothesis)
        return list(unique.values())

    def _scan_source_ast(
        self, ast: dict[str, object], source_name: str, source_bytes: bytes
    ) -> list[Hypothesis]:
        state_ids = {
            int(node["id"])
            for node in _walk_ast(ast)
            if node.get("nodeType") == "VariableDeclaration"
            and node.get("stateVariable") is True
            and isinstance(node.get("id"), int)
        }
        hypotheses: list[Hypothesis] = []
        for function in _walk_ast(ast):
            if function.get("nodeType") != "FunctionDefinition":
                continue
            body = function.get("body")
            if not isinstance(body, dict):
                continue
            nodes = sorted(_walk_ast(body), key=_ast_offset)
            writes = [node for node in nodes if _writes_state(node, state_ids)]
            external_calls = [node for node in nodes if _external_call(node)]
            function_name = str(function.get("name") or function.get("kind") or "function")
            location = _ast_location(function, source_name, source_bytes, function_name)
            guard_categories = _function_guard_categories(function, nodes)

            if external_calls and writes and any(
                _ast_offset(call) < _ast_offset(write)
                for call in external_calls
                for write in writes
            ) and "reentrancy" not in guard_categories:
                hypotheses.append(
                    _ast_hypothesis(
                        "EVM-AST-REENTRANCY",
                        location,
                        "External interactions must not expose partially updated state to callbacks",
                        "The compiler AST orders an external interaction before a state write",
                        "reentrancy",
                        [
                            "Confirm the exact call and state-write path in the compiler CFG",
                            "Re-enter through every attacker-reachable callback edge",
                            "Check whether a dominating guard or revert makes the sequence harmless",
                        ],
                        attacker_capabilities=[
                            "reach the external interaction",
                            "control the called contract or token callback",
                            "re-enter before the later state write",
                        ],
                    )
                )

            visibility = str(function.get("visibility", ""))
            mutability = str(function.get("stateMutability", ""))
            if (
                writes
                and visibility in {"public", "external"}
                and mutability not in {"view", "pure"}
                and str(function.get("kind")) not in {"constructor"}
                and "authority" not in guard_categories
            ):
                hypotheses.append(
                    _ast_hypothesis(
                        "EVM-AST-MISSING-AUTHORITY",
                        location,
                        "Privileged state transitions must be restricted to intended authorities",
                        "A public or external state-writing function has no AST-visible authority guard",
                        "access-control",
                        [
                            "Classify every state write and the authority it requires",
                            "Trace internal callers and inherited modifiers before treating the function as open",
                            "Call the function from an unprivileged address and observe protected effects",
                        ],
                    )
                )

            unchecked_calls = _unchecked_low_level_calls(body, nodes)
            if unchecked_calls and writes:
                hypotheses.append(
                    _ast_hypothesis(
                        "EVM-AST-UNCHECKED-LOW-LEVEL-CALL",
                        _ast_location(
                            unchecked_calls[0], source_name, source_bytes, function_name
                        ),
                        "Low-level call failure must be checked before dependent state or value transitions continue",
                        "A compiler-AST low-level call result is discarded or never reaches a dominating failure guard while the function also mutates state",
                        "external-call-integrity",
                        [
                            "Resolve the low-level target and the state/value changes that follow a false return",
                            "Force the callee to revert or return failure without reverting the caller",
                            "Demonstrate invariant divergence, value loss, or denial of service caused by continued execution",
                            "Patch by checking the result and retain the forced-failure case as a negative control",
                        ],
                        attacker_capabilities=[
                            "cause the low-level callee to fail without exhausting the caller transaction"
                        ],
                    )
                )

            parameter_ids = _parameter_declaration_ids(function)
            arbitrary_calls = [
                call
                for call in external_calls
                if _call_target_declarations(call) & parameter_ids
                and (_low_level_member_name(call) in {"call", "delegatecall"})
            ]
            if (
                arbitrary_calls
                and visibility in {"public", "external"}
                and "authority" not in guard_categories
            ):
                hypotheses.append(
                    _ast_hypothesis(
                        "EVM-AST-USER-CONTROLLED-CALL",
                        _ast_location(
                            arbitrary_calls[0], source_name, source_bytes, function_name
                        ),
                        "Attacker-reachable arbitrary execution must be constrained by target, selector, value, and authority policy",
                        "A public entry point performs call or delegatecall through a target derived from its parameters without an AST-visible authority guard",
                        "access-control",
                        [
                            "Trace target, calldata, and call value from entry parameters through every sanitizer",
                            "Enumerate reachable selectors and caller-context storage or approval effects",
                            "Invoke an attacker-controlled target and demonstrate an unauthorized asset or authority transition",
                            "Constrain the target/selector or authority and replay the same sequence as a negative control",
                        ],
                        attacker_capabilities=[
                            "invoke the public entry point",
                            "choose or influence the low-level call target",
                        ],
                    )
                )

            member_names = {
                str(node.get("memberName"))
                for node in nodes
                if node.get("nodeType") == "MemberAccess"
            }
            if member_names & {"getReserves", "slot0"}:
                hypotheses.append(
                    _ast_hypothesis(
                        "EVM-AST-SPOT-ORACLE",
                        location,
                        "Security-sensitive pricing must resist same-transaction reserve manipulation",
                        "The function consumes a raw pool reserve or slot0 observation",
                        "oracle",
                        [
                            "Trace the observed value to all price-sensitive effects",
                            "Check for TWAP, staleness, and independent-source validation",
                            "Distort the pool state within one transaction and measure extractable impact",
                        ],
                    )
                )

            chainlink_reads = member_names & {"latestAnswer", "latestRoundData"}
            if chainlink_reads:
                validation = _oracle_validation_signals(nodes)
                required = {"positive-answer", "freshness"}
                if "latestRoundData" in chainlink_reads:
                    required.add("round-completeness")
                missing = sorted(required - validation)
                if missing:
                    hypotheses.append(
                        _ast_hypothesis(
                            "EVM-AST-ORACLE-INTEGRITY",
                            location,
                            "External oracle values must be positive, fresh, and from a complete round before security-sensitive use",
                            "The compiler AST reads a Chainlink-style oracle without AST-visible validation of: "
                            + ", ".join(missing),
                            "oracle",
                            [
                                "Trace the returned answer, timestamps, and round identifiers into every asset-sensitive effect",
                                "Return zero/negative, stale, and incomplete-round values from a controlled feed",
                                "Measure whether collateral, minting, liquidation, or settlement accepts the invalid observation",
                                "Add all required validations and retain each invalid observation as a negative control",
                            ],
                            attacker_capabilities=[
                                "reach the price-dependent path when the feed is stale or reports an invalid round"
                            ],
                        )
                    )

            referenced_names = {
                str(node.get("name"))
                for node in nodes
                if node.get("nodeType") == "Identifier"
            } | member_names
            has_division = any(
                node.get("nodeType") == "BinaryOperation" and node.get("operator") == "/"
                for node in nodes
            )
            if (
                function_name.lower()
                in {"deposit", "mint", "convertToShares".lower(), "previewDeposit".lower()}
                and has_division
                and referenced_names & {"totalSupply", "totalAssets", "balanceOf"}
            ):
                hypotheses.append(
                    _ast_hypothesis(
                        "EVM-AST-SHARE-INFLATION",
                        location,
                        "Share issuance must not let donations or rounding capture depositor assets",
                        "Share conversion divides by supply or assets on a deposit-like path",
                        "accounting",
                        [
                            "Evaluate zero-supply, donation, and one-unit rounding states",
                            "Compare mint and redeem rounding direction and virtual offsets",
                            "Measure whether a first depositor can capture a later deposit",
                        ],
                    )
                )
        return hypotheses


@dataclass(slots=True)
class _CompilerFunctionFacts:
    declaration_id: int
    module: str
    name: str
    location: CodeLocation
    entry_point: bool
    state_reads: set[str] = field(default_factory=set)
    state_writes: set[str] = field(default_factory=set)
    guards: set[str] = field(default_factory=set)
    effects: set[str] = field(default_factory=set)
    internal_calls: set[int] = field(default_factory=set)


def _compiler_operation_summaries(
    source_units: list[tuple[str, dict[str, object], bytes]],
) -> tuple[list[OperationSummary], bool]:
    """Build bounded declaration-resolved summaries and close internal calls."""

    state_names = {
        int(node["id"]): str(node.get("name") or f"state#{node['id']}")
        for _, ast, _ in source_units
        for node in _walk_ast(ast)
        if node.get("nodeType") == "VariableDeclaration"
        and node.get("stateVariable") is True
        and isinstance(node.get("id"), int)
    }
    state_ids = set(state_names)
    facts: dict[int, _CompilerFunctionFacts] = {}
    for source_name, ast, source_bytes in source_units:
        for contract in _walk_ast(ast):
            if contract.get("nodeType") != "ContractDefinition":
                continue
            contract_name = str(
                contract.get("canonicalName") or contract.get("name") or "contract"
            )
            module = f"{source_name}:{contract_name}"
            members = contract.get("nodes")
            if not isinstance(members, list):
                continue
            for function in members:
                if (
                    not isinstance(function, dict)
                    or function.get("nodeType") != "FunctionDefinition"
                    or not isinstance(function.get("id"), int)
                    or not isinstance(function.get("body"), dict)
                ):
                    continue
                declaration_id = int(function["id"])
                body = function["body"]
                nodes = list(_walk_ast(body))
                name = str(function.get("name") or function.get("kind") or "function")
                reads = {
                    state_names[reference]
                    for reference in _referenced_declarations(body) & state_ids
                }
                writes: set[str] = set()
                for node in nodes:
                    references = _state_write_declarations(node, state_ids)
                    writes.update(state_names[item] for item in references & state_ids)
                internal_calls = {
                    int(reference)
                    for node in nodes
                    if node.get("nodeType") == "FunctionCall"
                    for reference in _direct_call_declarations(node)
                }
                facts[declaration_id] = _CompilerFunctionFacts(
                    declaration_id=declaration_id,
                    module=module,
                    name=name,
                    location=_ast_location(function, source_name, source_bytes, name),
                    entry_point=str(function.get("visibility")) in {"public", "external"},
                    state_reads=reads,
                    state_writes=writes,
                    guards=set(_function_guard_categories(function, nodes)),
                    effects=set(_function_effect_categories(nodes)),
                    internal_calls=internal_calls,
                )

    # Solidity function ids are global within standard JSON output. Repeatedly
    # union direct callee facts so wrappers inherit helper effects without
    # pretending to have path-sensitive control-flow proof.
    closure_converged = not facts
    for _ in range(min(len(facts), MAX_INTERNAL_CALL_SUMMARY_PASSES)):
        changed = False
        for fact in facts.values():
            before = (
                len(fact.state_reads),
                len(fact.state_writes),
                len(fact.guards),
                len(fact.effects),
            )
            for declaration_id in fact.internal_calls:
                callee = facts.get(declaration_id)
                if callee is None or callee is fact:
                    continue
                fact.state_reads.update(callee.state_reads)
                fact.state_writes.update(callee.state_writes)
                fact.guards.update(callee.guards)
                fact.effects.update(callee.effects)
            after = (
                len(fact.state_reads),
                len(fact.state_writes),
                len(fact.guards),
                len(fact.effects),
            )
            changed = changed or after != before
        if not changed:
            closure_converged = True
            break

    summaries = [
        OperationSummary(
            operation_id=f"solc:{item.declaration_id}",
            dialect="evm",
            module=item.module,
            name=item.name,
            location=item.location,
            entry_point=item.entry_point,
            state_reads=frozenset(item.state_reads),
            state_writes=frozenset(item.state_writes),
            guards=frozenset(item.guards),
            effects=frozenset(item.effects),
            frontend="solc-standard-json-ast:interprocedural-summary",
        )
        for item in sorted(facts.values(), key=lambda value: value.declaration_id)
    ]
    return summaries, not closure_converged


def _walk_ast(value: object):
    stack = [value]
    visited = 0
    while stack:
        current = stack.pop()
        visited += 1
        if visited > 2_000_000:
            raise ValueError("solc AST exceeds the two-million-node safety limit")
        if isinstance(current, dict):
            yield current
            stack.extend(reversed(list(current.values())))
        elif isinstance(current, list):
            stack.extend(reversed(current))


def _walk_ast_with_parents(value: object):
    stack: list[tuple[object, dict[str, object] | None]] = [(value, None)]
    visited = 0
    while stack:
        current, parent = stack.pop()
        visited += 1
        if visited > 2_000_000:
            raise ValueError("solc AST exceeds the two-million-node safety limit")
        if isinstance(current, dict):
            yield current, parent
            stack.extend(
                (child, current) for child in reversed(list(current.values()))
            )
        elif isinstance(current, list):
            stack.extend((child, parent) for child in reversed(current))


def _regular_source_path(root: Path, source_name: str) -> Path:
    source_unit = Path(source_name)
    if source_unit.is_absolute():
        try:
            relative = source_unit.relative_to(root)
        except ValueError as error:
            raise ValueError(
                f"solc AST source escapes the audited target: {source_name}"
            ) from error
    else:
        relative = source_unit
    if ".." in relative.parts:
        raise ValueError(f"solc AST source has unsafe traversal: {source_name}")
    current = root
    for part in relative.parts:
        current = current / part
        current_stat = current.lstat()
        if stat.S_ISLNK(current_stat.st_mode):
            raise ValueError(f"solc AST source follows a symlink: {source_name}")
    if not stat.S_ISREG(current.lstat().st_mode):
        raise ValueError(f"solc AST source is not a regular target file: {source_name}")
    return current.resolve(strict=True)


def _ast_offset(node: dict[str, object]) -> int:
    source = node.get("src")
    if not isinstance(source, str):
        return 2**63 - 1
    try:
        return int(source.split(":", maxsplit=1)[0])
    except ValueError:
        return 2**63 - 1


def _ast_location(
    node: dict[str, object], source_name: str, source_bytes: bytes, symbol: str
) -> CodeLocation:
    offset = max(0, min(_ast_offset(node), len(source_bytes)))
    line = source_bytes.count(b"\n", 0, offset) + 1
    return CodeLocation(source_name, line, line, symbol)


def _referenced_declarations(node: object) -> set[int]:
    return {
        int(item["referencedDeclaration"])
        for item in _walk_ast(node)
        if isinstance(item.get("referencedDeclaration"), int)
    }


def _direct_call_declarations(node: dict[str, object]) -> set[int]:
    if node.get("nodeType") != "FunctionCall":
        return set()
    expression = node.get("expression")
    if isinstance(expression, dict) and expression.get("nodeType") == "FunctionCallOptions":
        expression = expression.get("expression")
    if not isinstance(expression, dict) or expression.get("nodeType") not in {
        "Identifier",
        "IdentifierPath",
        "MemberAccess",
    }:
        return set()
    declaration = expression.get("referencedDeclaration")
    return {int(declaration)} if isinstance(declaration, int) else set()


def _writes_state(node: dict[str, object], state_ids: set[int]) -> bool:
    return bool(_state_write_declarations(node, state_ids))


def _state_write_declarations(
    node: dict[str, object], state_ids: set[int]
) -> set[int]:
    if node.get("nodeType") == "Assignment":
        return _referenced_declarations(node.get("leftHandSide")) & state_ids
    if node.get("nodeType") == "UnaryOperation" and node.get("operator") in {"++", "--", "delete"}:
        return _referenced_declarations(node.get("subExpression")) & state_ids
    if node.get("nodeType") == "FunctionCall":
        member = _low_level_member(node)
        if member is not None and member.get("memberName") in {"push", "pop"}:
            return _referenced_declarations(member.get("expression")) & state_ids
    return set()


def _external_call(node: dict[str, object]) -> bool:
    if node.get("nodeType") != "FunctionCall":
        return False
    if _low_level_member_name(node) in {
        "call",
        "delegatecall",
        "send",
        "transfer",
    }:
        return True
    member = _low_level_member(node)
    if member is None:
        return False
    descriptions = member.get("typeDescriptions")
    if not isinstance(descriptions, dict):
        return False
    type_text = " ".join(
        str(descriptions.get(key, "")).lower()
        for key in ("typeIdentifier", "typeString")
    )
    return (
        "function_external" in type_text or " external" in type_text
    ) and not any(mutability in type_text for mutability in (" view", " pure"))


def _low_level_member(node: dict[str, object]) -> dict[str, object] | None:
    if node.get("nodeType") != "FunctionCall":
        return None
    expression = node.get("expression")
    if isinstance(expression, dict) and expression.get("nodeType") == "FunctionCallOptions":
        expression = expression.get("expression")
    if isinstance(expression, dict) and expression.get("nodeType") == "MemberAccess":
        return expression
    return None


def _low_level_member_name(node: dict[str, object]) -> str | None:
    member = _low_level_member(node)
    if member is None:
        return None
    name = member.get("memberName")
    return str(name) if isinstance(name, str) else None


def _unchecked_low_level_calls(
    body: dict[str, object], nodes: list[dict[str, object]]
) -> list[dict[str, object]]:
    guard_references: set[int] = set()
    for condition in _guard_conditions(nodes):
        guard_references.update(_referenced_declarations(condition))

    unchecked: list[dict[str, object]] = []
    for call, parent in _walk_ast_with_parents(body):
        if _low_level_member_name(call) not in {"call", "delegatecall", "send"}:
            continue
        if not isinstance(parent, dict):
            continue
        parent_kind = parent.get("nodeType")
        if parent_kind == "ExpressionStatement":
            unchecked.append(call)
            continue
        result_declarations: set[int] = set()
        if parent_kind == "VariableDeclarationStatement":
            declarations = parent.get("declarations")
            if isinstance(declarations, list):
                result_declarations.update(
                    int(item["id"])
                    for item in declarations
                    if isinstance(item, dict) and isinstance(item.get("id"), int)
                )
        elif parent_kind == "Assignment":
            result_declarations.update(
                _referenced_declarations(parent.get("leftHandSide"))
            )
        if result_declarations and not result_declarations & guard_references:
            unchecked.append(call)
    return unchecked


def _call_target_declarations(node: dict[str, object]) -> set[int]:
    member = _low_level_member(node)
    if member is None:
        return set()
    return _referenced_declarations(member.get("expression"))


def _parameter_declaration_ids(function: dict[str, object]) -> set[int]:
    parameters = function.get("parameters")
    if not isinstance(parameters, dict):
        return set()
    return {
        int(node["id"])
        for node in _walk_ast(parameters)
        if node.get("nodeType") == "VariableDeclaration"
        and isinstance(node.get("id"), int)
    }


def _guard_conditions(nodes: list[dict[str, object]]):
    for node in nodes:
        if node.get("nodeType") == "FunctionCall":
            expression = node.get("expression")
            if (
                isinstance(expression, dict)
                and expression.get("nodeType") == "Identifier"
                and expression.get("name") in {"require", "assert"}
            ):
                arguments = node.get("arguments")
                if isinstance(arguments, list) and arguments and isinstance(arguments[0], dict):
                    yield arguments[0]
        elif node.get("nodeType") == "IfStatement" and _contains_revert(
            node.get("trueBody")
        ):
            condition = node.get("condition")
            if isinstance(condition, dict):
                yield condition


def _contains_revert(node: object) -> bool:
    return any(
        item.get("nodeType") == "RevertStatement"
        or (
            item.get("nodeType") == "FunctionCall"
            and isinstance(item.get("expression"), dict)
            and item["expression"].get("name") == "revert"
        )
        for item in _walk_ast(node)
    )


def _condition_words(condition: dict[str, object]) -> set[str]:
    words: set[str] = set()
    for node in _walk_ast(condition):
        for key in ("name", "memberName"):
            value = node.get(key)
            if isinstance(value, str):
                words.add(value)
    return words


def _modifier_words(function: dict[str, object]) -> set[str]:
    words: set[str] = set()
    for node in _walk_ast(function.get("modifiers", [])):
        if node.get("nodeType") in {"Identifier", "IdentifierPath", "MemberAccess"}:
            for key in ("name", "memberName"):
                value = node.get(key)
                if isinstance(value, str):
                    words.add(value)
    return words


def _function_guard_categories(
    function: dict[str, object], nodes: list[dict[str, object]]
) -> frozenset[str]:
    categories: set[str] = set()
    categories.update(classify_guard_text(" ".join(sorted(_modifier_words(function)))))
    for condition in _guard_conditions(nodes):
        categories.update(
            classify_guard_text(" ".join(sorted(_condition_words(condition))))
        )
    return frozenset(categories)


def _oracle_validation_signals(nodes: list[dict[str, object]]) -> set[str]:
    signals: set[str] = set()
    for condition in _guard_conditions(nodes):
        words = {item.lower() for item in _condition_words(condition)}
        operators = {
            str(node.get("operator"))
            for node in _walk_ast(condition)
            if node.get("nodeType") == "BinaryOperation"
        }
        literals = {
            str(node.get("value"))
            for node in _walk_ast(condition)
            if node.get("nodeType") in {"Literal", "NumberLiteral"}
        }
        if words & {"answer", "price", "latestanswer"} and (
            ">" in operators and "0" in literals
        ):
            signals.add("positive-answer")
        if (
            "updatedat" in words
            and words & {"timestamp", "now"}
            and words & {"heartbeat", "maxage", "staleafter", "timeout"}
            and operators
        ):
            signals.add("freshness")
        if {"answeredinround", "roundid"} <= words and operators & {">", ">=", "=="}:
            signals.add("round-completeness")
    return signals


def _function_effect_categories(nodes: list[dict[str, object]]) -> frozenset[str]:
    effects: set[str] = set()
    for node in nodes:
        if node.get("nodeType") != "FunctionCall":
            continue
        member_name = _low_level_member_name(node)
        if _external_call(node):
            effects.add("external-control")
        if member_name == "delegatecall":
            effects.add("delegated-execution")
        expression = node.get("expression")
        if isinstance(expression, dict) and expression.get("nodeType") == "FunctionCallOptions":
            expression = expression.get("expression")
        names: list[str] = []
        if isinstance(expression, dict):
            for key in ("name", "memberName"):
                value = expression.get(key)
                if isinstance(value, str):
                    names.append(value)
        for name in names:
            effects.update(classify_effect_text(name))
    return frozenset(effects)


def _ast_hypothesis(
    rule_id: str,
    location: CodeLocation,
    security_property: str,
    violation: str,
    threat_lens: str,
    verification_plan: list[str],
    *,
    affected_assets: list[str] | None = None,
    attacker_capabilities: list[str] | None = None,
    assumptions: list[str] | None = None,
) -> Hypothesis:
    stable = f"{rule_id}\0{location.path}\0{location.line_start}\0{location.symbol}".encode()
    base_assumptions = assumptions or [
        "compiler AST corresponds to the captured target snapshot"
    ]
    return Hypothesis(
        hypothesis_id="H-" + hashlib.sha256(stable).hexdigest()[:16].upper(),
        security_property=security_property,
        suspected_violation=violation,
        affected_assets=affected_assets or ["requires semantic asset-flow analysis"],
        required_attacker_capabilities=attacker_capabilities or ["requires verification"],
        assumptions=base_assumptions,
        candidate_locations=[location],
        verification_plan=verification_plan,
        threat_lens=threat_lens,
        generator=f"solc-ast:{rule_id}",
        unresolved_assumptions=[
            *base_assumptions,
            "reachability and impact require independent verification",
        ],
        proposed_next_experiment=verification_plan[0],
    )
