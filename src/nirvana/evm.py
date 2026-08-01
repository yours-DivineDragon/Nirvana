from __future__ import annotations

import hashlib
import json
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from .models import CodeLocation, Hypothesis


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

    def scan_file(self, path: Path, target_root: Path) -> list[Hypothesis]:
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
        for source_name, source_record in sorted(sources.items()):
            if not isinstance(source_name, str) or not isinstance(source_record, dict):
                continue
            ast = source_record.get("ast")
            if not isinstance(ast, dict):
                continue
            source_path = _regular_source_path(root, source_name)
            source_bytes = source_path.read_bytes()
            hypotheses.extend(self._scan_source_ast(ast, source_name, source_bytes))
        return hypotheses

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

            if external_calls and writes and any(
                _ast_offset(call) < _ast_offset(write)
                for call in external_calls
                for write in writes
            ):
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
                    )
                )

            visibility = str(function.get("visibility", ""))
            mutability = str(function.get("stateMutability", ""))
            if (
                writes
                and visibility in {"public", "external"}
                and mutability not in {"view", "pure"}
                and str(function.get("kind")) not in {"constructor"}
                and not _has_authority_guard(function, nodes)
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


def _writes_state(node: dict[str, object], state_ids: set[int]) -> bool:
    if node.get("nodeType") == "Assignment":
        return bool(_referenced_declarations(node.get("leftHandSide")) & state_ids)
    if node.get("nodeType") == "UnaryOperation" and node.get("operator") in {"++", "--", "delete"}:
        return bool(_referenced_declarations(node.get("subExpression")) & state_ids)
    return False


def _external_call(node: dict[str, object]) -> bool:
    if node.get("nodeType") != "FunctionCall":
        return False
    expression = node.get("expression")
    return isinstance(expression, dict) and expression.get("nodeType") == "MemberAccess" and str(
        expression.get("memberName")
    ) in {"call", "delegatecall", "send", "transfer"}


def _has_authority_guard(
    function: dict[str, object], nodes: list[dict[str, object]]
) -> bool:
    modifier_names = {
        str(item.get("name", "")).lower()
        for item in _walk_ast(function.get("modifiers", []))
        if item.get("nodeType") in {"Identifier", "IdentifierPath"}
    }
    authority_words = ("owner", "admin", "auth", "role", "permission", "govern")
    if any(any(word in name for word in authority_words) for name in modifier_names):
        return True
    return any(
        node.get("nodeType") == "MemberAccess"
        and node.get("memberName") == "sender"
        and isinstance(node.get("expression"), dict)
        and node["expression"].get("name") == "msg"
        for node in nodes
    )


def _ast_hypothesis(
    rule_id: str,
    location: CodeLocation,
    security_property: str,
    violation: str,
    threat_lens: str,
    verification_plan: list[str],
) -> Hypothesis:
    stable = f"{rule_id}\0{location.path}\0{location.line_start}\0{location.symbol}".encode()
    return Hypothesis(
        hypothesis_id="H-" + hashlib.sha256(stable).hexdigest()[:16].upper(),
        security_property=security_property,
        suspected_violation=violation,
        affected_assets=["requires semantic asset-flow analysis"],
        required_attacker_capabilities=["requires verification"],
        assumptions=["compiler AST corresponds to the captured target snapshot"],
        candidate_locations=[location],
        verification_plan=verification_plan,
        threat_lens=threat_lens,
        generator=f"solc-ast:{rule_id}",
        unresolved_assumptions=["reachability and impact require independent verification"],
        proposed_next_experiment=verification_plan[0],
    )
