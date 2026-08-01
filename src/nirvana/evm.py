from __future__ import annotations

import hashlib
import re
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

    def scan_repository(self, root: Path) -> list[Hypothesis]:
        hypotheses: list[Hypothesis] = []
        for path in sorted(root.rglob("*.sol")):
            if any(part in {".git", "node_modules", "out", "build"} for part in path.parts):
                continue
            if not path.is_file() or path.is_symlink():
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
