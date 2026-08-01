from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .contracts import validate_contract
from .util import jsonable, utc_now


class EvidenceLevel(StrEnum):
    HYPOTHESIS = "hypothesis"
    LOCALISED = "localised"
    STRUCTURALLY_CONFIRMED = "structurally_confirmed"
    EXECUTABLE = "executable"
    EXPLOIT_DEMONSTRATED = "exploit_demonstrated"
    FORMALLY_ESTABLISHED = "formally_established"


EVIDENCE_RANK = {
    EvidenceLevel.HYPOTHESIS: 0,
    EvidenceLevel.LOCALISED: 1,
    EvidenceLevel.STRUCTURALLY_CONFIRMED: 2,
    EvidenceLevel.EXECUTABLE: 3,
    EvidenceLevel.EXPLOIT_DEMONSTRATED: 4,
    EvidenceLevel.FORMALLY_ESTABLISHED: 5,
}


class HypothesisStatus(StrEnum):
    PROPOSED = "proposed"
    LOCALISING = "localising"
    AWAITING_VERIFICATION = "awaiting_verification"
    VERIFIED = "verified"
    REJECTED = "rejected"
    RESCUED = "rescued"


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NoveltyClass(StrEnum):
    EXACT_DUPLICATE = "exact_duplicate"
    KNOWN_UNFIXED = "known_unfixed_issue"
    VARIANT = "variant"
    NEW_INSTANCE = "new_instance"
    NOVEL_MECHANISM = "novel_mechanism"
    UNCERTAIN = "uncertain_novelty"


class MismatchClass(StrEnum):
    UNCLASSIFIED = "unclassified"
    HARNESS_BUG = "harness_bug"
    IMPLEMENTATION_BUG = "implementation_bug"
    SPEC_AMBIGUITY = "spec_ambiguity"
    CLEAR_BUT_UNSAFE_SPEC = "clear_but_unsafe_spec"


class SupportMaturity(StrEnum):
    SYNTAX_ONLY = "syntax_only"
    TYPED = "typed"
    DATA_FLOW = "data_flow_capable"
    EXECUTABLE = "executable"
    DOMAIN_COMPLETE = "domain_complete"


@dataclass(slots=True)
class CodeLocation:
    path: str
    line_start: int
    line_end: int | None = None
    symbol: str | None = None

    def __post_init__(self) -> None:
        if not self.path.strip():
            raise ValueError("code location path must not be empty")
        if self.line_start < 1 or (self.line_end is not None and self.line_end < self.line_start):
            raise ValueError("code location lines are invalid")


@dataclass(slots=True)
class Hypothesis:
    hypothesis_id: str
    security_property: str
    suspected_violation: str
    affected_assets: list[str]
    required_attacker_capabilities: list[str]
    assumptions: list[str]
    candidate_locations: list[CodeLocation]
    verification_plan: list[str]
    threat_lens: str
    generator: str
    graph_slice: list[str] = field(default_factory=list)
    supporting_evidence: list[str] = field(default_factory=list)
    contradicting_evidence: list[str] = field(default_factory=list)
    unresolved_assumptions: list[str] = field(default_factory=list)
    coverage_achieved: list[str] = field(default_factory=list)
    proposed_next_experiment: str | None = None
    cost: dict[str, float] = field(default_factory=dict)
    evidence_level: EvidenceLevel = EvidenceLevel.HYPOTHESIS
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    created_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        _validate_identifier(self.hypothesis_id, "H")
        if not self.security_property.strip() or not self.suspected_violation.strip():
            raise ValueError("hypothesis property and suspected violation are required")
        if not self.candidate_locations or not self.verification_plan:
            raise ValueError("hypothesis requires a location and verification plan")

    def to_dict(self) -> dict[str, Any]:
        value = jsonable(self)
        validate_contract(value, "hypothesis.schema.json")
        return value

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Hypothesis":
        validate_contract(value, "hypothesis.schema.json")
        required = {
            "hypothesis_id",
            "security_property",
            "suspected_violation",
            "affected_assets",
            "required_attacker_capabilities",
            "assumptions",
            "candidate_locations",
            "verification_plan",
            "threat_lens",
            "generator",
        }
        missing = required - value.keys()
        if missing:
            raise ValueError(f"hypothesis lacks required fields: {sorted(missing)}")
        locations = [CodeLocation(**item) for item in value["candidate_locations"]]
        return cls(
            hypothesis_id=str(value["hypothesis_id"]),
            security_property=str(value["security_property"]),
            suspected_violation=str(value["suspected_violation"]),
            affected_assets=[str(item) for item in value["affected_assets"]],
            required_attacker_capabilities=[
                str(item) for item in value["required_attacker_capabilities"]
            ],
            assumptions=[str(item) for item in value["assumptions"]],
            candidate_locations=locations,
            verification_plan=[str(item) for item in value["verification_plan"]],
            threat_lens=str(value["threat_lens"]),
            generator=str(value["generator"]),
            graph_slice=[str(item) for item in value.get("graph_slice", [])],
            supporting_evidence=[str(item) for item in value.get("supporting_evidence", [])],
            contradicting_evidence=[str(item) for item in value.get("contradicting_evidence", [])],
            unresolved_assumptions=[str(item) for item in value.get("unresolved_assumptions", [])],
            coverage_achieved=[str(item) for item in value.get("coverage_achieved", [])],
            proposed_next_experiment=value.get("proposed_next_experiment"),
            cost={str(key): float(item) for key, item in value.get("cost", {}).items()},
            evidence_level=EvidenceLevel(value.get("evidence_level", EvidenceLevel.HYPOTHESIS.value)),
            status=HypothesisStatus(value.get("status", HypothesisStatus.PROPOSED.value)),
            created_at=str(value.get("created_at", utc_now())),
        )


@dataclass(slots=True)
class EvidenceRecord:
    evidence_id: str
    hypothesis_id: str | None
    level: EvidenceLevel
    kind: str
    summary: str
    source: str
    artifact_path: str | None = None
    artifact_sha256: str | None = None
    command: list[str] = field(default_factory=list)
    tool_version: str | None = None
    assumptions: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        _validate_identifier(self.evidence_id, "E")
        if self.hypothesis_id is not None:
            _validate_identifier(self.hypothesis_id, "H")
        if not self.kind.strip() or not self.summary.strip() or not self.source.strip():
            raise ValueError("evidence kind, summary, and source are required")
        if (self.artifact_path is None) != (self.artifact_sha256 is None):
            raise ValueError("artifact path and hash must be provided together")
        if self.artifact_sha256 is not None and not re.fullmatch(r"[a-f0-9]{64}", self.artifact_sha256):
            raise ValueError("artifact hash must be a lowercase SHA-256 digest")
        if EVIDENCE_RANK[self.level] >= EVIDENCE_RANK[EvidenceLevel.STRUCTURALLY_CONFIRMED]:
            if self.artifact_path is None:
                raise ValueError("structural and stronger evidence requires a hashed artifact")
        if EVIDENCE_RANK[self.level] >= EVIDENCE_RANK[EvidenceLevel.EXECUTABLE] and not self.command:
            raise ValueError("executable and stronger evidence requires the reproducing command array")

    def to_dict(self) -> dict[str, Any]:
        value = jsonable(self)
        validate_contract(value, "evidence.schema.json")
        return value

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "EvidenceRecord":
        validate_contract(value, "evidence.schema.json")
        required = {"evidence_id", "level", "kind", "summary", "source"}
        missing = required - value.keys()
        if missing:
            raise ValueError(f"evidence lacks required fields: {sorted(missing)}")
        return cls(
            evidence_id=str(value["evidence_id"]),
            hypothesis_id=str(value["hypothesis_id"]) if value.get("hypothesis_id") is not None else None,
            level=EvidenceLevel(value["level"]),
            kind=str(value["kind"]),
            summary=str(value["summary"]),
            source=str(value["source"]),
            artifact_path=value.get("artifact_path"),
            artifact_sha256=value.get("artifact_sha256"),
            command=[str(item) for item in value.get("command", [])],
            tool_version=value.get("tool_version"),
            assumptions=[str(item) for item in value.get("assumptions", [])],
            metadata=dict(value.get("metadata", {})),
            created_at=str(value.get("created_at", utc_now())),
        )


@dataclass(slots=True)
class Finding:
    finding_id: str
    hypothesis_id: str
    title: str
    severity: Severity
    evidence_level: EvidenceLevel
    security_property: str
    root_cause: str
    locations: list[CodeLocation]
    attacker_prerequisites: list[str]
    assumptions: list[str]
    causal_path: list[str]
    reproducer: str
    impact: str
    reproduction_instructions: list[str]
    remediation: str
    regression_test: str
    supporting_evidence: list[str]
    reproducer_evidence_id: str | None = None
    novelty: NoveltyClass = NoveltyClass.UNCERTAIN
    related_issues: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        _validate_identifier(self.finding_id, "F")
        _validate_identifier(self.hypothesis_id, "H")
        required_text = {
            "title": self.title,
            "security_property": self.security_property,
            "root_cause": self.root_cause,
            "reproducer": self.reproducer,
            "impact": self.impact,
            "remediation": self.remediation,
            "regression_test": self.regression_test,
        }
        empty = [name for name, value in required_text.items() if not value.strip()]
        if empty:
            raise ValueError(f"finding fields must not be empty: {', '.join(empty)}")
        if not self.locations or not self.causal_path or not self.reproduction_instructions:
            raise ValueError("finding requires locations, a causal path, and reproduction instructions")
        if not self.supporting_evidence:
            raise ValueError("finding requires explicit supporting evidence identifiers")
        if len(set(self.supporting_evidence)) != len(self.supporting_evidence):
            raise ValueError("finding supporting evidence identifiers must be unique")
        for evidence_id in self.supporting_evidence:
            _validate_identifier(evidence_id, "E")
        if self.reproducer_evidence_id is not None:
            _validate_identifier(self.reproducer_evidence_id, "E")
            if self.reproducer_evidence_id not in self.supporting_evidence:
                raise ValueError("finding reproducer evidence must be listed as supporting evidence")

    def validate_reporting_gate(self) -> None:
        if EVIDENCE_RANK[self.evidence_level] < EVIDENCE_RANK[EvidenceLevel.STRUCTURALLY_CONFIRMED]:
            raise ValueError("a confirmed finding requires structurally confirmed evidence or stronger")
        if self.severity in {Severity.HIGH, Severity.CRITICAL}:
            if EVIDENCE_RANK[self.evidence_level] < EVIDENCE_RANK[EvidenceLevel.EXECUTABLE]:
                raise ValueError("high and critical findings require executable evidence or stronger")
        if EVIDENCE_RANK[self.evidence_level] >= EVIDENCE_RANK[EvidenceLevel.EXECUTABLE]:
            if self.reproducer_evidence_id is None:
                raise ValueError("executable findings require a runner-minted reproducer evidence id")

    def to_dict(self) -> dict[str, Any]:
        self.validate_reporting_gate()
        value = jsonable(self)
        validate_contract(value, "finding.schema.json")
        return value

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Finding":
        validate_contract(value, "finding.schema.json")
        finding = cls(
            finding_id=str(value["finding_id"]),
            hypothesis_id=str(value["hypothesis_id"]),
            title=str(value["title"]),
            severity=Severity(value["severity"]),
            evidence_level=EvidenceLevel(value["evidence_level"]),
            security_property=str(value["security_property"]),
            root_cause=str(value["root_cause"]),
            locations=[CodeLocation(**item) for item in value["locations"]],
            attacker_prerequisites=[str(item) for item in value["attacker_prerequisites"]],
            assumptions=[str(item) for item in value["assumptions"]],
            causal_path=[str(item) for item in value["causal_path"]],
            reproducer=str(value["reproducer"]),
            impact=str(value["impact"]),
            reproduction_instructions=[str(item) for item in value["reproduction_instructions"]],
            remediation=str(value["remediation"]),
            regression_test=str(value["regression_test"]),
            supporting_evidence=[str(item) for item in value["supporting_evidence"]],
            reproducer_evidence_id=(
                str(value["reproducer_evidence_id"])
                if value.get("reproducer_evidence_id") is not None
                else None
            ),
            novelty=NoveltyClass(value.get("novelty", NoveltyClass.UNCERTAIN.value)),
            related_issues=[str(item) for item in value.get("related_issues", [])],
        )
        finding.validate_reporting_gate()
        return finding


@dataclass(slots=True)
class DifferentialOutcome:
    implementation: str
    return_code: int | None
    normalized_output: str | None
    stdout_sha256: str
    stderr_sha256: str
    duration_ms: int
    run_count: int = 1
    flaky: bool = False
    observed_signatures: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass(slots=True)
class DifferentialMismatch:
    case_id: str
    input_sha256: str
    outcomes: list[DifferentialOutcome]
    classification: MismatchClass = MismatchClass.UNCLASSIFIED
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return jsonable(self)


def _validate_identifier(value: str, prefix: str) -> None:
    if not re.fullmatch(rf"{prefix}-[A-Za-z0-9._-]+", value):
        raise ValueError(f"identifier must match {prefix}-[A-Za-z0-9._-]+")
