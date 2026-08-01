import unittest

from nirvana.models import CodeLocation, EvidenceLevel, EvidenceRecord, Finding, Severity


class FindingGateTests(unittest.TestCase):
    def finding(self, level: EvidenceLevel) -> Finding:
        return Finding(
            finding_id="F-1",
            hypothesis_id="H-1",
            title="Test",
            severity=Severity.HIGH,
            evidence_level=level,
            security_property="property",
            root_cause="cause",
            locations=[CodeLocation("A.sol", 1)],
            attacker_prerequisites=["caller"],
            assumptions=["assumption"],
            causal_path=["input", "effect"],
            reproducer="test_reproducer",
            impact="impact",
            reproduction_instructions=["run test"],
            remediation="fix",
            regression_test="test_fix",
            supporting_evidence=["E-1"],
            reproducer_evidence_id=(
                "E-1"
                if level.value in {"executable", "exploit_demonstrated", "formally_established"}
                else None
            ),
        )

    def test_high_severity_rejects_structural_evidence(self) -> None:
        with self.assertRaisesRegex(ValueError, "executable evidence"):
            self.finding(EvidenceLevel.STRUCTURALLY_CONFIRMED).validate_reporting_gate()

    def test_high_severity_accepts_executable_evidence(self) -> None:
        self.finding(EvidenceLevel.EXECUTABLE).validate_reporting_gate()

    def test_structural_evidence_requires_hashed_artifact(self) -> None:
        with self.assertRaisesRegex(ValueError, "hashed artifact"):
            EvidenceRecord(
                evidence_id="E-1",
                hypothesis_id="H-1",
                level=EvidenceLevel.STRUCTURALLY_CONFIRMED,
                kind="static_path",
                summary="A path exists",
                source="tool",
            )


if __name__ == "__main__":
    unittest.main()
