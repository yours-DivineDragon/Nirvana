import json
import tempfile
import unittest
from pathlib import Path

from nirvana.board import HypothesisBoard
from nirvana.ledger import EvidenceLedger
from nirvana.models import EvidenceLevel
from nirvana.util import sha256_file
from nirvana.workflow import audit


FIXTURE = Path(__file__).parent / "fixtures" / "evm"


class BoardTests(unittest.TestCase):
    def test_import_evidence_and_enforce_finding_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            evidence_path = root / "evidence.json"
            evidence_path.write_text(
                json.dumps(
                    {
                        "evidence_id": "E-1",
                        "hypothesis_id": result.hypotheses[0].hypothesis_id,
                        "level": EvidenceLevel.LOCALISED.value,
                        "kind": "manual_slice",
                        "summary": "Exact code site inspected",
                        "source": "analyst",
                    }
                )
            )
            board = HypothesisBoard(result.run_directory)
            board.import_evidence(evidence_path)
            self.assertEqual(EvidenceLedger(result.run_directory / "evidence.jsonl").verify(), 5)

            finding_path = root / "finding.json"
            finding_path.write_text(
                json.dumps(
                    {
                        "finding_id": "F-1",
                        "hypothesis_id": result.hypotheses[0].hypothesis_id,
                        "title": "Unproven",
                        "severity": "high",
                        "evidence_level": "structurally_confirmed",
                        "security_property": "property",
                        "root_cause": "cause",
                        "locations": [{"path": "src/Vault.sol", "line_start": 1}],
                        "attacker_prerequisites": ["caller"],
                        "assumptions": ["assumption"],
                        "causal_path": ["input", "effect"],
                        "reproducer": "test",
                        "impact": "impact",
                        "reproduction_instructions": ["run test"],
                        "remediation": "fix",
                        "regression_test": "test fix",
                    }
                )
            )
            with self.assertRaisesRegex(ValueError, "executable evidence"):
                board.confirm_finding(finding_path)

    def test_confirmed_level_cannot_exceed_recorded_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            hypothesis_id = result.hypotheses[0].hypothesis_id
            evidence_path = root / "evidence.json"
            evidence_path.write_text(
                json.dumps(
                    {
                        "evidence_id": "E-LOCAL",
                        "hypothesis_id": hypothesis_id,
                        "level": "localised",
                        "kind": "manual_slice",
                        "summary": "Exact code site inspected",
                        "source": "analyst",
                    }
                )
            )
            board = HypothesisBoard(result.run_directory)
            board.import_evidence(evidence_path)
            finding_path = root / "finding.json"
            finding_path.write_text(
                json.dumps(
                    {
                        "finding_id": "F-STRUCTURAL",
                        "hypothesis_id": hypothesis_id,
                        "title": "Unsupported promotion",
                        "severity": "medium",
                        "evidence_level": "structurally_confirmed",
                        "security_property": "property",
                        "root_cause": "cause",
                        "locations": [{"path": "src/Vault.sol", "line_start": 13}],
                        "attacker_prerequisites": ["caller"],
                        "assumptions": ["assumption"],
                        "causal_path": ["input", "effect"],
                        "reproducer": "test",
                        "impact": "impact",
                        "reproduction_instructions": ["run test"],
                        "remediation": "fix",
                        "regression_test": "test fix",
                    }
                )
            )
            with self.assertRaisesRegex(ValueError, "exceeds its recorded"):
                board.confirm_finding(finding_path)

    def test_executable_evidence_can_confirm_and_refresh_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            hypothesis_id = result.hypotheses[0].hypothesis_id
            artifact = root / "poc.txt"
            artifact.write_text("reproducible counterexample\n")
            evidence_path = root / "evidence.json"
            evidence_path.write_text(
                json.dumps(
                    {
                        "evidence_id": "E-POC",
                        "hypothesis_id": hypothesis_id,
                        "level": "executable",
                        "kind": "failing_test",
                        "summary": "A reviewed fixture produced the counterexample",
                        "source": "test",
                        "artifact_path": str(artifact),
                        "artifact_sha256": sha256_file(artifact),
                        "command": ["python3", "poc.py"],
                        "tool_version": "fixture",
                    }
                )
            )
            board = HypothesisBoard(result.run_directory)
            board.import_evidence(evidence_path)
            finding_path = root / "finding.json"
            finding_path.write_text(
                json.dumps(
                    {
                        "finding_id": "F-POC",
                        "hypothesis_id": hypothesis_id,
                        "title": "Executable fixture finding",
                        "severity": "high",
                        "evidence_level": "executable",
                        "security_property": "Authorization is bound to the caller",
                        "root_cause": "The fixture uses an unsafe caller identity",
                        "locations": [{"path": "src/Vault.sol", "line_start": 13}],
                        "attacker_prerequisites": ["intermediary contract"],
                        "assumptions": ["fixture semantics"],
                        "causal_path": ["intermediary", "tx.origin", "authority branch"],
                        "reproducer": str(artifact),
                        "impact": "Unauthorized behavior in the fixture",
                        "reproduction_instructions": ["run python3 poc.py"],
                        "remediation": "Bind authorization to the intended caller",
                        "regression_test": "Reject the intermediary caller",
                    }
                )
            )
            board.confirm_finding(finding_path)
            report = json.loads((result.run_directory / "report.json").read_text())
            self.assertEqual([item["finding_id"] for item in report["confirmed_findings"]], ["F-POC"])


if __name__ == "__main__":
    unittest.main()
