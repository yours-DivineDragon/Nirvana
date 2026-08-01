import json
import tempfile
import unittest
from pathlib import Path

from nirvana.ledger import EvidenceLedger
from nirvana.workflow import audit


FIXTURE = Path(__file__).parent / "fixtures" / "evm"


class WorkflowTests(unittest.TestCase):
    def test_audit_generates_reproducible_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = audit(FIXTURE, Path(directory))
            self.assertTrue((result.run_directory / "scope.json").is_file())
            self.assertTrue((result.run_directory / "hypotheses.jsonl").is_file())
            self.assertTrue((result.run_directory / "report.md").is_file())
            self.assertIn("Confirmed findings: **0**", (result.run_directory / "report.md").read_text())
            scope = json.loads((result.run_directory / "scope.json").read_text())
            report = json.loads((result.run_directory / "report.json").read_text())
            self.assertEqual(scope["evidence_ceiling"], "localised")
            self.assertEqual(report["target_snapshot_sha256"], scope["target_snapshot_sha256"])
            self.assertEqual(report["verified_evidence"], [])
            self.assertEqual(report["corroborated_evidence"], [])
            self.assertEqual(EvidenceLedger(result.run_directory / "evidence.jsonl").verify(), 4)


if __name__ == "__main__":
    unittest.main()
