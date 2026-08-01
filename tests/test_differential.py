import tempfile
import unittest
from pathlib import Path

from nirvana.differential import DifferentialManifest, compare
from nirvana.policy import CommandRunner, ExecutionMode, ExecutionPolicy


FIXTURE = Path(__file__).parent / "fixtures" / "differential"


class DifferentialTests(unittest.TestCase):
    def test_execution_is_denied_by_default(self) -> None:
        report = compare(
            DifferentialManifest.load(FIXTURE / "manifest.toml"),
            CommandRunner(ExecutionPolicy(), ExecutionMode.DENY),
        )
        self.assertEqual(report.blocked_executions, 4)
        self.assertEqual(report.mismatches, [])

    def test_independent_implementations_surface_odd_rounding(self) -> None:
        policy = ExecutionPolicy(allow_host_execution=True, allow_network=True)
        report = compare(
            DifferentialManifest.load(FIXTURE / "manifest.toml"),
            CommandRunner(policy, ExecutionMode.HOST),
        )
        self.assertEqual(report.case_count, 2)
        self.assertEqual([item.case_id for item in report.mismatches], ["odd"])
        self.assertEqual(report.mismatches[0].classification.value, "unclassified")


if __name__ == "__main__":
    unittest.main()
