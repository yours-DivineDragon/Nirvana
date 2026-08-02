import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from nirvana.cli import main


ROOT = Path(__file__).resolve().parents[1]
DIFF_FIXTURE = ROOT / "tests" / "fixtures" / "differential"
BENCHMARK_TEMPLATE = (
    ROOT / ".agents" / "skills" / "nirvana-audit" / "assets" / "benchmark-manifest.json"
)


class CliFailureReportingTests(unittest.TestCase):
    def test_blocked_differential_run_is_invalid_and_exits_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = main(
                    [
                        "spec",
                        "compare",
                        str(DIFF_FIXTURE / "manifest.toml"),
                        "--output",
                        str(output),
                    ]
                )
            lines = stdout.getvalue().splitlines()
            self.assertEqual(result, 2)
            self.assertTrue(lines[0].startswith("INVALID differential run:"))
            self.assertIn("blocked executions: 8", lines[0])
            self.assertNotIn("mismatches: 0", stdout.getvalue())
            report = json.loads(output.read_text())
            self.assertFalse(report["valid"])
            self.assertEqual(report["successful_executions"], 0)

    def test_contaminated_benchmark_suppresses_metrics_and_exits_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "benchmark.json"
            manifest.write_text(BENCHMARK_TEMPLATE.read_text())
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = main(["benchmark", "evaluate", str(manifest)])
            lines = stdout.getvalue().splitlines()
            output = root / "benchmark-report.json"
            self.assertEqual(result, 2)
            self.assertEqual(
                lines[0],
                "INVALID benchmark: temporal validation failed; metrics suppressed",
            )
            self.assertIn("violation: benchmark is not marked blind", lines)
            self.assertNotIn("precision:", stdout.getvalue())
            self.assertTrue(output.is_file())
            report = json.loads(output.read_text())
            self.assertFalse(report["valid"])
            self.assertIsNone(report["metrics"])
            self.assertIsNone(report["magma"])
            self.assertIn("benchmark is not marked blind", report["invalid_reasons"])


if __name__ == "__main__":
    unittest.main()
