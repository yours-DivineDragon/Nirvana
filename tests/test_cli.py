import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from nirvana.cli import main


ROOT = Path(__file__).resolve().parents[1]
DIFF_FIXTURE = ROOT / "tests" / "fixtures" / "differential"
EVM_FIXTURE = ROOT / "tests" / "fixtures" / "evm"
BENCHMARK_TEMPLATE = (
    ROOT / ".agents" / "skills" / "nirvana-audit" / "assets" / "benchmark-manifest.json"
)


class CliFailureReportingTests(unittest.TestCase):
    def test_detached_differential_attach_command_is_unavailable(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            main(["spec", "attach", "run", "report.json"])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("invalid choice: 'attach'", stderr.getvalue())

    def test_compare_can_attach_its_in_process_result_to_an_audit_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runs = root / "runs"
            policy = root / "policy.toml"
            policy.write_text(
                "[execution]\n"
                "allow_host_execution = true\n"
                "accept_host_network_risk = true\n"
            )
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(
                    main(["audit", str(EVM_FIXTURE), "--output", str(runs)]),
                    0,
                )
            run_directory = next(runs.iterdir())
            output = root / "differential-report.json"

            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                result = main(
                    [
                        "spec",
                        "compare",
                        str(DIFF_FIXTURE / "manifest.toml"),
                        "--policy",
                        str(policy),
                        "--execution-mode",
                        "host",
                        "--output",
                        str(output),
                        "--run-directory",
                        str(run_directory),
                    ]
                )

            self.assertEqual(result, 0)
            events = [
                json.loads(line)["payload"]
                for line in (run_directory / "evidence.jsonl").read_text().splitlines()
            ]
            attachment = next(
                item
                for item in events
                if item.get("event") == "differential_report_attached"
            )
            self.assertEqual(
                attachment["attachment_source"], "in_process_spec_compare"
            )
            self.assertEqual(attachment["source_sha256"], attachment["artifact_sha256"])

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
                "INVALID benchmark: validation failed; metrics suppressed",
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
