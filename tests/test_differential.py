import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from nirvana.differential import (
    DifferentialManifest,
    compare,
    validate_differential_report_consistency,
)
from nirvana.policy import CommandResult, CommandRunner, ExecutionMode, ExecutionPolicy


FIXTURE = Path(__file__).parent / "fixtures" / "differential"


class DifferentialTests(unittest.TestCase):
    def test_execution_is_denied_by_default(self) -> None:
        report = compare(
            DifferentialManifest.load(FIXTURE / "manifest.toml"),
            CommandRunner(ExecutionPolicy(), ExecutionMode.DENY),
        )
        self.assertEqual(report.blocked_executions, 8)
        self.assertEqual(report.scheduled_executions, 8)
        self.assertEqual(report.successful_executions, 0)
        self.assertFalse(report.valid)
        self.assertIn("blocked by policy", " ".join(report.invalid_reasons))
        self.assertEqual(report.mismatches, [])

    def test_independent_implementations_surface_odd_rounding(self) -> None:
        policy = ExecutionPolicy(
            allow_host_execution=True, accept_host_network_risk=True
        )
        report = compare(
            DifferentialManifest.load(FIXTURE / "manifest.toml"),
            CommandRunner(policy, ExecutionMode.HOST),
        )
        self.assertEqual(report.case_count, 2)
        self.assertEqual([item.case_id for item in report.mismatches], ["odd"])
        self.assertEqual(report.mismatches[0].classification.value, "unclassified")
        self.assertEqual(report.repetitions, 2)
        self.assertEqual(
            [item["language"] for item in report.implementations], ["python", "python"]
        )
        self.assertTrue(all(item["source_sha256"] for item in report.implementations))
        self.assertEqual(report.to_dict()["schema_version"], "2.1.0")
        self.assertTrue(report.valid)
        self.assertEqual(report.successful_executions, report.scheduled_executions)
        self.assertEqual(report.invalid_reasons, [])
        self.assertEqual(report.mismatches[0].input, {"value": 3})
        self.assertTrue(report.mismatches[0].outcomes[0].stdout_base64)

    def test_seeded_fuzzing_extends_the_corpus_deterministically(self) -> None:
        manifest = replace(
            DifferentialManifest.load(FIXTURE / "manifest.toml"),
            fuzz_cases=5,
            fuzz_seed=42,
        )
        policy = ExecutionPolicy(
            allow_host_execution=True, accept_host_network_risk=True
        )
        first = compare(manifest, CommandRunner(policy, ExecutionMode.HOST))
        second = compare(manifest, CommandRunner(policy, ExecutionMode.HOST))
        self.assertEqual(first.fuzz_case_count, 5)
        self.assertEqual(first.case_count, 7)
        self.assertEqual(
            [item.case_id for item in first.mismatches],
            [item.case_id for item in second.mismatches],
        )

    def test_repeated_runs_flag_flaky_implementations(self) -> None:
        manifest = DifferentialManifest.load(FIXTURE / "manifest.toml")
        runner = CommandRunner(ExecutionPolicy(), ExecutionMode.DENY)
        counts: dict[str, int] = {}

        def unstable(command, _cwd, _stdin):
            key = command[-1]
            counts[key] = counts.get(key, 0) + 1
            value = 2 if key == "implementation_a.py" and counts[key] % 2 == 0 else 1
            return CommandResult(command, 0, f'{{"value":{value}}}\n'.encode(), b"", 1)

        with patch.object(runner, "run", side_effect=unstable):
            report = compare(manifest, runner)

        self.assertEqual(report.flaky_executions, 2)
        self.assertTrue(
            all(
                any(outcome.flaky for outcome in mismatch.outcomes)
                for mismatch in report.mismatches
            )
        )

    def test_nonzero_normalized_result_remains_a_comparable_outcome(self) -> None:
        manifest = DifferentialManifest.load(FIXTURE / "manifest.toml")
        runner = CommandRunner(ExecutionPolicy(), ExecutionMode.DENY)

        def observable_error(command, _cwd, _stdin):
            return CommandResult(
                command,
                1 if command[-1] == "implementation_b.py" else 0,
                b'{"error":"rejected"}\n',
                b"",
                1,
            )

        with patch.object(runner, "run", side_effect=observable_error):
            report = compare(manifest, runner)

        self.assertTrue(report.valid)
        self.assertEqual(report.successful_executions, report.scheduled_executions)
        self.assertTrue(report.mismatches)

    def test_report_validity_is_derived_from_cross_field_execution_facts(self) -> None:
        manifest = DifferentialManifest.load(FIXTURE / "manifest.toml")
        denied = compare(
            manifest, CommandRunner(ExecutionPolicy(), ExecutionMode.DENY)
        ).to_dict()
        denied["valid"] = True
        with self.assertRaisesRegex(ValueError, "validity conflicts"):
            validate_differential_report_consistency(denied)

        valid = compare(
            manifest,
            CommandRunner(
                ExecutionPolicy(
                    allow_host_execution=True, accept_host_network_risk=True
                ),
                ExecutionMode.HOST,
            ),
        ).to_dict()
        valid["scheduled_executions"] += 1
        with self.assertRaisesRegex(ValueError, "scheduled execution count conflicts"):
            validate_differential_report_consistency(valid)

    def test_fuzz_budget_shortfall_is_reported(self) -> None:
        manifest = replace(
            DifferentialManifest.load(FIXTURE / "manifest.toml"),
            fuzz_cases=32,
            fuzz_seed=20260801,
        )
        report = compare(manifest, CommandRunner(ExecutionPolicy(), ExecutionMode.DENY))
        self.assertEqual(report.requested_fuzz_case_count, 32)
        self.assertEqual(report.fuzz_case_count, 8)
        self.assertTrue(
            any(
                "generated 8 of 32 requested fuzz cases" in warning
                for warning in report.warnings
            )
        )


if __name__ == "__main__":
    unittest.main()
