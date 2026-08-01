import tempfile
import unittest
from pathlib import Path

from nirvana.contracts import ContractValidationError
from nirvana.policy import CommandResult
from nirvana.verification import (
    AdapterOutcome,
    ExecutionRequest,
    classify_adapter_outcome,
    snapshot_harness,
)


def request() -> dict:
    return {
        "evidence_id": "E-1",
        "hypothesis_id": "H-1",
        "evidence_level": "executable",
        "kind": "failing_test",
        "summary": "A named test establishes the violation",
        "adapter": "pytest",
        "claim": {
            "security_property": "Only the owner may withdraw",
            "suspected_violation": "An arbitrary caller can withdraw",
        },
        "assertions": [
            {
                "assertion_id": "A-1",
                "source": "stdout",
                "operator": "contains",
                "value": "violation reproduced",
            }
        ],
        "control_invariants": [
            {
                "assertion_id": "A-VERIFIER-HEALTHY",
                "source": "stdout",
                "operator": "contains",
                "value": "collected 1 item",
            }
        ],
        "command": ["pytest", "-q", "test_exploit.py"],
        "expected_return_codes": [0],
        "tool_version": "pytest-9",
        "negative_control": {
            "target_root": "/tmp/nirvana-patched-target",
            "changed_files": ["src/Contract.sol"],
            "expected_return_codes": [1],
        },
    }


class VerificationContractTests(unittest.TestCase):
    def test_expected_return_code_must_be_singular(self) -> None:
        value = request()
        value["expected_return_codes"] = [0, 1]
        with self.assertRaisesRegex(ValueError, "at most 1 items|exactly one"):
            ExecutionRequest.from_dict(value)

    def test_request_requires_a_checked_assertion(self) -> None:
        value = request()
        value["assertions"] = []
        with self.assertRaisesRegex(ValueError, "at least 1 items|at least one"):
            ExecutionRequest.from_dict(value)

    def test_runtime_schema_rejects_unknown_fields(self) -> None:
        value = request()
        value["trust_me"] = True
        with self.assertRaises(ContractValidationError):
            ExecutionRequest.from_dict(value)

    def test_executable_request_requires_negative_control(self) -> None:
        value = request()
        del value["negative_control"]
        with self.assertRaisesRegex(ValueError, "requires a patched-target negative control"):
            ExecutionRequest.from_dict(value)

    def test_executable_request_requires_control_invariants(self) -> None:
        value = request()
        del value["control_invariants"]
        with self.assertRaisesRegex(ValueError, "requires at least one control invariant"):
            ExecutionRequest.from_dict(value)

    def test_control_invariant_identifiers_must_be_distinct(self) -> None:
        value = request()
        value["control_invariants"][0]["assertion_id"] = "A-1"
        with self.assertRaisesRegex(ValueError, "distinct from exploit assertions"):
            ExecutionRequest.from_dict(value)

    def test_pytest_control_rejects_collection_exit_states(self) -> None:
        value = request()
        value["negative_control"]["expected_return_codes"] = [2]
        with self.assertRaisesRegex(
            ValueError, "collection, interruption, usage, and infrastructure"
        ):
            ExecutionRequest.from_dict(value)

    def test_pytest_target_rejects_collection_exit_states(self) -> None:
        value = request()
        value["expected_return_codes"] = [2]
        with self.assertRaisesRegex(
            ValueError, "collection, interruption, usage, and infrastructure"
        ):
            ExecutionRequest.from_dict(value)

    def test_executable_adapters_reject_arbitrary_exit_codes(self) -> None:
        cases = [
            ("forge-test", ["forge", "test"]),
            ("echidna", ["echidna", ".", "--format=json"]),
            ("medusa", ["medusa", "fuzz"]),
            ("halmos", ["halmos"]),
            ("node-test", ["node", "--test", "--test-reporter=tap"]),
        ]
        for adapter, command in cases:
            with self.subTest(adapter=adapter):
                value = request()
                value["adapter"] = adapter
                value["command"] = command
                value["negative_control"]["expected_return_codes"] = [101]
                with self.assertRaisesRegex(
                    ValueError, "unsupported or infrastructure outcomes"
                ):
                    ExecutionRequest.from_dict(value)

    def test_medusa_uses_its_dedicated_test_failure_code(self) -> None:
        value = request()
        value["adapter"] = "medusa"
        value["command"] = ["medusa", "fuzz"]
        value["negative_control"]["expected_return_codes"] = [1]
        with self.assertRaisesRegex(
            ValueError, "unsupported or infrastructure outcomes"
        ):
            ExecutionRequest.from_dict(value)

        value["negative_control"]["expected_return_codes"] = [7]
        parsed = ExecutionRequest.from_dict(value)
        outcome = classify_adapter_outcome(
            parsed,
            CommandResult(parsed.command, 7, b"property failed\n", b"", 1),
        )
        self.assertIs(outcome, AdapterOutcome.TEST_FAILURE)

    def test_cargo_101_requires_a_successful_json_build_and_failed_tests(self) -> None:
        value = request()
        value["adapter"] = "cargo-test"
        value["command"] = ["cargo", "test"]
        value["negative_control"]["expected_return_codes"] = [101]
        with self.assertRaisesRegex(ValueError, "requires --message-format=json"):
            ExecutionRequest.from_dict(value)

        value["command"].append("--message-format=json")
        parsed = ExecutionRequest.from_dict(value)
        failed_test = CommandResult(
            parsed.command,
            101,
            (
                b'{"reason":"build-finished","success":true}\n'
                b"running 1 test\n"
                b"test exploit ... FAILED\n"
                b"test result: FAILED. 0 passed; 1 failed; 0 ignored\n"
            ),
            b"",
            1,
        )
        failed_build = CommandResult(
            parsed.command,
            101,
            (
                b'{"reason":"build-finished","success":false}\n'
                b"test result: FAILED. 0 passed; 1 failed; 0 ignored\n"
            ),
            b"error: could not compile target\n",
            1,
        )
        self.assertIs(
            classify_adapter_outcome(parsed, failed_test),
            AdapterOutcome.TEST_FAILURE,
        )
        self.assertIs(
            classify_adapter_outcome(parsed, failed_build),
            AdapterOutcome.INVALID,
        )

    def test_forge_failure_requires_a_completed_suite_summary(self) -> None:
        value = request()
        value["adapter"] = "forge-test"
        value["command"] = ["forge", "test"]
        value["expected_return_codes"] = [1]
        parsed = ExecutionRequest.from_dict(value)
        test_failure = CommandResult(
            parsed.command,
            1,
            b"Suite result: FAILED. 0 passed; 1 failed; 0 skipped;\n",
            b"",
            1,
        )
        compile_failure = CommandResult(
            parsed.command,
            1,
            b"Compiler run failed\n",
            b"ParserError\n",
            1,
        )
        self.assertIs(
            classify_adapter_outcome(parsed, test_failure),
            AdapterOutcome.TEST_FAILURE,
        )
        self.assertIs(
            classify_adapter_outcome(parsed, compile_failure),
            AdapterOutcome.INVALID,
        )

    def test_node_failure_requires_native_tap_output(self) -> None:
        value = request()
        value["adapter"] = "node-test"
        value["command"] = ["npm", "test"]
        value["negative_control"]["expected_return_codes"] = [1]
        with self.assertRaisesRegex(ValueError, "requires native node --test"):
            ExecutionRequest.from_dict(value)

        value["command"] = ["node", "--test"]
        with self.assertRaisesRegex(ValueError, "requires --test-reporter=tap"):
            ExecutionRequest.from_dict(value)

        value["command"].append("--test-reporter=tap")
        parsed = ExecutionRequest.from_dict(value)
        test_failure = CommandResult(
            parsed.command,
            1,
            b"TAP version 13\n1..1\n# tests 1\n# pass 0\n# fail 1\n",
            b"",
            1,
        )
        startup_failure = CommandResult(
            parsed.command, 1, b"", b"Cannot find module 'test.js'\n", 1
        )
        self.assertIs(
            classify_adapter_outcome(parsed, test_failure),
            AdapterOutcome.TEST_FAILURE,
        )
        self.assertIs(
            classify_adapter_outcome(parsed, startup_failure),
            AdapterOutcome.INVALID,
        )

    def test_echidna_and_halmos_failures_require_completed_test_results(self) -> None:
        echidna_value = request()
        echidna_value["adapter"] = "echidna"
        echidna_value["command"] = ["echidna", "."]
        echidna_value["expected_return_codes"] = [1]
        with self.assertRaisesRegex(ValueError, "requires --format=json"):
            ExecutionRequest.from_dict(echidna_value)

        echidna_value["command"].append("--format=json")
        echidna = ExecutionRequest.from_dict(echidna_value)
        property_failure = CommandResult(
            echidna.command,
            1,
            b'{"success":true,"error":null,"tests":[{"status":"solved"}]}',
            b"",
            1,
        )
        tool_failure = CommandResult(
            echidna.command,
            1,
            b'{"success":false,"error":"compile failed","tests":[]}',
            b"",
            1,
        )
        self.assertIs(
            classify_adapter_outcome(echidna, property_failure),
            AdapterOutcome.TEST_FAILURE,
        )
        self.assertIs(
            classify_adapter_outcome(echidna, tool_failure),
            AdapterOutcome.INVALID,
        )

        halmos_value = request()
        halmos_value["adapter"] = "halmos"
        halmos_value["command"] = ["halmos"]
        halmos_value["expected_return_codes"] = [1]
        halmos = ExecutionRequest.from_dict(halmos_value)
        symbolic_failure = CommandResult(
            halmos.command,
            1,
            b"Symbolic test result: 1 passed; 1 failed; time: 2s\n",
            b"",
            1,
        )
        build_failure = CommandResult(
            halmos.command, 1, b"", b"Build failed: forge build\n", 1
        )
        self.assertIs(
            classify_adapter_outcome(halmos, symbolic_failure),
            AdapterOutcome.TEST_FAILURE,
        )
        self.assertIs(
            classify_adapter_outcome(halmos, build_failure),
            AdapterOutcome.INVALID,
        )

    def test_regex_assertions_are_not_supported(self) -> None:
        value = request()
        value["assertions"][0]["operator"] = "regex"
        with self.assertRaisesRegex(ValueError, "must be one of"):
            ExecutionRequest.from_dict(value)

    def test_adapter_executable_must_resolve_inside_the_sandbox(self) -> None:
        value = request()
        value["command"] = ["./pytest"]
        with self.assertRaisesRegex(ValueError, "bare tool name"):
            ExecutionRequest.from_dict(value)

    def test_harness_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "test.py").write_text("assert True\n")
            (root / "escape").symlink_to("/etc/passwd")
            with self.assertRaisesRegex(ValueError, "regular files only"):
                snapshot_harness(root)


if __name__ == "__main__":
    unittest.main()
