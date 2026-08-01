import tempfile
import unittest
from pathlib import Path

from nirvana.contracts import ContractValidationError
from nirvana.verification import ExecutionRequest, snapshot_harness


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
