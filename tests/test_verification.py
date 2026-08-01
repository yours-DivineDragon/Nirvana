import unittest

from nirvana.contracts import ContractValidationError
from nirvana.verification import ExecutionRequest


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
        "command": ["pytest", "-q", "test_exploit.py"],
        "expected_return_codes": [0],
        "tool_version": "pytest-9",
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


if __name__ == "__main__":
    unittest.main()
