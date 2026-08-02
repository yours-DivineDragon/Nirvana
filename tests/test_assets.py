import json
import unittest
from pathlib import Path

from nirvana.baseline import BaselineRequest
from nirvana.contracts import validate_contract
from nirvana.evaluation import evaluate_benchmark
from nirvana.models import EvidenceRecord, Finding, Hypothesis
from nirvana.verification import ExecutionRequest


ASSETS = (
    Path(__file__).parents[1]
    / ".agents"
    / "skills"
    / "nirvana-audit"
    / "assets"
)


class SkillAssetTests(unittest.TestCase):
    def load(self, name: str) -> dict:
        return json.loads((ASSETS / name).read_text(encoding="utf-8"))

    def test_core_templates_satisfy_runtime_models(self) -> None:
        Hypothesis.from_dict(self.load("hypothesis.json"))
        EvidenceRecord.from_dict(self.load("evidence.json"))
        Finding.from_dict(self.load("finding.json"))
        BaselineRequest.from_path(ASSETS / "baseline-request.json")
        for name in (
            "execution-request.json",
            "exploit-request.json",
            "formal-request.json",
        ):
            with self.subTest(name=name):
                ExecutionRequest.from_dict(self.load(name))

    def test_workflow_templates_satisfy_runtime_contracts(self) -> None:
        contracts = {
            "critic-decision.json": "critic-decision.schema.json",
            "known-issue-corpus.json": "known-issue-corpus.schema.json",
            "deployment-attestation.json": "deployment-attestation.schema.json",
            "detector-review.json": "detector-review.schema.json",
            "disclosure-agent-context.json": "disclosure-agent-context.schema.json",
            "benchmark-case-pack.json": "benchmark-case-pack.schema.json",
        }
        for asset, schema in contracts.items():
            with self.subTest(asset=asset):
                validate_contract(self.load(asset), schema)

    def test_benchmark_template_is_evaluable(self) -> None:
        report = evaluate_benchmark(ASSETS / "benchmark-manifest.json")
        self.assertFalse(report["valid"])
        self.assertFalse(report["temporal_validation"]["valid"])
        self.assertFalse(report["release_gates"]["closed_beta"]["passed"])
        self.assertIsNone(report["metrics"])
        self.assertIsNone(report["magma"])
        self.assertTrue(report["invalid_reasons"])


if __name__ == "__main__":
    unittest.main()
