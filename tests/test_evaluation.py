import json
import tempfile
import unittest
from pathlib import Path

from nirvana.evaluation import evaluate_benchmark
from nirvana.util import sha256_file


class EvaluationTests(unittest.TestCase):
    def manifest(self, root: Path | None = None) -> dict:
        trial = {
            "trial_id": "T-1",
            "case_id": "CASE-1",
            "run_id": "RUN-1",
            "seed": 1,
            "started_at": "2025-02-01T00:00:00Z",
            "ended_at": "2025-02-01T00:10:00Z",
            "model": "agent-model-version",
            "prompt_sha256": "1" * 64,
            "tools": ["nirvana-0.4.0", "forge-1"],
            "token_budget": 100000,
            "compute_hours": 0.5,
            "model_cost": 0.0,
            "transcript_sha256": "2" * 64,
            "environment_sha256": "3" * 64,
            "findings": [
                {
                    "finding_id": "F-1",
                    "verdict": "true_positive",
                    "severity": "high",
                    "evidence_level": "exploit_demonstrated",
                    "confidence": 0.95,
                    "ground_truth_id": "VULN-1",
                    "reproduced": True,
                    "duplicate": False,
                    "novel": False,
                    "time_to_finding_seconds": 300,
                    "patch_tests_passed": True,
                }
            ],
            "coverage": {
                "assets": 1.0,
                "authority_paths": 0.8,
                "state_transitions": 0.9,
                "trust_boundaries": 1.0,
            },
            "reached_ids": ["VULN-1"],
            "triggered_ids": ["VULN-1"],
            "detected_ids": ["VULN-1"],
        }
        second = json.loads(json.dumps(trial))
        second["trial_id"] = "T-2"
        second["run_id"] = "RUN-2"
        second["seed"] = 2
        release_artifacts = []
        if root is not None:
            for gate in (
                "research_prototype",
                "web3_alpha",
                "production_candidate",
                "universal_expansion",
            ):
                artifact = root / f"{gate}.json"
                artifact.write_text(json.dumps({"gate": gate, "reviewed": True}))
                release_artifacts.append(
                    {
                        "gate": gate,
                        "path": str(artifact),
                        "sha256": sha256_file(artifact),
                    }
                )
        return {
            "schema_version": "1.0.0",
            "benchmark_id": "blind-temporal-1",
            "cutoff": "2024-12-31T00:00:00Z",
            "track": "web3_hidden_variants",
            "blind": True,
            "corpora": [
                {
                    "corpus_id": "rules-pre-cutoff",
                    "role": "detector_rules",
                    "published_at": "2024-01-01T00:00:00Z",
                    "sha256": "4" * 64,
                }
            ],
            "cases": [
                {
                    "case_id": "CASE-1",
                    "repository": "local-fixture",
                    "last_vulnerable_commit": "a" * 40,
                    "originated_at": "2025-01-15T00:00:00Z",
                    "disclosed_at": "2025-03-01T00:00:00Z",
                    "eligible": True,
                    "hidden_variant": True,
                    "transformation_log_sha256": "5" * 64,
                    "kloc": 10.0,
                    "ground_truth": [
                        {"vulnerability_id": "VULN-1", "severity": "high"}
                    ],
                    "ground_truth_material_blocked": True,
                    "eventual_fix_accessed": False,
                }
            ],
            "trials": [trial, second],
            "release_evidence": {
                "reproducible_builds": True,
                "ssg_dialects": ["evm", "rust-native"],
                "deterministic_baseline": True,
                "typed_hypotheses": True,
                "executable_evidence_ledger": True,
                "dynamic_verifiers_per_ecosystem": {
                    "evm": 2,
                    "solana": 2,
                    "move-sui": 2
                },
                "deterministic_baseline_recall": 0.5,
                "auditable_cost_controls": True,
                "adapter_conformance": [
                    {
                        "dialect": "fixture-adapter",
                        "semantic_conformance": True,
                        "negative_cases": True,
                        "runtime_verification": True
                    }
                ],
                "evidence_artifacts": release_artifacts
            },
        }

    def test_all_pdf_metrics_and_temporal_release_gate_are_computed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "benchmark.json"
            path.write_text(json.dumps(self.manifest(Path(directory))))
            report = evaluate_benchmark(path)
            self.assertTrue(report["valid"])
            self.assertTrue(report["temporal_validation"]["valid"])
            self.assertEqual(report["metrics"]["validated_precision"], 1.0)
            self.assertEqual(report["metrics"]["ground_truth_recall"], 1.0)
            self.assertEqual(report["metrics"]["high_severity_precision"], 1.0)
            self.assertEqual(report["magma"]["reached"], 1)
            self.assertEqual(report["magma"]["triggered"], 1)
            self.assertEqual(report["magma"]["detected_and_explained"], 1)
            self.assertIn("calibration", report["metrics"])
            self.assertIn("cost_efficiency", report["metrics"])
            self.assertIn("stability", report["metrics"])
            self.assertTrue(report["release_gates"]["closed_beta"]["passed"])
            self.assertTrue(report["release_gates"]["research_prototype"]["passed"])
            self.assertTrue(report["release_gates"]["web3_alpha"]["passed"])
            self.assertTrue(report["release_gates"]["production_candidate"]["passed"])
            self.assertTrue(report["release_gates"]["universal_expansion"]["passed"])

    def test_post_cutoff_retrieval_invalidates_temporal_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = self.manifest(Path(directory))
            manifest["corpora"][0]["published_at"] = "2025-02-01T00:00:00Z"
            path = Path(directory) / "benchmark.json"
            path.write_text(json.dumps(manifest))
            report = evaluate_benchmark(path)
            self.assertFalse(report["valid"])
            self.assertFalse(report["temporal_validation"]["valid"])
            self.assertFalse(report["release_gates"]["closed_beta"]["passed"])
            self.assertIn("post-dates cutoff", " ".join(report["warnings"]))


if __name__ == "__main__":
    unittest.main()
