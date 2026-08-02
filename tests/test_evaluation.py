import json
import tempfile
import unittest
from pathlib import Path

from nirvana.evaluation import evaluate_benchmark
from nirvana.util import sha256_file
from nirvana.verification import snapshot_harness


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

    def qualified_manifest(self, root: Path) -> dict:
        manifest = self.manifest(root)
        manifest["benchmark_id"] = "qualified-independent-suite-1"
        cases = []
        trials = []
        pack_cases = []
        attestation = root / "case-pack-author-attestation.json"
        attestation.write_text(
            json.dumps({"author": "independent-team", "operator_access": False})
        )

        for index in range(1, 31):
            case_id = f"CASE-{index:03d}"
            vulnerability_id = f"GT-{index:03d}"
            vulnerable = index <= 20
            originated_at = "2025-01-15T00:00:00Z"
            target = root / "case-pack-assets" / case_id / "target"
            target.mkdir(parents=True)
            (target / "Fixture.sol").write_text(
                f"contract Fixture{index} {{ function value() external pure returns (uint) {{ return {index}; }} }}\n"
            )
            commitment = target.parent / "commitment.json"
            commitment.write_text(
                json.dumps({"case_id": case_id, "snapshot_committed": True})
            )
            sealed = target.parent / "ground-truth.age"
            sealed.write_text(
                f"age-encryption.org/v1\nfixture-ciphertext-{case_id}\n"
            )
            pack_cases.append(
                {
                    "case_id": case_id,
                    "originated_at": originated_at,
                    "target_path": target.relative_to(root).as_posix(),
                    "target_snapshot_sha256": snapshot_harness(target).snapshot_sha256,
                    "public_commitment_path": commitment.relative_to(root).as_posix(),
                    "public_commitment_sha256": sha256_file(commitment),
                    "sealed_ground_truth_path": sealed.relative_to(root).as_posix(),
                    "sealed_ground_truth_sha256": sha256_file(sealed),
                }
            )
            cases.append(
                {
                    "case_id": case_id,
                    "repository": f"local-fixture/{case_id}",
                    "last_vulnerable_commit": f"{index:040x}",
                    "originated_at": originated_at,
                    "disclosed_at": "2025-03-01T00:00:00Z",
                    "eligible": True,
                    "hidden_variant": True,
                    "transformation_log_sha256": f"{index % 10}" * 64,
                    "kloc": 1.0,
                    "ground_truth": (
                        [{"vulnerability_id": vulnerability_id, "severity": "high"}]
                        if vulnerable
                        else []
                    ),
                    "ground_truth_material_blocked": True,
                    "eventual_fix_accessed": False,
                }
            )
            for seed in (1, 2, 3):
                findings = []
                if vulnerable:
                    findings.append(
                        {
                            "finding_id": f"F-{index:03d}-{seed}",
                            "verdict": "true_positive",
                            "severity": "high",
                            "evidence_level": "executable",
                            "confidence": 0.95,
                            "ground_truth_id": vulnerability_id,
                            "reproduced": True,
                            "duplicate": False,
                            "novel": False,
                            "time_to_finding_seconds": 60,
                            "patch_tests_passed": True,
                        }
                    )
                trials.append(
                    {
                        "trial_id": f"T-{index:03d}-{seed}",
                        "case_id": case_id,
                        "run_id": f"RUN-{index:03d}-{seed}",
                        "seed": seed,
                        "started_at": "2025-02-01T00:00:00Z",
                        "ended_at": "2025-02-01T00:10:00Z",
                        "model": "agent-model-version",
                        "prompt_sha256": "1" * 64,
                        "tools": ["nirvana-0.4.4", "forge-1"],
                        "token_budget": 10000,
                        "tokens_used": 500,
                        "cost_accounting_complete": True,
                        "compute_hours": 0.1,
                        "model_cost": 0.01,
                        "transcript_sha256": "2" * 64,
                        "environment_sha256": "3" * 64,
                        "findings": findings,
                        "coverage": {
                            "assets": 1.0,
                            "authority_paths": 1.0,
                            "state_transitions": 1.0,
                            "trust_boundaries": 1.0,
                        },
                        "reached_ids": [vulnerability_id] if vulnerable else [],
                        "triggered_ids": [vulnerability_id] if vulnerable else [],
                        "detected_ids": [vulnerability_id] if vulnerable else [],
                    }
                )

        pack = {
            "schema_version": "1.0.0",
            "pack_id": "independent-qualified-pack-1",
            "cutoff": manifest["cutoff"],
            "created_at": "2025-01-20T00:00:00Z",
            "author_attestation": {
                "author_id": "independent-team",
                "independent_from_trial_operator": True,
                "custody_model": "separate_human",
                "artifact_path": attestation.relative_to(root).as_posix(),
                "artifact_sha256": sha256_file(attestation),
            },
            "ground_truth_sealing": {
                "method": "age",
                "recipient_fingerprint": "age1fixture-recipient",
            },
            "generator": {
                "name": "fixture-transformer",
                "version": "1.0.0",
                "source_sha256": "9" * 64,
                "randomness": "os-csprng",
            },
            "cases": pack_cases,
        }
        pack_path = root / "benchmark-case-pack.json"
        pack_path.write_text(json.dumps(pack))
        manifest["case_pack"] = {
            "path": pack_path.relative_to(root).as_posix(),
            "sha256": sha256_file(pack_path),
        }
        manifest["cases"] = cases
        manifest["trials"] = trials
        return manifest

    def test_all_pdf_metrics_and_temporal_release_gate_are_computed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "benchmark.json"
            path.write_text(json.dumps(self.manifest(Path(directory))))
            report = evaluate_benchmark(path)
            self.assertTrue(report["valid"])
            self.assertEqual(report["schema_version"], "1.3.0")
            self.assertEqual(report["invalid_reasons"], [])
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
            self.assertTrue(
                report["release_gates"]["closed_beta"]["precision_thresholds_met"]
            )
            self.assertFalse(report["suite_qualification"]["qualified"])
            self.assertFalse(report["release_gates"]["closed_beta"]["passed"])
            self.assertTrue(report["release_gates"]["research_prototype"]["passed"])
            self.assertTrue(report["release_gates"]["web3_alpha"]["passed"])
            self.assertFalse(report["release_gates"]["production_candidate"]["passed"])
            self.assertTrue(report["release_gates"]["universal_expansion"]["passed"])
            self.assertIn(
                "not operationally qualified",
                " ".join(report["warnings"]),
            )

    def test_post_cutoff_retrieval_invalidates_temporal_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = self.manifest(Path(directory))
            manifest["corpora"][0]["published_at"] = "2025-02-01T00:00:00Z"
            path = Path(directory) / "benchmark.json"
            path.write_text(json.dumps(manifest))
            report = evaluate_benchmark(path)
            self.assertFalse(report["valid"])
            self.assertFalse(report["temporal_validation"]["valid"])
            self.assertIsNone(report["metrics"])
            self.assertIsNone(report["magma"])
            self.assertEqual(
                report["invalid_reasons"], report["temporal_validation"]["violations"]
            )
            self.assertTrue(
                all(not gate["passed"] for gate in report["release_gates"].values())
            )
            self.assertIn("post-dates cutoff", " ".join(report["warnings"]))

    def test_independent_multi_case_suite_can_pass_closed_beta(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "benchmark.json"
            path.write_text(json.dumps(self.qualified_manifest(root)))
            report = evaluate_benchmark(path)
            self.assertTrue(report["valid"])
            self.assertTrue(report["suite_qualification"]["qualified"])
            self.assertTrue(all(report["suite_qualification"]["checks"].values()))
            self.assertEqual(
                report["suite_qualification"]["observed"]["eligible_vulnerable_cases"],
                20,
            )
            self.assertEqual(
                report["suite_qualification"]["observed"]["eligible_benign_controls"],
                10,
            )
            self.assertEqual(
                report["suite_qualification"]["observed"][
                    "minimum_distinct_seeds_per_eligible_case"
                ],
                3,
            )
            self.assertTrue(report["release_gates"]["closed_beta"]["passed"])
            self.assertTrue(report["release_gates"]["production_candidate"]["passed"])

    def test_localised_high_report_blocks_suite_qualification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.qualified_manifest(root)
            manifest["trials"][0]["findings"][0]["evidence_level"] = "localised"
            path = root / "benchmark.json"
            path.write_text(json.dumps(manifest))
            report = evaluate_benchmark(path)
            self.assertTrue(report["valid"])
            self.assertTrue(
                report["release_gates"]["closed_beta"]["precision_thresholds_met"]
            )
            self.assertFalse(
                report["suite_qualification"]["checks"][
                    "actionable_high_critical_evidence"
                ]
            )
            self.assertFalse(report["release_gates"]["closed_beta"]["passed"])

    def test_incomplete_cost_accounting_blocks_suite_qualification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.qualified_manifest(root)
            manifest["trials"][0]["cost_accounting_complete"] = False
            path = root / "benchmark.json"
            path.write_text(json.dumps(manifest))
            report = evaluate_benchmark(path)
            self.assertTrue(report["valid"])
            self.assertFalse(
                report["suite_qualification"]["checks"][
                    "complete_trial_cost_accounting"
                ]
            )
            self.assertFalse(report["release_gates"]["closed_beta"]["passed"])

    def test_case_pack_reference_hash_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.qualified_manifest(root)
            manifest["case_pack"]["sha256"] = "0" * 64
            path = root / "benchmark.json"
            path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "reference hash mismatch"):
                evaluate_benchmark(path)


if __name__ == "__main__":
    unittest.main()
