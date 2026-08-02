import json
import tempfile
import unittest
from pathlib import Path

from nirvana.benchmark_pack import (
    GROUND_TRUTH_COMMITMENT_ALGORITHM,
    TARGET_SNAPSHOT_ALGORITHM,
    benchmark_target_snapshot,
    canonical_ground_truth_document,
    write_ground_truth_commitment,
)
from nirvana.benchmark_ledger import (
    BENCHMARK_LEDGER_BINDING_ALGORITHM,
    seal_benchmark_trial,
)
from nirvana.evaluation import evaluate_benchmark
from nirvana.ledger import EvidenceLedger
from nirvana.models import EVIDENCE_RANK, EvidenceLevel
from nirvana.util import sha256_file


class EvaluationTests(unittest.TestCase):
    def bind_trial(self, root: Path, trial: dict) -> None:
        run_directory = root / "runs" / trial["run_id"]
        run_directory.mkdir(parents=True, exist_ok=True)
        ledger = EvidenceLedger(run_directory / "evidence.jsonl")
        levels = [
            EvidenceLevel(finding["evidence_level"])
            for finding in trial["findings"]
        ]
        ceiling = max(
            levels,
            key=lambda item: EVIDENCE_RANK[item],
            default=EvidenceLevel.HYPOTHESIS,
        )
        captured_scope = {
            "schema_version": "2.0.0",
            "created_at": "2025-02-01T00:00:00Z",
            "target_root": str(root),
            "repository_commit": None,
            "repository_dirty": False,
            "target_snapshot_sha256": "a" * 64,
            "snapshot_complete": True,
            "max_analysis_file_bytes": 5000000,
            "files": [],
            "excluded_directories": [".git"],
            "toolchains": [],
            "frameworks": [],
            "languages": {},
            "untrusted_instruction_surfaces": [],
            "build_status": "not_detected",
            "test_status": "not_detected",
            "evidence_ceiling": "hypothesis",
            "dependency_manifests": [],
            "discovered_artifacts": [],
            "privileged_identities": [],
            "upgrade_mechanisms": [],
            "external_dependencies": [],
            "build_plan": [],
            "test_plan": [],
            "deployment_matches": [],
            "declared_tool_versions": {},
            "submodules": [],
            "warnings": [],
        }
        ledger.append({"event": "scope_captured", "scope": captured_scope})

        finding_payloads = []
        for finding in trial["findings"]:
            suffix = finding["finding_id"].removeprefix("F-")
            evidence_id = f"E-{suffix}"
            level = EvidenceLevel(finding["evidence_level"])
            evidence_record = {
                "evidence_id": evidence_id,
                "hypothesis_id": f"H-{suffix}",
                "level": level.value,
                "kind": "benchmark-fixture",
                "summary": "replay-verified benchmark fixture evidence",
                "source": "nirvana:command-runner",
                "artifact_path": str(run_directory / f"{evidence_id}.json"),
                "artifact_sha256": "b" * 64,
                "command": (
                    ["fixture-verifier"]
                    if EVIDENCE_RANK[level]
                    >= EVIDENCE_RANK[EvidenceLevel.EXECUTABLE]
                    else []
                ),
                "tool_version": "fixture-1",
                "assumptions": [],
                "metadata": {
                    "runner_minted": True,
                    "negative_control_verified": True,
                },
                "created_at": "2025-02-01T00:01:00Z",
            }
            ledger.append(
                {
                    "event": "evidence_recorded",
                    "evidence": evidence_record,
                    "minted_by": "nirvana:command-runner",
                }
            )
            ledger.append(
                {
                    "event": "evidence_verified",
                    "evidence_id": evidence_id,
                }
            )
            finding_payloads.append(
                {
                    "event": "finding_confirmed",
                    "finding": {
                        "finding_id": finding["finding_id"],
                        "hypothesis_id": f"H-{suffix}",
                        "title": "Benchmark fixture finding",
                        "severity": finding["severity"],
                        "evidence_level": level.value,
                        "security_property": "fixture property",
                        "root_cause": "fixture root cause",
                        "locations": [{"path": "Fixture.sol", "line_start": 1}],
                        "attacker_prerequisites": ["fixture access"],
                        "assumptions": [],
                        "causal_path": ["fixture-node"],
                        "reproducer": "fixture reproducer",
                        "impact": "fixture impact",
                        "severity_rationale": "fixture severity rationale",
                        "reproduction_instructions": ["run fixture verifier"],
                        "remediation": "fix the fixture",
                        "regression_test": "run fixture regression",
                        "supporting_evidence": [evidence_id],
                        "reproducer_evidence_id": (
                            evidence_id
                            if EVIDENCE_RANK[level]
                            >= EVIDENCE_RANK[EvidenceLevel.EXECUTABLE]
                            else None
                        ),
                        "regression_evidence_id": (
                            evidence_id
                            if EVIDENCE_RANK[level]
                            >= EVIDENCE_RANK[EvidenceLevel.EXECUTABLE]
                            else None
                        ),
                        "novelty": "uncertain_novelty",
                        "related_issues": [],
                    },
                }
            )

        if ceiling is not EvidenceLevel.HYPOTHESIS:
            ledger.append(
                {
                    "event": "evidence_ceiling_raised",
                    "previous": "hypothesis",
                    "current": ceiling.value,
                    "basis": [
                        payload["finding"]["supporting_evidence"][0]
                        for payload in finding_payloads
                    ],
                }
            )
        ledger.append_many(finding_payloads)
        ledger.append(
            {
                "event": "run_completed",
                "confirmed_findings": len(finding_payloads),
                "hypotheses": len(finding_payloads),
            }
        )
        projected_scope = json.loads(json.dumps(captured_scope))
        projected_scope["evidence_ceiling"] = ceiling.value
        (run_directory / "scope.json").write_text(json.dumps(projected_scope))
        checkpoint = run_directory / "ledger-checkpoint.json"
        sealed = seal_benchmark_trial(
            run_directory,
            trial_id=trial["trial_id"],
            case_id=trial["case_id"],
            seed=trial["seed"],
            output=checkpoint,
        )
        trial["ledger_checkpoint"] = {
            "algorithm": BENCHMARK_LEDGER_BINDING_ALGORITHM,
            "run_directory": run_directory.relative_to(root).as_posix(),
            "checkpoint_path": checkpoint.relative_to(root).as_posix(),
            "checkpoint_sha256": sealed["checkpoint_sha256"],
        }

    def manifest(self, root: Path) -> dict:
        trial = {
            "trial_id": "T-1",
            "case_id": "CASE-1",
            "run_id": "RUN-1",
            "seed": 1,
            "started_at": "2025-02-01T00:00:00Z",
            "ended_at": "2025-02-01T00:10:00Z",
            "model": "agent-model-version",
            "prompt_sha256": "1" * 64,
            "tools": ["nirvana-0.4.6", "forge-1"],
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
        self.bind_trial(root, trial)
        self.bind_trial(root, second)
        release_artifacts = []
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
            "schema_version": "1.1.0",
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
            ground_truth = (
                [{"vulnerability_id": vulnerability_id, "severity": "high"}]
                if vulnerable
                else []
            )
            originated_at = "2025-01-15T00:00:00Z"
            target = root / "case-pack-assets" / case_id / "target"
            target.mkdir(parents=True)
            (target / "Fixture.sol").write_text(
                f"contract Fixture{index} {{ function value() external pure returns (uint) {{ return {index}; }} }}\n"
            )
            reveal = target.parent / "ground-truth.json"
            reveal.write_text(
                json.dumps(
                    canonical_ground_truth_document(
                        case_id,
                        True,
                        ground_truth,
                    )
                )
            )
            commitment = target.parent / "commitment.json"
            commitment_record = write_ground_truth_commitment(reveal, commitment)
            reveal.unlink()
            sealed = target.parent / "ground-truth.age"
            sealed.write_text(
                f"age-encryption.org/v1\nfixture-ciphertext-{case_id}\n"
            )
            pack_cases.append(
                {
                    "case_id": case_id,
                    "originated_at": originated_at,
                    "target_path": target.relative_to(root).as_posix(),
                    "target_snapshot_sha256": benchmark_target_snapshot(target)[
                        "target_snapshot_sha256"
                    ],
                    "public_commitment_path": commitment.relative_to(root).as_posix(),
                    "public_commitment_artifact_sha256": sha256_file(commitment),
                    "public_commitment_sha256": commitment_record[
                        "public_commitment_sha256"
                    ],
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
                    "ground_truth": ground_truth,
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
                        "tools": ["nirvana-0.4.6", "forge-1"],
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
            "schema_version": "1.1.0",
            "pack_id": "independent-qualified-pack-1",
            "cutoff": manifest["cutoff"],
            "created_at": "2025-01-20T00:00:00Z",
            "target_snapshot_algorithm": TARGET_SNAPSHOT_ALGORITHM,
            "ground_truth_commitment_algorithm": GROUND_TRUTH_COMMITMENT_ALGORITHM,
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
        for trial in trials:
            self.bind_trial(root, trial)
        return manifest

    def test_all_pdf_metrics_and_temporal_release_gate_are_computed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "benchmark.json"
            path.write_text(json.dumps(self.manifest(Path(directory))))
            report = evaluate_benchmark(path)
            self.assertTrue(report["valid"])
            self.assertEqual(report["schema_version"], "1.5.0")
            self.assertEqual(report["invalid_reasons"], [])
            self.assertTrue(report["temporal_validation"]["valid"])
            self.assertIsNone(report["ground_truth_validation"]["valid"])
            self.assertTrue(report["finding_attribution_validation"]["valid"])
            self.assertTrue(report["ledger_validation"]["valid"])
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
            self.assertTrue(report["ground_truth_validation"]["valid"])
            self.assertEqual(
                report["ground_truth_validation"]["matched_case_count"], 30
            )
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

    def test_claimed_evidence_tier_must_match_checkpointed_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.qualified_manifest(root)
            manifest["trials"][0]["findings"][0]["evidence_level"] = "localised"
            path = root / "benchmark.json"
            path.write_text(json.dumps(manifest))
            report = evaluate_benchmark(path)
            self.assertFalse(report["valid"])
            self.assertFalse(report["ledger_validation"]["valid"])
            self.assertIn(
                "evidence level does not match",
                " ".join(report["invalid_reasons"]),
            )
            self.assertIsNone(report["metrics"])
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

    def test_vulnerable_case_cannot_be_reclassified_as_benign_after_reveal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.qualified_manifest(root)
            manifest["cases"][0]["ground_truth"] = []
            path = root / "benchmark.json"
            path.write_text(json.dumps(manifest))
            report = evaluate_benchmark(path)
            self.assertFalse(report["valid"])
            self.assertIsNone(report["metrics"])
            self.assertIsNone(report["magma"])
            self.assertEqual(
                report["ground_truth_validation"]["mismatched_case_ids"],
                ["CASE-001"],
            )
            self.assertIn(
                "revealed ground truth does not match",
                " ".join(report["invalid_reasons"]),
            )
            self.assertTrue(
                all(not gate["passed"] for gate in report["release_gates"].values())
            )

    def test_benign_case_cannot_be_reclassified_as_vulnerable_after_reveal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.qualified_manifest(root)
            manifest["cases"][20]["ground_truth"] = [
                {"vulnerability_id": "INVENTED", "severity": "high"}
            ]
            path = root / "benchmark.json"
            path.write_text(json.dumps(manifest))
            report = evaluate_benchmark(path)
            self.assertFalse(report["valid"])
            self.assertEqual(
                report["ground_truth_validation"]["mismatched_case_ids"],
                ["CASE-021"],
            )

    def test_revealed_vulnerability_labels_cannot_change_after_commitment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.qualified_manifest(root)
            manifest["cases"][0]["ground_truth"][0]["severity"] = "critical"
            path = root / "benchmark.json"
            path.write_text(json.dumps(manifest))
            report = evaluate_benchmark(path)
            self.assertFalse(report["valid"])
            self.assertEqual(
                report["ground_truth_validation"]["mismatched_case_ids"],
                ["CASE-001"],
            )

    def test_case_eligibility_cannot_change_after_commitment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.qualified_manifest(root)
            manifest["cases"][0]["eligible"] = False
            path = root / "benchmark.json"
            path.write_text(json.dumps(manifest))
            report = evaluate_benchmark(path)
            self.assertFalse(report["valid"])
            self.assertEqual(
                report["ground_truth_validation"]["mismatched_case_ids"],
                ["CASE-001"],
            )

    def test_true_positive_requires_a_ground_truth_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.manifest(root)
            manifest["trials"][0]["findings"][0]["ground_truth_id"] = None
            path = root / "benchmark.json"
            path.write_text(json.dumps(manifest))
            report = evaluate_benchmark(path)
            self.assertFalse(report["valid"])
            self.assertFalse(report["finding_attribution_validation"]["valid"])
            self.assertIn("lacks a ground_truth_id", " ".join(report["invalid_reasons"]))
            self.assertIsNone(report["metrics"])
            self.assertIsNone(report["magma"])

    def test_true_positive_cannot_name_uncommitted_ground_truth(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.manifest(root)
            manifest["trials"][0]["findings"][0]["ground_truth_id"] = "V99"
            path = root / "benchmark.json"
            path.write_text(json.dumps(manifest))
            report = evaluate_benchmark(path)
            self.assertFalse(report["valid"])
            self.assertEqual(
                report["finding_attribution_validation"]["invalid_findings"][0][
                    "ground_truth_id"
                ],
                "V99",
            )
            self.assertIn(
                "attributes to unknown ground truth V99",
                " ".join(report["invalid_reasons"]),
            )

    def test_every_non_null_ground_truth_id_must_match_the_case(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.manifest(root)
            finding = manifest["trials"][0]["findings"][0]
            finding["verdict"] = "false_positive"
            finding["ground_truth_id"] = "V99"
            path = root / "benchmark.json"
            path.write_text(json.dumps(manifest))
            report = evaluate_benchmark(path)
            self.assertFalse(report["valid"])
            self.assertFalse(report["finding_attribution_validation"]["valid"])

    def test_run_id_must_name_the_checkpointed_run_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.manifest(root)
            manifest["trials"][0]["run_id"] = "FREE-STRING"
            path = root / "benchmark.json"
            path.write_text(json.dumps(manifest))
            report = evaluate_benchmark(path)
            self.assertFalse(report["valid"])
            self.assertIn(
                "does not match run directory",
                " ".join(report["ledger_validation"]["violations"]),
            )

    def test_trial_identity_must_match_the_checkpointed_seal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.manifest(root)
            manifest["trials"][0]["trial_id"] = "T-REWRITTEN"
            path = root / "benchmark.json"
            path.write_text(json.dumps(manifest))
            report = evaluate_benchmark(path)
            self.assertFalse(report["valid"])
            self.assertIn(
                "identity does not match its checkpointed trial seal",
                " ".join(report["ledger_validation"]["violations"]),
            )

    def test_manifest_cannot_invent_a_finding_absent_from_the_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.manifest(root)
            invented = json.loads(
                json.dumps(manifest["trials"][0]["findings"][0])
            )
            invented["finding_id"] = "F-INVENTED"
            manifest["trials"][0]["findings"].append(invented)
            path = root / "benchmark.json"
            path.write_text(json.dumps(manifest))
            report = evaluate_benchmark(path)
            self.assertFalse(report["valid"])
            self.assertIn(
                "finding F-INVENTED is not confirmed",
                " ".join(report["ledger_validation"]["violations"]),
            )

    def test_manifest_cannot_omit_a_checkpointed_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.manifest(root)
            manifest["trials"][0]["findings"] = []
            path = root / "benchmark.json"
            path.write_text(json.dumps(manifest))
            report = evaluate_benchmark(path)
            self.assertFalse(report["valid"])
            self.assertIn(
                "omits checkpointed finding F-1",
                " ".join(report["ledger_validation"]["violations"]),
            )

    def test_checkpoint_requires_evidence_to_remain_replay_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.manifest(root)
            trial = manifest["trials"][0]
            binding = trial["ledger_checkpoint"]
            run_directory = root / binding["run_directory"]
            ledger = EvidenceLedger(run_directory / "evidence.jsonl")
            ledger.append(
                {"event": "evidence_replay_failed", "evidence_id": "E-1"}
            )
            path = root / "benchmark.json"
            path.write_text(json.dumps(manifest))
            report = evaluate_benchmark(path)
            self.assertFalse(report["valid"])
            self.assertIn(
                "evidence invalidated in the later ledger",
                " ".join(report["ledger_validation"]["violations"]),
            )

    def test_trial_binding_rejects_path_traversal_as_report_invalidity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.manifest(root)
            manifest["trials"][0]["ledger_checkpoint"]["run_directory"] = (
                "../outside"
            )
            path = root / "benchmark.json"
            path.write_text(json.dumps(manifest))
            report = evaluate_benchmark(path)
            self.assertFalse(report["valid"])
            self.assertIn(
                "must stay inside the benchmark directory",
                " ".join(report["ledger_validation"]["violations"]),
            )


if __name__ == "__main__":
    unittest.main()
