from __future__ import annotations

import json
import math
import stat
import statistics
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from .benchmark_pack import (
    GROUND_TRUTH_COMMITMENT_ALGORITHM,
    canonical_ground_truth_document,
    ground_truth_commitment_sha256,
    resolve_case_pack_reference,
    verify_case_pack,
)
from .benchmark_ledger import validate_trial_ledger_bindings
from .contracts import validate_contract
from .models import EvidenceLevel, Severity
from .util import atomic_write_json, sha256_file, utc_now


MINIMUM_VULNERABLE_CASES = 20
MINIMUM_BENIGN_CONTROLS = 10
MINIMUM_DISTINCT_SEEDS_PER_CASE = 3


def evaluate_benchmark(manifest_path: Path) -> dict[str, Any]:
    resolved = manifest_path.resolve(strict=True)
    if resolved.stat().st_size > 256 * 1024 * 1024:
        raise ValueError("benchmark manifest exceeds the 256 MB import limit")
    manifest = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("benchmark manifest must be one JSON object")
    validate_contract(manifest, "benchmark-manifest.schema.json")
    _validate_manifest_shapes(manifest)
    temporal = _validate_temporal_split(manifest)
    cases = {str(item["case_id"]): item for item in manifest["cases"]}
    trials = list(manifest["trials"])
    case_pack = _verified_case_pack(manifest, resolved)
    ground_truth_validation = _validate_revealed_ground_truth(
        manifest, cases, case_pack
    )
    finding_attribution_validation = _validate_finding_attribution(cases, trials)
    ledger_validation = validate_trial_ledger_bindings(resolved, trials)
    invalid_reasons = [
        *temporal["violations"],
        *ground_truth_validation["violations"],
        *finding_attribution_validation["violations"],
        *ledger_validation["violations"],
    ]
    evaluation_valid = not invalid_reasons
    derived_finding_states = {
        (str(result["trial_id"]), str(finding["finding_id"])): finding
        for result in ledger_validation["trials"]
        for finding in result["derived_findings"]
    }
    findings: list[dict[str, Any]] = []
    for trial in trials:
        for finding in trial["findings"]:
            item = {
                **finding,
                "trial_id": trial["trial_id"],
                "case_id": trial["case_id"],
            }
            derived = derived_finding_states.get(
                (str(trial["trial_id"]), str(finding["finding_id"]))
            )
            if derived is not None:
                item["reproduced"] = derived["reproduced"]
                item["patch_tests_passed"] = derived["patch_tests_passed"]
            findings.append(item)
    eligible_ground_truth = {
        (case_id, str(vulnerability["vulnerability_id"]))
        for case_id, case in cases.items()
        if case["eligible"]
        for vulnerability in case["ground_truth"]
    }
    all_ground_truth = {
        (case_id, str(vulnerability["vulnerability_id"]))
        for case_id, case in cases.items()
        for vulnerability in case["ground_truth"]
    }
    detected_ground_truth = {
        (str(item["case_id"]), str(item["ground_truth_id"]))
        for item in findings
        if item["verdict"] == "true_positive" and item.get("ground_truth_id") is not None
    } & eligible_ground_truth
    reported = [
        item
        for item in findings
        if item["verdict"] in {"true_positive", "false_positive"}
    ]
    true_reports = [
        item
        for item in reported
        if item["verdict"] == "true_positive"
        and item.get("ground_truth_id") is not None
        and (
            str(item["case_id"]),
            str(item["ground_truth_id"]),
        )
        in all_ground_truth
    ]
    high_reports = [item for item in reported if item["severity"] in {"high", "critical"}]
    true_report_keys = {
        (str(item["trial_id"]), str(item["finding_id"])) for item in true_reports
    }
    high_true = [
        item
        for item in high_reports
        if (str(item["trial_id"]), str(item["finding_id"])) in true_report_keys
    ]
    confirmed = [
        item
        for item in true_reports
        if _evidence_rank(item["evidence_level"])
        >= _evidence_rank(EvidenceLevel.STRUCTURALLY_CONFIRMED.value)
    ]
    novel_confirmed = [item for item in confirmed if item.get("novel") is True]
    kloc_is_committed = bool(
        case_pack is not None and ground_truth_validation["kloc_valid"] is True
    )
    total_kloc = (
        sum(float(case["kloc"]) for case in cases.values() if case["eligible"])
        if kloc_is_committed
        else None
    )
    total_compute = sum(float(item["compute_hours"]) for item in trials)
    total_model_cost = sum(float(item["model_cost"]) for item in trials)
    reproduced = [item for item in confirmed if item.get("reproduced") is True]
    duplicates = [item for item in reported if item.get("duplicate") is True]
    patchable = [item for item in true_reports if item.get("patch_tests_passed") is not None]
    patch_correct = [item for item in patchable if item["patch_tests_passed"] is True]
    confidence_items = [
        item for item in reported if isinstance(item.get("confidence"), (int, float))
    ]
    first_times = [
        float(item["time_to_finding_seconds"])
        for item in true_reports
        if item.get("time_to_finding_seconds") is not None
    ]
    evidence_counts = Counter(item["evidence_level"] for item in reported)
    coverage_dimensions = ("assets", "authority_paths", "state_transitions", "trust_boundaries")
    coverage = {
        dimension: _mean(
            float(trial["coverage"][dimension])
            for trial in trials
            if dimension in trial["coverage"]
        )
        for dimension in coverage_dimensions
    }
    stability = _stability(trials)
    metrics = {
        "validated_precision": _ratio(len(true_reports), len(reported)),
        "ground_truth_recall": _ratio(len(detected_ground_truth), len(eligible_ground_truth)),
        "high_severity_precision": _ratio(len(high_true), len(high_reports)),
        "novel_validated_yield": {
            "total": len(novel_confirmed),
            "per_project": _ratio(len(novel_confirmed), len(cases)),
            "per_kloc": (
                _ratio(len(novel_confirmed), total_kloc)
                if total_kloc is not None
                else None
            ),
            "per_compute_hour": _ratio(len(novel_confirmed), total_compute),
            "per_model_cost_unit": _ratio(len(novel_confirmed), total_model_cost),
        },
        "time_to_first_valid_finding_seconds": min(first_times) if first_times else None,
        "evidence_level_distribution": {
            level.value: _ratio(evidence_counts[level.value], len(reported))
            for level in EvidenceLevel
        },
        "reproduction_rate": _ratio(len(reproduced), len(confirmed)),
        "coverage_completeness": {
            **coverage,
            "mean": _mean(value for value in coverage.values() if value is not None),
        },
        "duplicate_rate": _ratio(len(duplicates), len(reported)),
        "calibration": {
            "brier_score": _mean(
                (float(item["confidence"]) - (1.0 if item["verdict"] == "true_positive" else 0.0)) ** 2
                for item in confidence_items
            ),
            "sample_count": len(confidence_items),
        },
        "patch_correctness": _ratio(len(patch_correct), len(patchable)),
        "cost_efficiency": {
            "compute_hours_per_confirmed_finding": _ratio(total_compute, len(confirmed)),
            "model_cost_per_confirmed_finding": _ratio(total_model_cost, len(confirmed)),
        },
        "stability": stability,
    }
    magma = _magma_metrics(trials, eligible_ground_truth)
    precision = metrics["validated_precision"]
    high_precision = metrics["high_severity_precision"]
    release_evidence = _release_evidence(manifest.get("release_evidence", {}))
    precision_thresholds_met = (
        evaluation_valid
        and precision is not None
        and precision >= 0.80
        and high_precision is not None
        and high_precision >= 0.90
    )
    suite_qualification = _suite_qualification(
        manifest,
        cases,
        trials,
        high_reports,
        temporal,
        case_pack,
        ground_truth_validation,
        finding_attribution_validation,
        ledger_validation,
        evaluation_valid,
    )
    closed_beta = precision_thresholds_met and suite_qualification["qualified"]
    research_prototype = all(
        (
            release_evidence["reproducible_builds"],
            {"evm", "rust-native"} <= set(release_evidence["ssg_dialects"]),
            release_evidence["deterministic_baseline"],
            release_evidence["typed_hypotheses"],
            release_evidence["executable_evidence_ledger"],
            _has_release_artifact(release_evidence, "research_prototype"),
        )
    )
    ecosystem_adapters = release_evidence["dynamic_verifiers_per_ecosystem"]
    web3_alpha = (
        all(ecosystem_adapters.get(item, 0) >= 2 for item in ("evm", "solana", "move-sui"))
        and len(high_reports) - len(high_true) == 0
        and _has_release_artifact(release_evidence, "web3_alpha")
    )
    deterministic_recall = release_evidence["deterministic_baseline_recall"]
    production_candidate = bool(
        closed_beta
        and metrics["ground_truth_recall"] is not None
        and deterministic_recall is not None
        and metrics["ground_truth_recall"] > deterministic_recall
        and stability["mean_pairwise_jaccard"] is not None
        and stability["mean_pairwise_jaccard"] >= 0.80
        and metrics["reproduction_rate"] is not None
        and metrics["reproduction_rate"] >= 0.90
        and metrics["cost_efficiency"]["compute_hours_per_confirmed_finding"] is not None
        and metrics["cost_efficiency"]["model_cost_per_confirmed_finding"] is not None
        and release_evidence["auditable_cost_controls"]
        and _has_release_artifact(release_evidence, "production_candidate")
    )
    adapter_conformance = release_evidence["adapter_conformance"]
    universal_expansion = bool(adapter_conformance) and all(
        item["semantic_conformance"]
        and item["negative_cases"]
        and item["runtime_verification"]
        for item in adapter_conformance
    ) and _has_release_artifact(release_evidence, "universal_expansion")
    release_gates = {
        "research_prototype": {
            "passed": research_prototype,
            "requirements": "reproducible builds, Solidity and Rust SSGs, deterministic baseline, typed hypotheses, and executable evidence ledger",
            "evidence": release_evidence,
        },
        "web3_alpha": {
            "passed": web3_alpha,
            "requirements": "EVM, Solana, and Sui adapters with at least two dynamic verifiers per ecosystem and no unactionable high-severity reports",
            "unactionable_high_severity_reports": len(high_reports) - len(high_true),
        },
        "closed_beta": {
            "passed": closed_beta,
            "precision_thresholds_met": precision_thresholds_met,
            "suite_qualified": suite_qualification["qualified"],
            "overall_precision_target": 0.80,
            "high_critical_precision_target": 0.90,
            "blind_temporal_suite_required": True,
            "recall_reported": metrics["ground_truth_recall"] is not None,
            "qualification_version": suite_qualification["qualification_version"],
            "qualification_reasons": list(suite_qualification["reasons"]),
        },
        "production_candidate": {
            "passed": production_candidate,
            "requirements": "stable precision, recall above a recorded deterministic baseline, at least 90% independent reproduction, and auditable cost controls",
            "deterministic_baseline_recall": deterministic_recall,
            "minimum_stability_jaccard": 0.80,
            "minimum_reproduction_rate": 0.90,
        },
        "universal_expansion": {
            "passed": universal_expansion,
            "requirements": "every new adapter passes semantic conformance, negative-case, and runtime-verification suites",
            "adapter_conformance": adapter_conformance,
        },
    }
    if not evaluation_valid:
        for gate in release_gates.values():
            gate["passed"] = False
    warnings: list[str] = []
    if not evaluation_valid:
        warnings.extend(invalid_reasons)
        warnings.insert(
            0,
            "benchmark report is invalid; metrics and Magma results were suppressed",
        )
    if metrics["ground_truth_recall"] is None:
        warnings.append("ground-truth recall is undefined because no eligible vulnerabilities were supplied")
    if not high_reports:
        warnings.append("high-severity precision is undefined because no high/critical reports were emitted")
    if evaluation_valid and not kloc_is_committed:
        warnings.append(
            "per-KLOC yield is undefined because no independently committed case "
            "sizes were supplied"
        )
    if evaluation_valid and precision_thresholds_met and not suite_qualification["qualified"]:
        warnings.append(
            "closed-beta precision thresholds were met, but the benchmark suite is not operationally qualified"
        )
    report = {
        "schema_version": "1.6.0",
        "created_at": utc_now(),
        "benchmark_id": manifest["benchmark_id"],
        "manifest_sha256": sha256_file(resolved),
        "track": manifest["track"],
        "valid": evaluation_valid,
        "temporal_validation": temporal,
        "ground_truth_validation": ground_truth_validation,
        "finding_attribution_validation": finding_attribution_validation,
        "ledger_validation": ledger_validation,
        "invalid_reasons": invalid_reasons,
        "counts": {
            "cases": len(cases),
            "trials": len(trials),
            "eligible_ground_truth": len(eligible_ground_truth),
            "reported_findings": len(reported),
            "suppressed_findings": sum(
                item["verdict"] == "suppressed" for item in findings
            ),
            "true_reports": len(true_reports),
            "confirmed_true_reports": len(confirmed),
            "ledger_bound_findings": ledger_validation["matched_finding_count"],
            "committed_kloc_cases": ground_truth_validation[
                "matched_kloc_case_count"
            ],
        },
        "metrics": metrics if evaluation_valid else None,
        "magma": magma if evaluation_valid else None,
        "suite_qualification": suite_qualification,
        "release_gates": release_gates,
        "warnings": warnings,
    }
    validate_contract(report, "benchmark-report.schema.json")
    return report


def write_benchmark_report(manifest_path: Path, output: Path) -> dict[str, Any]:
    report = evaluate_benchmark(manifest_path)
    atomic_write_json(output.resolve(), report)
    return report


def _validate_manifest_shapes(manifest: dict[str, Any]) -> None:
    case_ids: set[str] = set()
    for case in manifest["cases"]:
        required = {
            "case_id",
            "repository",
            "last_vulnerable_commit",
            "originated_at",
            "disclosed_at",
            "eligible",
            "hidden_variant",
            "transformation_log_sha256",
            "kloc",
            "ground_truth",
            "ground_truth_material_blocked",
            "eventual_fix_accessed",
        }
        missing = required - case.keys()
        if missing:
            raise ValueError(f"benchmark case lacks required fields: {sorted(missing)}")
        case_id = str(case["case_id"])
        if case_id in case_ids:
            raise ValueError(f"duplicate benchmark case: {case_id}")
        case_ids.add(case_id)
        if not isinstance(case["ground_truth"], list):
            raise ValueError("benchmark ground_truth must be an array")
        if not isinstance(case["eligible"], bool):
            raise ValueError("benchmark case eligible must be boolean")
        vulnerability_ids: set[str] = set()
        for vulnerability in case["ground_truth"]:
            if {"vulnerability_id", "severity"} - vulnerability.keys():
                raise ValueError("ground-truth vulnerabilities require id and severity")
            vulnerability_id = vulnerability["vulnerability_id"]
            if not isinstance(vulnerability_id, str) or not vulnerability_id:
                raise ValueError(
                    "ground-truth vulnerability ids must be non-empty strings"
                )
            if vulnerability_id in vulnerability_ids:
                raise ValueError(
                    f"duplicate ground-truth vulnerability id in case {case_id}: "
                    f"{vulnerability_id}"
                )
            vulnerability_ids.add(vulnerability_id)
            Severity(vulnerability["severity"])
        if not isinstance(case["kloc"], (int, float)) or isinstance(case["kloc"], bool) or case["kloc"] < 0:
            raise ValueError("benchmark case kloc must be a non-negative number")
    trial_ids: set[str] = set()
    run_ids: set[str] = set()
    for trial in manifest["trials"]:
        required = {
            "trial_id", "case_id", "run_id", "seed", "started_at", "ended_at",
            "model", "prompt_sha256", "tools", "token_budget", "compute_hours",
            "model_cost", "transcript_sha256", "environment_sha256", "findings",
            "coverage", "reached_ids", "triggered_ids", "detected_ids",
            "ledger_checkpoint",
        }
        missing = required - trial.keys()
        if missing:
            raise ValueError(f"benchmark trial lacks required fields: {sorted(missing)}")
        if trial["case_id"] not in case_ids:
            raise ValueError(f"benchmark trial references unknown case: {trial['case_id']}")
        if trial["trial_id"] in trial_ids:
            raise ValueError(f"duplicate benchmark trial: {trial['trial_id']}")
        trial_ids.add(trial["trial_id"])
        if not isinstance(trial["run_id"], str) or not trial["run_id"]:
            raise ValueError("benchmark trial run_id must be a non-empty string")
        if trial["run_id"] in run_ids:
            raise ValueError(f"duplicate benchmark run id: {trial['run_id']}")
        run_ids.add(trial["run_id"])
        binding = trial["ledger_checkpoint"]
        required_binding = {
            "algorithm",
            "run_directory",
            "checkpoint_path",
            "checkpoint_sha256",
        }
        if not isinstance(binding, dict) or set(binding) != required_binding:
            raise ValueError(
                "benchmark trial ledger_checkpoint requires only algorithm, "
                "run_directory, checkpoint_path, and checkpoint_sha256"
            )
        if not isinstance(trial["tools"], list) or not trial["tools"]:
            raise ValueError("benchmark trial tools must be a non-empty array")
        if not isinstance(trial["token_budget"], int) or isinstance(trial["token_budget"], bool) or trial["token_budget"] < 0:
            raise ValueError("benchmark token_budget must be a non-negative integer")
        tokens_used = trial.get("tokens_used")
        if tokens_used is not None and (
            not isinstance(tokens_used, int)
            or isinstance(tokens_used, bool)
            or tokens_used < 0
        ):
            raise ValueError("benchmark tokens_used must be a non-negative integer")
        if "cost_accounting_complete" in trial and not isinstance(
            trial["cost_accounting_complete"], bool
        ):
            raise ValueError("benchmark cost_accounting_complete must be boolean")
        for field in ("compute_hours", "model_cost"):
            if not isinstance(trial[field], (int, float)) or isinstance(trial[field], bool) or trial[field] < 0:
                raise ValueError(f"benchmark {field} must be a non-negative number")
        finding_ids: set[str] = set()
        for finding in trial["findings"]:
            required_finding = {
                "finding_id", "verdict", "severity", "evidence_level", "confidence",
                "ground_truth_id", "reproduced", "duplicate", "novel",
                "time_to_finding_seconds", "patch_tests_passed",
            }
            missing_finding = required_finding - finding.keys()
            if missing_finding:
                raise ValueError(f"benchmark finding lacks required fields: {sorted(missing_finding)}")
            if finding["verdict"] not in {"true_positive", "false_positive", "suppressed"}:
                raise ValueError("benchmark finding verdict is invalid")
            if not isinstance(finding["finding_id"], str) or not finding["finding_id"]:
                raise ValueError("benchmark finding_id must be a non-empty string")
            if finding["finding_id"] in finding_ids:
                raise ValueError(
                    f"duplicate benchmark finding in trial {trial['trial_id']}: "
                    f"{finding['finding_id']}"
                )
            finding_ids.add(finding["finding_id"])
            ground_truth_id = finding["ground_truth_id"]
            if ground_truth_id is not None and (
                not isinstance(ground_truth_id, str) or not ground_truth_id
            ):
                raise ValueError(
                    "benchmark ground_truth_id must be null or a non-empty string"
                )
            Severity(finding["severity"])
            EvidenceLevel(finding["evidence_level"])
            if not isinstance(finding["reproduced"], bool):
                raise ValueError("benchmark finding reproduced must be boolean")
            if finding["patch_tests_passed"] is not None and not isinstance(
                finding["patch_tests_passed"], bool
            ):
                raise ValueError(
                    "benchmark finding patch_tests_passed must be boolean or null"
                )
            confidence = finding["confidence"]
            if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1:
                raise ValueError("benchmark finding confidence must be between zero and one")


def _release_evidence(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("benchmark release_evidence must be an object")
    allowed = {
        "reproducible_builds",
        "ssg_dialects",
        "deterministic_baseline",
        "typed_hypotheses",
        "executable_evidence_ledger",
        "dynamic_verifiers_per_ecosystem",
        "deterministic_baseline_recall",
        "auditable_cost_controls",
        "adapter_conformance",
        "evidence_artifacts",
    }
    unknown = value.keys() - allowed
    if unknown:
        raise ValueError(f"benchmark release_evidence has unknown fields: {sorted(unknown)}")
    booleans = (
        "reproducible_builds",
        "deterministic_baseline",
        "typed_hypotheses",
        "executable_evidence_ledger",
        "auditable_cost_controls",
    )
    for field in booleans:
        if field in value and not isinstance(value[field], bool):
            raise ValueError(f"benchmark release_evidence {field} must be boolean")
    dialects = value.get("ssg_dialects", [])
    if not isinstance(dialects, list) or any(not isinstance(item, str) for item in dialects):
        raise ValueError("benchmark release_evidence ssg_dialects must be a string array")
    adapters = value.get("dynamic_verifiers_per_ecosystem", {})
    if not isinstance(adapters, dict) or any(
        not isinstance(name, str)
        or not isinstance(count, int)
        or isinstance(count, bool)
        or count < 0
        for name, count in adapters.items()
    ):
        raise ValueError("dynamic_verifiers_per_ecosystem must map names to non-negative integers")
    baseline_recall = value.get("deterministic_baseline_recall")
    if baseline_recall is not None and (
        not isinstance(baseline_recall, (int, float))
        or isinstance(baseline_recall, bool)
        or not 0 <= baseline_recall <= 1
    ):
        raise ValueError("deterministic_baseline_recall must be null or between zero and one")
    conformance = value.get("adapter_conformance", [])
    if not isinstance(conformance, list):
        raise ValueError("adapter_conformance must be an array")
    normalized_conformance: list[dict[str, Any]] = []
    for item in conformance:
        required = {"dialect", "semantic_conformance", "negative_cases", "runtime_verification"}
        if not isinstance(item, dict) or set(item) != required:
            raise ValueError("adapter conformance entries require dialect and three gate booleans")
        if not isinstance(item["dialect"], str) or any(
            not isinstance(item[field], bool) for field in required - {"dialect"}
        ):
            raise ValueError("adapter conformance entries have invalid field types")
        normalized_conformance.append(dict(item))
    evidence_artifacts = value.get("evidence_artifacts", [])
    if not isinstance(evidence_artifacts, list):
        raise ValueError("release evidence_artifacts must be an array")
    normalized_artifacts: list[dict[str, str]] = []
    allowed_gates = {
        "research_prototype",
        "web3_alpha",
        "production_candidate",
        "universal_expansion",
    }
    for artifact in evidence_artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {"gate", "path", "sha256"}:
            raise ValueError("release evidence artifacts require only gate, path, and sha256")
        gate = str(artifact["gate"])
        if gate not in allowed_gates:
            raise ValueError(f"unknown release evidence artifact gate: {gate}")
        artifact_input = Path(str(artifact["path"]))
        artifact_stat = artifact_input.lstat()
        if (
            not stat.S_ISREG(artifact_stat.st_mode)
            or stat.S_ISLNK(artifact_stat.st_mode)
            or artifact_stat.st_size > 100 * 1024 * 1024
        ):
            raise ValueError("release evidence artifacts must be regular non-symlink files no larger than 100 MB")
        artifact_path = artifact_input.resolve(strict=True)
        if sha256_file(artifact_path) != artifact["sha256"]:
            raise ValueError(f"release evidence artifact hash mismatch: {artifact_path}")
        normalized_artifacts.append(
            {"gate": gate, "path": str(artifact_path), "sha256": str(artifact["sha256"])}
        )
    return {
        "reproducible_builds": value.get("reproducible_builds", False),
        "ssg_dialects": list(dialects),
        "deterministic_baseline": value.get("deterministic_baseline", False),
        "typed_hypotheses": value.get("typed_hypotheses", False),
        "executable_evidence_ledger": value.get("executable_evidence_ledger", False),
        "dynamic_verifiers_per_ecosystem": dict(adapters),
        "deterministic_baseline_recall": baseline_recall,
        "auditable_cost_controls": value.get("auditable_cost_controls", False),
        "adapter_conformance": normalized_conformance,
        "evidence_artifacts": normalized_artifacts,
    }


def _has_release_artifact(evidence: dict[str, Any], gate: str) -> bool:
    return any(item["gate"] == gate for item in evidence["evidence_artifacts"])


def _verified_case_pack(
    manifest: dict[str, Any], manifest_path: Path
) -> dict[str, Any] | None:
    reference = manifest.get("case_pack")
    if reference is None:
        return None
    pack_path = resolve_case_pack_reference(manifest_path, str(reference["path"]))
    if sha256_file(pack_path) != reference["sha256"]:
        raise ValueError("benchmark case-pack reference hash mismatch")
    report = verify_case_pack(pack_path)
    if report["case_pack_sha256"] != reference["sha256"]:
        raise ValueError("benchmark case-pack verification hash mismatch")
    return report


def _validate_revealed_ground_truth(
    manifest: dict[str, Any],
    cases: dict[str, dict[str, Any]],
    case_pack: dict[str, Any] | None,
) -> dict[str, Any]:
    if case_pack is None:
        return {
            "case_pack_declared": False,
            "algorithm": GROUND_TRUTH_COMMITMENT_ALGORITHM,
            "valid": None,
            "metadata_matches": False,
            "committed_case_count": 0,
            "matched_case_count": 0,
            "mismatched_case_ids": [],
            "kloc_valid": None,
            "committed_kloc_case_count": 0,
            "matched_kloc_case_count": 0,
            "kloc_mismatched_case_ids": [],
            "missing_manifest_case_ids": [],
            "unexpected_manifest_case_ids": [],
            "violations": [],
        }

    pack_cases = {str(item["case_id"]): item for item in case_pack["cases"]}
    manifest_case_ids = set(cases)
    pack_case_ids = set(pack_cases)
    missing_manifest = sorted(pack_case_ids - manifest_case_ids)
    unexpected_manifest = sorted(manifest_case_ids - pack_case_ids)
    violations: list[str] = []
    if case_pack["cutoff"] != manifest["cutoff"]:
        violations.append("benchmark case-pack cutoff does not match the manifest")
    for case_id in missing_manifest:
        violations.append(f"benchmark manifest omits committed case: {case_id}")
    for case_id in unexpected_manifest:
        violations.append(f"benchmark manifest adds uncommitted case: {case_id}")

    origin_mismatches: list[str] = []
    commitment_mismatches: list[str] = []
    kloc_mismatches: list[str] = []
    matched = 0
    matched_kloc = 0
    for case_id in sorted(pack_case_ids & manifest_case_ids):
        case = cases[case_id]
        committed = pack_cases[case_id]
        if committed["originated_at"] != case["originated_at"]:
            origin_mismatches.append(case_id)
            violations.append(
                f"case {case_id} origin timestamp does not match the pre-trial case pack"
            )
        if committed["kloc"] != case["kloc"]:
            kloc_mismatches.append(case_id)
            violations.append(
                f"case {case_id} KLOC does not match the pre-trial case pack"
            )
        else:
            matched_kloc += 1
        revealed = canonical_ground_truth_document(
            case_id,
            case["eligible"],
            list(case["ground_truth"]),
        )
        observed_commitment = ground_truth_commitment_sha256(revealed)
        if observed_commitment != committed["public_commitment_sha256"]:
            commitment_mismatches.append(case_id)
            violations.append(
                f"case {case_id} revealed ground truth does not match its pre-trial commitment"
            )
        else:
            matched += 1

    metadata_matches = bool(
        case_pack["cutoff"] == manifest["cutoff"]
        and not missing_manifest
        and not unexpected_manifest
        and not origin_mismatches
        and not kloc_mismatches
    )
    kloc_valid = not missing_manifest and not unexpected_manifest and not kloc_mismatches
    return {
        "case_pack_declared": True,
        "algorithm": GROUND_TRUTH_COMMITMENT_ALGORITHM,
        "valid": not violations,
        "metadata_matches": metadata_matches,
        "committed_case_count": len(pack_cases),
        "matched_case_count": matched,
        "mismatched_case_ids": commitment_mismatches,
        "kloc_valid": kloc_valid,
        "committed_kloc_case_count": len(pack_cases),
        "matched_kloc_case_count": matched_kloc,
        "kloc_mismatched_case_ids": kloc_mismatches,
        "missing_manifest_case_ids": missing_manifest,
        "unexpected_manifest_case_ids": unexpected_manifest,
        "violations": violations,
    }


def _validate_finding_attribution(
    cases: dict[str, dict[str, Any]], trials: list[dict[str, Any]]
) -> dict[str, Any]:
    ground_truth_by_case = {
        case_id: {
            str(vulnerability["vulnerability_id"])
            for vulnerability in case["ground_truth"]
        }
        for case_id, case in cases.items()
    }
    violations: list[str] = []
    true_positive_count = 0
    attributed_true_positive_count = 0
    non_null_attribution_count = 0
    matched_attribution_count = 0
    invalid_findings: list[dict[str, Any]] = []
    for trial in trials:
        trial_id = str(trial["trial_id"])
        case_id = str(trial["case_id"])
        committed_ids = ground_truth_by_case[case_id]
        for finding in trial["findings"]:
            finding_id = str(finding["finding_id"])
            ground_truth_id = finding.get("ground_truth_id")
            is_true_positive = finding["verdict"] == "true_positive"
            true_positive_count += is_true_positive
            if ground_truth_id is None:
                if is_true_positive:
                    reason = (
                        f"trial {trial_id} true-positive finding {finding_id} lacks a "
                        "ground_truth_id"
                    )
                    violations.append(reason)
                    invalid_findings.append(
                        {
                            "trial_id": trial_id,
                            "finding_id": finding_id,
                            "ground_truth_id": None,
                            "reason": reason,
                        }
                    )
                continue

            non_null_attribution_count += 1
            if str(ground_truth_id) not in committed_ids:
                reason = (
                    f"trial {trial_id} finding {finding_id} attributes to unknown "
                    f"ground truth {ground_truth_id} for case {case_id}"
                )
                violations.append(reason)
                invalid_findings.append(
                    {
                        "trial_id": trial_id,
                        "finding_id": finding_id,
                        "ground_truth_id": str(ground_truth_id),
                        "reason": reason,
                    }
                )
                continue
            matched_attribution_count += 1
            attributed_true_positive_count += is_true_positive

    return {
        "valid": not violations,
        "finding_count": sum(len(trial["findings"]) for trial in trials),
        "true_positive_count": true_positive_count,
        "attributed_true_positive_count": attributed_true_positive_count,
        "non_null_attribution_count": non_null_attribution_count,
        "matched_attribution_count": matched_attribution_count,
        "invalid_findings": invalid_findings,
        "violations": violations,
    }


def _suite_qualification(
    manifest: dict[str, Any],
    cases: dict[str, dict[str, Any]],
    trials: list[dict[str, Any]],
    high_reports: list[dict[str, Any]],
    temporal: dict[str, Any],
    case_pack: dict[str, Any] | None,
    ground_truth_validation: dict[str, Any],
    finding_attribution_validation: dict[str, Any],
    ledger_validation: dict[str, Any],
    evaluation_valid: bool,
) -> dict[str, Any]:
    eligible = {
        case_id: case for case_id, case in cases.items() if case["eligible"] is True
    }
    vulnerable_cases = {
        case_id for case_id, case in eligible.items() if case["ground_truth"]
    }
    benign_controls = set(eligible) - vulnerable_cases

    seeds_by_case: dict[str, set[int]] = defaultdict(set)
    for trial in trials:
        seed = trial.get("seed")
        if (
            trial["case_id"] in eligible
            and isinstance(seed, int)
            and not isinstance(seed, bool)
        ):
            seeds_by_case[str(trial["case_id"])].add(seed)
    distinct_seed_counts = {
        case_id: len(seeds_by_case[case_id]) for case_id in eligible
    }
    minimum_distinct_seeds = min(distinct_seed_counts.values(), default=0)

    actionable_high_reports = sum(
        _evidence_rank(item["evidence_level"])
        >= _evidence_rank(EvidenceLevel.EXECUTABLE.value)
        for item in high_reports
    )
    fully_accounted_trials = sum(_trial_costs_complete(trial) for trial in trials)

    pack_matches_manifest = ground_truth_validation["metadata_matches"] is True

    checks = {
        "valid_blind_temporal_suite": evaluation_valid
        and temporal["valid"]
        and manifest["blind"] is True,
        "minimum_vulnerable_cases": len(vulnerable_cases) >= MINIMUM_VULNERABLE_CASES,
        "minimum_benign_controls": len(benign_controls) >= MINIMUM_BENIGN_CONTROLS,
        "minimum_distinct_seeds_per_case": bool(eligible)
        and minimum_distinct_seeds >= MINIMUM_DISTINCT_SEEDS_PER_CASE,
        "verified_independent_case_pack": bool(
            case_pack is not None
            and case_pack["valid"] is True
            and case_pack["independent"] is True
            and pack_matches_manifest
        ),
        "committed_ground_truth_matches_reveal": ground_truth_validation["valid"]
        is True,
        "committed_case_sizes_match": ground_truth_validation["kloc_valid"] is True,
        "findings_match_committed_ground_truth": finding_attribution_validation[
            "valid"
        ]
        is True,
        "checkpointed_trial_ledgers": ledger_validation["valid"] is True,
        "actionable_high_critical_evidence": actionable_high_reports
        == len(high_reports),
        "complete_trial_cost_accounting": fully_accounted_trials == len(trials),
    }
    reason_by_check = {
        "valid_blind_temporal_suite": "requires a valid blind temporal suite",
        "minimum_vulnerable_cases": (
            f"requires at least {MINIMUM_VULNERABLE_CASES} eligible vulnerable cases "
            f"(observed {len(vulnerable_cases)})"
        ),
        "minimum_benign_controls": (
            f"requires at least {MINIMUM_BENIGN_CONTROLS} eligible benign controls "
            f"(observed {len(benign_controls)})"
        ),
        "minimum_distinct_seeds_per_case": (
            f"requires at least {MINIMUM_DISTINCT_SEEDS_PER_CASE} distinct integer seeds "
            f"for every eligible case (minimum observed {minimum_distinct_seeds})"
        ),
        "verified_independent_case_pack": (
            "requires a hash-verified independently authored encrypted case pack "
            "whose cutoff, case ids, and origin timestamps match the manifest"
        ),
        "committed_ground_truth_matches_reveal": (
            "requires every revealed eligibility flag, vulnerable/benign class, label, "
            "and ground-truth record to match its pre-trial commitment"
        ),
        "committed_case_sizes_match": (
            "requires every manifest KLOC denominator to match its independently "
            "authored pre-trial case-pack value"
        ),
        "findings_match_committed_ground_truth": (
            "requires every true positive to identify committed ground truth and every "
            "non-null attribution to match that case's committed vulnerability ids"
        ),
        "checkpointed_trial_ledgers": (
            "requires every trial and complete finding set to match a verified Nirvana "
            "ledger checkpoint with replay-verified evidence at the claimed tier"
        ),
        "actionable_high_critical_evidence": (
            "requires executable-or-stronger evidence for every High/Critical report"
        ),
        "complete_trial_cost_accounting": (
            "requires every trial to declare complete accounting, tokens used within a "
            "non-zero budget, compute hours, and model cost"
        ),
    }
    reasons = [reason_by_check[name] for name, passed in checks.items() if not passed]
    return {
        "qualification_version": "nirvana-closed-beta-v3",
        "qualified": all(checks.values()),
        "requirements": {
            "minimum_eligible_vulnerable_cases": MINIMUM_VULNERABLE_CASES,
            "minimum_eligible_benign_controls": MINIMUM_BENIGN_CONTROLS,
            "minimum_distinct_seeds_per_eligible_case": MINIMUM_DISTINCT_SEEDS_PER_CASE,
            "independently_authored_encrypted_case_pack": True,
            "committed_ground_truth_reveal": True,
            "committed_ground_truth_attribution": True,
            "committed_case_sizes": True,
            "checkpointed_trial_ledgers": True,
            "high_critical_minimum_evidence": EvidenceLevel.EXECUTABLE.value,
            "complete_trial_cost_accounting": True,
        },
        "observed": {
            "eligible_vulnerable_cases": len(vulnerable_cases),
            "eligible_benign_controls": len(benign_controls),
            "minimum_distinct_seeds_per_eligible_case": minimum_distinct_seeds,
            "high_critical_reports": len(high_reports),
            "high_critical_reports_with_actionable_evidence": actionable_high_reports,
            "trials": len(trials),
            "fully_accounted_trials": fully_accounted_trials,
            "case_pack_declared": manifest.get("case_pack") is not None,
            "case_pack_verified": case_pack is not None,
            "case_pack_matches_manifest": pack_matches_manifest,
            "committed_ground_truth_cases": ground_truth_validation[
                "committed_case_count"
            ],
            "matched_ground_truth_commitments": ground_truth_validation[
                "matched_case_count"
            ],
            "committed_kloc_cases": ground_truth_validation[
                "committed_kloc_case_count"
            ],
            "matched_kloc_cases": ground_truth_validation[
                "matched_kloc_case_count"
            ],
            "attributed_true_positive_findings": finding_attribution_validation[
                "attributed_true_positive_count"
            ],
            "verified_trial_ledgers": ledger_validation["verified_trial_count"],
            "ledger_bound_findings": ledger_validation["matched_finding_count"],
            "externally_anchored_trial_ledgers": ledger_validation[
                "externally_anchored_trial_count"
            ],
        },
        "checks": checks,
        "reasons": reasons,
        "case_pack": (
            {
                "pack_id": case_pack["pack_id"],
                "sha256": case_pack["case_pack_sha256"],
                "case_count": case_pack["case_count"],
            }
            if case_pack is not None
            else None
        ),
    }


def _trial_costs_complete(trial: dict[str, Any]) -> bool:
    tokens_used = trial.get("tokens_used")
    token_budget = trial.get("token_budget")
    return bool(
        trial.get("cost_accounting_complete") is True
        and isinstance(tokens_used, int)
        and not isinstance(tokens_used, bool)
        and tokens_used >= 0
        and isinstance(token_budget, int)
        and not isinstance(token_budget, bool)
        and token_budget > 0
        and tokens_used <= token_budget
        and isinstance(trial.get("compute_hours"), (int, float))
        and not isinstance(trial.get("compute_hours"), bool)
        and isinstance(trial.get("model_cost"), (int, float))
        and not isinstance(trial.get("model_cost"), bool)
    )


def _validate_temporal_split(manifest: dict[str, Any]) -> dict[str, Any]:
    cutoff = _date(manifest["cutoff"])
    violations: list[str] = []
    for corpus in manifest["corpora"]:
        missing = {"corpus_id", "role", "published_at", "sha256"} - corpus.keys()
        if missing:
            violations.append(f"corpus record lacks {sorted(missing)}")
            continue
        if corpus["role"] in {"training", "retrieval", "detector_rules"} and _date(corpus["published_at"]) > cutoff:
            violations.append(f"corpus {corpus['corpus_id']} post-dates cutoff")
    for case in manifest["cases"]:
        if _date(case["originated_at"]) <= cutoff:
            violations.append(f"case {case['case_id']} does not originate after cutoff")
        if _date(case["disclosed_at"]) <= cutoff:
            violations.append(f"case {case['case_id']} was disclosed before or at cutoff")
        if case["ground_truth_material_blocked"] is not True:
            violations.append(f"case {case['case_id']} did not block issue, patch, and audit ground truth")
        if case["eventual_fix_accessed"] is not False:
            violations.append(f"case {case['case_id']} accessed the eventual fix")
        if case["hidden_variant"] and not case["transformation_log_sha256"]:
            violations.append(f"hidden variant {case['case_id']} lacks a transformation log hash")
    archives_complete = all(
        bool(trial.get("model"))
        and bool(trial.get("prompt_sha256"))
        and bool(trial.get("tools"))
        and bool(trial.get("transcript_sha256"))
        and bool(trial.get("environment_sha256"))
        and isinstance(trial.get("token_budget"), int)
        for trial in manifest["trials"]
    )
    if not archives_complete:
        violations.append("one or more trials lack archived model, prompt, tool, budget, transcript, or environment provenance")
    if manifest["blind"] is not True:
        violations.append("benchmark is not marked blind")
    return {
        "cutoff": manifest["cutoff"],
        "valid": not violations,
        "blind": manifest["blind"],
        "archives_complete": archives_complete,
        "violations": violations,
    }


def _magma_metrics(
    trials: list[dict[str, Any]], eligible: set[tuple[str, str]]
) -> dict[str, Any]:
    reached = {
        (str(trial["case_id"]), str(item))
        for trial in trials
        for item in trial["reached_ids"]
    } & eligible
    triggered = {
        (str(trial["case_id"]), str(item))
        for trial in trials
        for item in trial["triggered_ids"]
    } & eligible
    detected = {
        (str(trial["case_id"]), str(item))
        for trial in trials
        for item in trial["detected_ids"]
    } & eligible
    return {
        "eligible": len(eligible),
        "reached": len(reached),
        "triggered": len(triggered),
        "detected_and_explained": len(detected),
        "reach_rate": _ratio(len(reached), len(eligible)),
        "trigger_rate": _ratio(len(triggered), len(eligible)),
        "detection_rate": _ratio(len(detected), len(eligible)),
    }


def _stability(trials: list[dict[str, Any]]) -> dict[str, Any]:
    by_case: dict[str, list[set[str]]] = defaultdict(list)
    for trial in trials:
        by_case[str(trial["case_id"])].append(
            {
                str(item["ground_truth_id"])
                for item in trial["findings"]
                if item["verdict"] == "true_positive" and item.get("ground_truth_id")
            }
        )
    counts = [len(items) for groups in by_case.values() for items in groups]
    jaccards: list[float] = []
    for groups in by_case.values():
        for index, first in enumerate(groups):
            for second in groups[index + 1 :]:
                union = first | second
                jaccards.append(len(first & second) / len(union) if union else 1.0)
    return {
        "detection_count_variance": statistics.pvariance(counts) if len(counts) > 1 else 0.0 if counts else None,
        "mean_pairwise_jaccard": _mean(jaccards),
        "repeated_case_count": sum(len(items) > 1 for items in by_case.values()),
    }


def _evidence_rank(value: str) -> int:
    order = [item.value for item in EvidenceLevel]
    return order.index(EvidenceLevel(value).value)


def _ratio(numerator: float, denominator: float) -> float | None:
    return numerator / denominator if denominator else None


def _mean(values: Iterable[float]) -> float | None:
    items = list(values)
    return sum(items) / len(items) if items else None


def _date(value: str) -> datetime:
    normalized = str(value).replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
