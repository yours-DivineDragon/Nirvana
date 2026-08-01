from __future__ import annotations

import json
import math
import stat
import statistics
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from .contracts import validate_contract
from .models import EvidenceLevel, Severity
from .util import atomic_write_json, sha256_file, utc_now


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
    findings = [
        {**finding, "trial_id": trial["trial_id"], "case_id": trial["case_id"]}
        for trial in trials
        for finding in trial["findings"]
    ]
    eligible_ground_truth = {
        (case_id, str(vulnerability["vulnerability_id"]))
        for case_id, case in cases.items()
        if case["eligible"]
        for vulnerability in case["ground_truth"]
    }
    detected_ground_truth = {
        (str(item["case_id"]), str(item["ground_truth_id"]))
        for item in findings
        if item["verdict"] == "true_positive" and item.get("ground_truth_id") is not None
    } & eligible_ground_truth
    reported = [item for item in findings if item["verdict"] != "suppressed"]
    true_reports = [item for item in reported if item["verdict"] == "true_positive"]
    high_reports = [item for item in reported if item["severity"] in {"high", "critical"}]
    high_true = [item for item in high_reports if item["verdict"] == "true_positive"]
    confirmed = [
        item
        for item in true_reports
        if _evidence_rank(item["evidence_level"])
        >= _evidence_rank(EvidenceLevel.STRUCTURALLY_CONFIRMED.value)
    ]
    novel_confirmed = [item for item in confirmed if item.get("novel") is True]
    total_kloc = sum(float(case["kloc"]) for case in cases.values() if case["eligible"])
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
            "per_kloc": _ratio(len(novel_confirmed), total_kloc),
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
    closed_beta = (
        temporal["valid"]
        and manifest["blind"] is True
        and precision is not None
        and precision >= 0.80
        and high_precision is not None
        and high_precision >= 0.90
    )
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
            "overall_precision_target": 0.80,
            "high_critical_precision_target": 0.90,
            "blind_temporal_suite_required": True,
            "recall_reported": metrics["ground_truth_recall"] is not None,
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
    warnings: list[str] = []
    if not temporal["valid"]:
        warnings.extend(temporal["violations"])
        warnings.insert(
            0,
            "benchmark report is invalid; metrics are diagnostic only and must not be used as release evidence",
        )
    if metrics["ground_truth_recall"] is None:
        warnings.append("ground-truth recall is undefined because no eligible vulnerabilities were supplied")
    if not high_reports:
        warnings.append("high-severity precision is undefined because no high/critical reports were emitted")
    report = {
        "schema_version": "1.1.0",
        "created_at": utc_now(),
        "benchmark_id": manifest["benchmark_id"],
        "manifest_sha256": sha256_file(resolved),
        "track": manifest["track"],
        "valid": temporal["valid"],
        "temporal_validation": temporal,
        "counts": {
            "cases": len(cases),
            "trials": len(trials),
            "eligible_ground_truth": len(eligible_ground_truth),
            "reported_findings": len(reported),
            "true_reports": len(true_reports),
            "confirmed_true_reports": len(confirmed),
        },
        "metrics": metrics,
        "magma": magma,
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
        for vulnerability in case["ground_truth"]:
            if {"vulnerability_id", "severity"} - vulnerability.keys():
                raise ValueError("ground-truth vulnerabilities require id and severity")
            Severity(vulnerability["severity"])
        if not isinstance(case["kloc"], (int, float)) or isinstance(case["kloc"], bool) or case["kloc"] < 0:
            raise ValueError("benchmark case kloc must be a non-negative number")
    trial_ids: set[str] = set()
    for trial in manifest["trials"]:
        required = {
            "trial_id", "case_id", "run_id", "seed", "started_at", "ended_at",
            "model", "prompt_sha256", "tools", "token_budget", "compute_hours",
            "model_cost", "transcript_sha256", "environment_sha256", "findings",
            "coverage", "reached_ids", "triggered_ids", "detected_ids",
        }
        missing = required - trial.keys()
        if missing:
            raise ValueError(f"benchmark trial lacks required fields: {sorted(missing)}")
        if trial["case_id"] not in case_ids:
            raise ValueError(f"benchmark trial references unknown case: {trial['case_id']}")
        if trial["trial_id"] in trial_ids:
            raise ValueError(f"duplicate benchmark trial: {trial['trial_id']}")
        trial_ids.add(trial["trial_id"])
        if not isinstance(trial["tools"], list) or not trial["tools"]:
            raise ValueError("benchmark trial tools must be a non-empty array")
        if not isinstance(trial["token_budget"], int) or isinstance(trial["token_budget"], bool) or trial["token_budget"] < 0:
            raise ValueError("benchmark token_budget must be a non-negative integer")
        for field in ("compute_hours", "model_cost"):
            if not isinstance(trial[field], (int, float)) or isinstance(trial[field], bool) or trial[field] < 0:
                raise ValueError(f"benchmark {field} must be a non-negative number")
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
            Severity(finding["severity"])
            EvidenceLevel(finding["evidence_level"])
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
