from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .adjudication import (
    current_hypothesis_status,
    latest_novelty_assessments,
    rejected_archive,
)
from .contracts import validate_contract
from .coverage import CoverageManifest, build_coverage_schedule
from .evm import SolcAstCandidateScanner, SolidityCandidateScanner
from .intake import IntakePolicy, RepositoryIntake, ScopeManifest, validate_scope_against_ledger
from .ledger import EvidenceLedger
from .models import Finding, Hypothesis
from .policy import CommandRunner
from .reporting import render_audit_report
from .semantic import (
    SemanticGraphBuilder,
    bind_hypotheses_to_graph,
    default_historical_templates,
    graph_hypotheses,
)
from .util import atomic_write_json, atomic_write_text, canonical_json, sha256_bytes, sha256_file, utc_now


@dataclass(slots=True)
class AuditResult:
    run_id: str
    run_directory: Path
    scope: ScopeManifest
    hypotheses: list[Hypothesis]


def audit(
    target: Path,
    output_root: Path,
    intake_policy: IntakePolicy | None = None,
    solc_ast: Path | None = None,
    baseline_request: Path | None = None,
    baseline_runner: CommandRunner | None = None,
) -> AuditResult:
    target_root = target.resolve(strict=True)
    timestamp = utc_now().replace(":", "").replace("-", "")
    identity = sha256_bytes(f"{target_root}\0{time.time_ns()}".encode())[:8]
    run_id = f"{timestamp}-{identity}"
    run_directory = output_root.resolve() / run_id
    run_directory.mkdir(parents=True, exist_ok=False)

    ledger = EvidenceLedger(run_directory / "evidence.jsonl")
    selected_policy = intake_policy or IntakePolicy()
    scope = RepositoryIntake(
        max_file_bytes=selected_policy.max_file_bytes,
        ignored_directories=selected_policy.excluded_directories,
    ).inspect(target_root)
    atomic_write_json(run_directory / "scope.json", scope)
    ledger.append({"event": "scope_captured", "scope": scope.to_dict()})
    if baseline_request is not None:
        if baseline_runner is None:
            raise ValueError("a baseline request requires an execution runner")
        from .baseline import run_baseline

        run_baseline(run_directory, baseline_request, baseline_runner)

    hypotheses = SolidityCandidateScanner(
        max_file_bytes=selected_policy.max_file_bytes
    ).scan_repository(target_root)
    ast_path: Path | None = None
    if solc_ast is not None:
        ast_path = solc_ast.resolve(strict=True)
        ast_hypotheses = SolcAstCandidateScanner().scan_file(ast_path, target_root)
        known = {item.hypothesis_id for item in hypotheses}
        hypotheses.extend(item for item in ast_hypotheses if item.hypothesis_id not in known)
        ledger.append(
            {
                "event": "analysis_input_recorded",
                "kind": "solc-standard-json-ast",
                "path": str(ast_path),
                "sha256": sha256_file(ast_path),
                "hypotheses": len(ast_hypotheses),
            }
        )
    graph = SemanticGraphBuilder(
        max_file_bytes=selected_policy.max_file_bytes
    ).build(
        target_root,
        scope,
        solc_ast=ast_path,
    )
    bind_hypotheses_to_graph(graph, hypotheses)
    graph_candidates = graph_hypotheses(
        graph,
        target_root,
        hypotheses,
        default_historical_templates(),
    )
    known = {item.hypothesis_id for item in hypotheses}
    hypotheses.extend(item for item in graph_candidates if item.hypothesis_id not in known)
    graph_path = run_directory / "semantic-graph.json"
    atomic_write_json(graph_path, graph)
    graph_digest = sha256_file(graph_path)
    ledger.append(
        {
            "event": "semantic_graph_created",
            "artifact_path": str(graph_path),
            "artifact_sha256": graph_digest,
            "target_snapshot_sha256": scope.target_snapshot_sha256,
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
            "support": [item.maturity.value for item in graph.support],
            "warnings": list(graph.warnings),
        }
    )
    hypothesis_text = "".join(canonical_json(item.to_dict()) + "\n" for item in hypotheses)
    atomic_write_text(run_directory / "hypotheses.jsonl", hypothesis_text)
    ledger.append_many(
        [{"event": "hypothesis_proposed", "hypothesis": hypothesis.to_dict()} for hypothesis in hypotheses]
    )

    coverage = build_coverage_schedule(graph, hypotheses)
    coverage_initial_path = run_directory / "coverage-initial.json"
    coverage_path = run_directory / "coverage.json"
    atomic_write_json(coverage_initial_path, coverage)
    atomic_write_json(coverage_path, coverage)
    ledger.append(
        {
            "event": "coverage_schedule_created",
            "artifact_path": str(coverage_initial_path),
            "coverage_sha256": sha256_file(coverage_initial_path),
            "graph_sha256": coverage.graph_sha256,
            "flow_count": len(coverage.flows),
            "task_count": len(coverage.tasks),
        }
    )

    ledger.append(
        {
            "event": "run_completed",
            "confirmed_findings": 0,
            "hypotheses": len(hypotheses),
        }
    )
    refresh_report(run_directory)
    return AuditResult(run_id, run_directory, scope, hypotheses)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def refresh_report(run_directory: Path) -> None:
    resolved = run_directory.resolve(strict=True)
    ledger = EvidenceLedger(resolved / "evidence.jsonl")
    records = ledger.records()
    ledger.verify()
    scope_path = resolved / "scope.json"
    loaded_scope = ScopeManifest.from_dict(load_json(scope_path))
    recorded_ceiling = loaded_scope.evidence_ceiling
    scope = validate_scope_against_ledger(loaded_scope, records)
    if scope.evidence_ceiling is not recorded_ceiling:
        atomic_write_json(scope_path, scope)
    hypotheses = [
        Hypothesis.from_dict(record["payload"]["hypothesis"])
        for record in records
        if record["payload"].get("event") == "hypothesis_proposed"
    ]
    for hypothesis in hypotheses:
        hypothesis.status = current_hypothesis_status(records, hypothesis.hypothesis_id)
    findings = [
        Finding.from_dict(record["payload"]["finding"])
        for record in records
        if record["payload"].get("event") == "finding_confirmed"
    ]
    novelty_assessments = latest_novelty_assessments(records)
    duplicate_findings = sorted(
        finding.finding_id
        for finding in findings
        if novelty_assessments.get(finding.finding_id, {}).get("classification")
        == "exact_duplicate"
    )
    reportable_findings = [
        finding for finding in findings if finding.finding_id not in duplicate_findings
    ]
    rejection_records = rejected_archive(records)
    graph_path = resolved / "semantic-graph.json"
    if graph_path.is_file():
        graph_value = load_json(graph_path)
        validate_contract(graph_value, "semantic-graph.schema.json")
        # The report only needs the validated serialized support and counts. The
        # graph contract is checked when it is created; its immutable hash is in
        # the ledger and rechecked below.
        graph_record = next(
            (
                record["payload"]
                for record in records
                if record["payload"].get("event") == "semantic_graph_created"
            ),
            None,
        )
        if graph_record is None or sha256_file(graph_path) != graph_record.get("artifact_sha256"):
            raise ValueError("semantic graph does not match its ledger-bound artifact")
    coverage_value: dict[str, Any] | None = None
    coverage_path = resolved / "coverage.json"
    if coverage_path.is_file():
        from .coverage import CoverageBoard

        coverage_value = CoverageBoard(resolved).load().to_dict()
    baseline = next(
        (
            record["payload"]
            for record in reversed(records)
            if record["payload"].get("event") == "baseline_executed"
        ),
        None,
    )
    evidence_records = [
        record["payload"]["evidence"]
        for record in records
        if record["payload"].get("event") == "evidence_recorded"
    ]
    model_cost_values = [
        float(value)
        for hypothesis in hypotheses
        for key, value in hypothesis.cost.items()
        if key in {"model_cost", "model_cost_units"}
    ]
    cost_accounting = {
        "verification_execution_ms": sum(
            int(item.get("metadata", {}).get("duration_ms", 0))
            + int(item.get("metadata", {}).get("negative_control_duration_ms", 0))
            for item in evidence_records
        ),
        "model_cost_units": sum(model_cost_values),
        "model_cost_complete": bool(hypotheses) and all(
            "model_cost" in hypothesis.cost or "model_cost_units" in hypothesis.cost
            for hypothesis in hypotheses
        ),
        "confirmed_finding_count": len(reportable_findings),
    }
    cost_accounting["verification_ms_per_confirmed_finding"] = (
        cost_accounting["verification_execution_ms"] / len(reportable_findings)
        if reportable_findings
        else None
    )
    latest_replays: dict[str, str] = {}
    for record in records:
        payload = record["payload"]
        if payload.get("event") in {"evidence_verified", "evidence_replay_failed"}:
            latest_replays[str(payload["evidence_id"])] = str(payload["event"])
    verified_evidence = sorted(
        evidence_id
        for evidence_id, event in latest_replays.items()
        if event == "evidence_verified"
    )
    corroborated_evidence = sorted(
        {
            str(evidence_id)
            for record in records
            if record["payload"].get("event") == "structural_corroboration_verified"
            for evidence_id in record["payload"].get("evidence_ids", [])
        }
    )
    summary: dict[str, Any] = {
        "schema_version": "2.0.0",
        "run_id": resolved.name,
        "target": scope.target_root,
        "commit": scope.repository_commit,
        "target_snapshot_sha256": scope.target_snapshot_sha256,
        "snapshot_complete": scope.snapshot_complete,
        "confirmed_findings": [item.to_dict() for item in reportable_findings],
        "deduplicated_findings": duplicate_findings,
        "novelty_assessments": novelty_assessments,
        "rejection_archive": rejection_records,
        "learning_bundles": [
            {
                "finding_id": record["payload"]["finding_id"],
                "artifact_path": record["payload"]["artifact_path"],
                "artifact_sha256": record["payload"]["artifact_sha256"],
                "promotion_status": record["payload"]["promotion_status"],
            }
            for record in records
            if record["payload"].get("event") == "learning_bundle_created"
        ],
        "hypothesis_count": len(hypotheses),
        "evidence_ceiling": scope.evidence_ceiling.value,
        "verified_evidence": verified_evidence,
        "corroborated_evidence": corroborated_evidence,
        "ledger_records": len(records),
        "semantic_graph": (
            {
                "artifact_sha256": graph_record["artifact_sha256"],
                "node_count": graph_record["node_count"],
                "edge_count": graph_record["edge_count"],
                "support": graph_value.get("support", []),
                "warnings": graph_value.get("warnings", []),
            }
            if graph_path.is_file()
            else None
        ),
        "coverage": coverage_value,
        "baseline": baseline,
        "cost_accounting": cost_accounting,
    }
    validate_contract(summary, "audit-report.schema.json")
    atomic_write_json(resolved / "report.json", summary)
    atomic_write_text(
        resolved / "report.md",
        render_audit_report(
            scope,
            hypotheses,
            reportable_findings,
            resolved.name,
            graph_summary=summary["semantic_graph"],
            coverage=coverage_value,
            baseline=baseline,
            novelty_assessments=novelty_assessments,
            rejection_archive=rejection_records,
            deduplicated_findings=duplicate_findings,
            cost_accounting=cost_accounting,
        ),
    )
