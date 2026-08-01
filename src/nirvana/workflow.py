from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .evm import SolcAstCandidateScanner, SolidityCandidateScanner
from .intake import IntakePolicy, RepositoryIntake, ScopeManifest, validate_scope_against_ledger
from .ledger import EvidenceLedger
from .models import Finding, Hypothesis
from .reporting import render_audit_report
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

    hypotheses = SolidityCandidateScanner(
        max_file_bytes=selected_policy.max_file_bytes
    ).scan_repository(target_root)
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
    hypothesis_text = "".join(canonical_json(item.to_dict()) + "\n" for item in hypotheses)
    atomic_write_text(run_directory / "hypotheses.jsonl", hypothesis_text)
    ledger.append_many(
        [{"event": "hypothesis_proposed", "hypothesis": hypothesis.to_dict()} for hypothesis in hypotheses]
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
    findings = [
        Finding.from_dict(record["payload"]["finding"])
        for record in records
        if record["payload"].get("event") == "finding_confirmed"
    ]
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
        "schema_version": "1.1.0",
        "run_id": resolved.name,
        "target": scope.target_root,
        "commit": scope.repository_commit,
        "target_snapshot_sha256": scope.target_snapshot_sha256,
        "snapshot_complete": scope.snapshot_complete,
        "confirmed_findings": [item.to_dict() for item in findings],
        "hypothesis_count": len(hypotheses),
        "evidence_ceiling": scope.evidence_ceiling.value,
        "verified_evidence": verified_evidence,
        "corroborated_evidence": corroborated_evidence,
        "ledger_records": len(records),
    }
    atomic_write_json(resolved / "report.json", summary)
    atomic_write_text(
        resolved / "report.md",
        render_audit_report(scope, hypotheses, findings, resolved.name),
    )
