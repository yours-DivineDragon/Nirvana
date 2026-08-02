from __future__ import annotations

import json
import stat
from pathlib import Path, PurePosixPath
from typing import Any

from .contracts import validate_contract
from .intake import ScopeManifest, validate_scope_against_ledger
from .ledger import EvidenceLedger
from .models import EVIDENCE_RANK, EvidenceLevel, EvidenceRecord, Finding
from .util import canonical_json, sha256_bytes, sha256_file


BENCHMARK_LEDGER_BINDING_ALGORITHM = "nirvana-ledger-checkpoint-v1"
MAX_BENCHMARK_LEDGER_BYTES = 256 * 1024 * 1024
MAX_BENCHMARK_CHECKPOINT_BYTES = 1024 * 1024


def seal_benchmark_trial(
    run_directory: Path,
    *,
    trial_id: str,
    case_id: str,
    seed: int,
    output: Path,
) -> dict[str, Any]:
    """Seal a completed run's full finding set and export its ledger checkpoint."""

    if not trial_id or not case_id:
        raise ValueError("benchmark trial and case ids must be non-empty")
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise ValueError("benchmark trial seed must be an integer")
    resolved_run = run_directory.resolve(strict=True)
    ledger_path = _regular_file(
        resolved_run / "evidence.jsonl",
        MAX_BENCHMARK_LEDGER_BYTES,
        "benchmark trial evidence ledger",
    )
    scope_path = _regular_file(
        resolved_run / "scope.json",
        MAX_BENCHMARK_CHECKPOINT_BYTES,
        "benchmark trial scope manifest",
    )
    resolved_output = _checkpoint_output(output)
    if resolved_output in {ledger_path, scope_path}:
        raise ValueError("benchmark trial checkpoint must not overwrite run evidence")

    ledger = EvidenceLedger(ledger_path)
    records = ledger.records()
    ledger.verify()
    if not any(
        record["payload"].get("event") == "run_completed" for record in records
    ):
        raise ValueError("benchmark trial cannot be sealed before the run completes")

    scope_value = json.loads(scope_path.read_text(encoding="utf-8"))
    if not isinstance(scope_value, dict):
        raise ValueError("run scope manifest must be one JSON object")
    scope = ScopeManifest.from_dict(scope_value)
    validate_scope_against_ledger(scope, records)
    findings, _, violations = _checkpointed_findings(records, scope)
    if violations:
        raise ValueError(
            "benchmark trial findings are not ledger-valid: " + "; ".join(violations)
        )
    finding_claims = _finding_claims(findings)
    existing_seals = [
        record
        for record in records
        if record["payload"].get("event") == "benchmark_trial_sealed"
    ]
    if existing_seals:
        _, seal_violations = _validate_trial_seal(
            records,
            {
                "trial_id": trial_id,
                "case_id": case_id,
                "run_id": resolved_run.name,
                "seed": seed,
            },
            findings,
        )
        if seal_violations:
            raise ValueError(
                "benchmark trial already has a conflicting seal: "
                + "; ".join(seal_violations)
            )
        seal = existing_seals[0]["payload"]
        seal_record_hash = existing_seals[0]["record_hash"]
    else:
        seal = {
            "schema_version": "1.0.0",
            "event": "benchmark_trial_sealed",
            "trial_id": trial_id,
            "case_id": case_id,
            "run_id": resolved_run.name,
            "seed": seed,
            "ledger_sequence_before_seal": len(records),
            "findings": finding_claims,
            "finding_set_sha256": sha256_bytes(
                canonical_json(finding_claims).encode("utf-8")
            ),
        }
        validate_contract(seal, "benchmark-trial-seal.schema.json")
        seal_record_hash = ledger.append(seal)["record_hash"]
    checkpoint = ledger.export_checkpoint(resolved_output)
    return {
        "seal": seal,
        "seal_record_hash": seal_record_hash,
        "checkpoint": checkpoint,
        "checkpoint_path": str(resolved_output),
        "checkpoint_sha256": sha256_file(resolved_output),
    }


def validate_trial_ledger_bindings(
    manifest_path: Path, trials: list[dict[str, Any]]
) -> dict[str, Any]:
    """Verify each trial against an immutable prefix of its Nirvana run ledger."""

    results: list[dict[str, Any]] = []
    violations: list[str] = []
    verified_trials = 0
    verified_findings = 0
    externally_anchored_trials = 0
    for trial in trials:
        trial_id = str(trial["trial_id"])
        run_id = str(trial["run_id"])
        try:
            result, trial_violations = _validate_trial_binding(
                manifest_path, trial
            )
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            trial_violations = [
                f"trial {trial_id} ledger binding is invalid: {error}"
            ]
            result = {
                "trial_id": trial_id,
                "run_id": run_id,
                "valid": False,
                "checkpoint_sha256": None,
                "checkpoint_sequence": None,
                "checkpoint_record_hash": None,
                "trial_seal_sequence": None,
                "externally_anchored": False,
                "checkpointed_finding_ids": [],
                "matched_finding_ids": [],
                "replay_verified_evidence_ids": [],
                "post_checkpoint_invalidated_evidence_ids": [],
                "violations": trial_violations,
            }
        if trial_violations:
            result["valid"] = False
            result["violations"] = trial_violations
            violations.extend(trial_violations)
        else:
            verified_trials += 1
            verified_findings += len(result["matched_finding_ids"])
            externally_anchored_trials += result["externally_anchored"] is True
        results.append(result)

    return {
        "algorithm": BENCHMARK_LEDGER_BINDING_ALGORITHM,
        "valid": not violations,
        "trial_count": len(trials),
        "verified_trial_count": verified_trials,
        "checkpointed_finding_count": sum(
            len(item["checkpointed_finding_ids"]) for item in results
        ),
        "matched_finding_count": verified_findings,
        "externally_anchored_trial_count": externally_anchored_trials,
        "trials": results,
        "violations": violations,
    }


def _validate_trial_binding(
    manifest_path: Path, trial: dict[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    trial_id = str(trial["trial_id"])
    run_id = str(trial["run_id"])
    binding = trial["ledger_checkpoint"]
    if binding["algorithm"] != BENCHMARK_LEDGER_BINDING_ALGORITHM:
        raise ValueError("unsupported ledger checkpoint binding algorithm")

    run_directory = _relative_path(
        manifest_path,
        str(binding["run_directory"]),
        kind="directory",
        label=f"trial {trial_id} run directory",
    )
    if run_directory.name != run_id:
        raise ValueError(
            f"run id {run_id} does not match run directory {run_directory.name}"
        )
    checkpoint_path = _relative_path(
        manifest_path,
        str(binding["checkpoint_path"]),
        kind="file",
        label=f"trial {trial_id} ledger checkpoint",
        max_bytes=MAX_BENCHMARK_CHECKPOINT_BYTES,
    )
    observed_checkpoint_sha256 = sha256_file(checkpoint_path)
    if observed_checkpoint_sha256 != binding["checkpoint_sha256"]:
        raise ValueError("ledger checkpoint artifact hash mismatch")

    ledger_path = _regular_file(
        run_directory / "evidence.jsonl",
        MAX_BENCHMARK_LEDGER_BYTES,
        f"trial {trial_id} evidence ledger",
    )
    scope_path = _regular_file(
        run_directory / "scope.json",
        MAX_BENCHMARK_CHECKPOINT_BYTES,
        f"trial {trial_id} scope manifest",
    )
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    if not isinstance(checkpoint, dict):
        raise ValueError("ledger checkpoint must be one JSON object")

    ledger = EvidenceLedger(ledger_path)
    sequence = ledger.verify_checkpoint(checkpoint_path)
    all_records = ledger.records()
    records = all_records[:sequence]
    scope_value = json.loads(scope_path.read_text(encoding="utf-8"))
    if not isinstance(scope_value, dict):
        raise ValueError("run scope manifest must be one JSON object")
    scope = ScopeManifest.from_dict(scope_value)
    validate_scope_against_ledger(scope, records)

    findings, replay_verified, semantic_violations = _checkpointed_findings(
        records, scope
    )
    supporting_evidence = {
        evidence_id
        for finding in findings.values()
        for evidence_id in finding.supporting_evidence
    }
    latest_full_replay: dict[str, str] = {}
    for record in all_records:
        payload = record["payload"]
        if payload.get("event") in {
            "evidence_verified",
            "evidence_replay_failed",
        }:
            latest_full_replay[str(payload["evidence_id"])] = str(payload["event"])
    post_checkpoint_invalidated = sorted(
        evidence_id
        for evidence_id in supporting_evidence
        if latest_full_replay.get(evidence_id) != "evidence_verified"
    )
    if post_checkpoint_invalidated:
        semantic_violations.append(
            f"trial {trial_id} checkpointed findings have evidence invalidated "
            "in the later ledger: "
            f"{post_checkpoint_invalidated}"
        )
    seal_sequence, seal_violations = _validate_trial_seal(records, trial, findings)
    semantic_violations.extend(seal_violations)
    claimed = {str(item["finding_id"]): item for item in trial["findings"]}
    checkpointed_ids = set(findings)
    claimed_ids = set(claimed)
    for finding_id in sorted(checkpointed_ids - claimed_ids):
        semantic_violations.append(
            f"trial {trial_id} omits checkpointed finding {finding_id}"
        )
    for finding_id in sorted(claimed_ids - checkpointed_ids):
        semantic_violations.append(
            f"trial {trial_id} finding {finding_id} is not confirmed in its "
            "checkpointed ledger"
        )

    matched_ids: list[str] = []
    for finding_id in sorted(claimed_ids & checkpointed_ids):
        claim = claimed[finding_id]
        recorded = findings[finding_id]
        matches = True
        if claim["severity"] != recorded.severity.value:
            semantic_violations.append(
                f"trial {trial_id} finding {finding_id} severity does not match "
                "its checkpointed finding"
            )
            matches = False
        if claim["evidence_level"] != recorded.evidence_level.value:
            semantic_violations.append(
                f"trial {trial_id} finding {finding_id} evidence level does not "
                "match its checkpointed finding"
            )
            matches = False
        if matches:
            matched_ids.append(finding_id)

    if not any(
        record["payload"].get("event") == "run_completed" for record in records
    ):
        semantic_violations.append(
            f"trial {trial_id} checkpoint does not contain a completed Nirvana run"
        )

    result = {
        "trial_id": trial_id,
        "run_id": run_id,
        "valid": not semantic_violations,
        "checkpoint_sha256": observed_checkpoint_sha256,
        "checkpoint_sequence": sequence,
        "checkpoint_record_hash": checkpoint["record_hash"],
        "trial_seal_sequence": seal_sequence,
        "externally_anchored": checkpoint.get("external_anchor") is not None,
        "checkpointed_finding_ids": sorted(checkpointed_ids),
        "matched_finding_ids": matched_ids,
        "replay_verified_evidence_ids": sorted(replay_verified),
        "post_checkpoint_invalidated_evidence_ids": post_checkpoint_invalidated,
        "violations": semantic_violations,
    }
    return result, semantic_violations


def _validate_trial_seal(
    records: list[dict[str, Any]],
    trial: dict[str, Any],
    findings: dict[str, Finding],
) -> tuple[int | None, list[str]]:
    trial_id = str(trial["trial_id"])
    matches = [
        record
        for record in records
        if record["payload"].get("event") == "benchmark_trial_sealed"
    ]
    if len(matches) != 1:
        return None, [
            f"trial {trial_id} checkpoint must contain exactly one benchmark trial seal"
        ]
    record = matches[0]
    seal = record["payload"]
    validate_contract(seal, "benchmark-trial-seal.schema.json")
    violations: list[str] = []
    expected_identity = {
        "trial_id": trial_id,
        "case_id": str(trial["case_id"]),
        "run_id": str(trial["run_id"]),
        "seed": trial["seed"],
    }
    observed_identity = {key: seal[key] for key in expected_identity}
    if observed_identity != expected_identity:
        violations.append(
            f"trial {trial_id} identity does not match its checkpointed trial seal"
        )
    if seal["ledger_sequence_before_seal"] != record["sequence"] - 1:
        violations.append(
            f"trial {trial_id} seal records an invalid ledger sequence"
        )
    completed_sequences = [
        item["sequence"]
        for item in records
        if item["payload"].get("event") == "run_completed"
    ]
    if not completed_sequences or min(completed_sequences) >= record["sequence"]:
        violations.append(
            f"trial {trial_id} was sealed before its run-completed event"
        )
    expected_claims = _finding_claims(findings)
    expected_digest = sha256_bytes(canonical_json(expected_claims).encode("utf-8"))
    if seal["findings"] != expected_claims:
        violations.append(
            f"trial {trial_id} checkpointed finding set does not match its trial seal"
        )
    if seal["finding_set_sha256"] != expected_digest:
        violations.append(
            f"trial {trial_id} trial-seal finding-set hash does not match the ledger"
        )
    return int(record["sequence"]), violations


def _finding_claims(findings: dict[str, Finding]) -> list[dict[str, str]]:
    return [
        {
            "finding_id": finding.finding_id,
            "severity": finding.severity.value,
            "evidence_level": finding.evidence_level.value,
        }
        for finding in sorted(findings.values(), key=lambda item: item.finding_id)
    ]


def _checkpointed_findings(
    records: list[dict[str, Any]], scope: ScopeManifest
) -> tuple[dict[str, Finding], set[str], list[str]]:
    evidence: dict[str, EvidenceRecord] = {}
    latest_replay: dict[str, str] = {}
    findings: dict[str, Finding] = {}
    verified_at_confirmation: dict[str, set[str]] = {}
    ceiling_at_confirmation: dict[str, EvidenceLevel] = {}
    current_ceiling = EvidenceLevel(
        next(
            record["payload"]["scope"]["evidence_ceiling"]
            for record in records
            if record["payload"].get("event") == "scope_captured"
        )
    )

    for record in records:
        payload = record["payload"]
        event = payload.get("event")
        if event == "evidence_recorded":
            item = EvidenceRecord.from_dict(payload["evidence"])
            if item.evidence_id in evidence:
                raise ValueError(
                    f"duplicate checkpointed evidence record: {item.evidence_id}"
                )
            evidence[item.evidence_id] = item
        elif event in {"evidence_verified", "evidence_replay_failed"}:
            latest_replay[str(payload["evidence_id"])] = str(event)
        elif event == "evidence_ceiling_raised":
            current_ceiling = EvidenceLevel(payload["current"])
        elif event == "finding_confirmed":
            item = Finding.from_dict(payload["finding"])
            if item.finding_id in findings:
                raise ValueError(
                    f"duplicate checkpointed finding: {item.finding_id}"
                )
            findings[item.finding_id] = item
            verified_at_confirmation[item.finding_id] = {
                evidence_id
                for evidence_id, status in latest_replay.items()
                if status == "evidence_verified"
            }
            ceiling_at_confirmation[item.finding_id] = current_ceiling

    currently_verified = {
        evidence_id
        for evidence_id, status in latest_replay.items()
        if status == "evidence_verified"
    }
    violations: list[str] = []
    for finding_id, finding in findings.items():
        supporting = set(finding.supporting_evidence)
        unknown = sorted(supporting - evidence.keys())
        if unknown:
            violations.append(
                f"checkpointed finding {finding_id} references unknown evidence: {unknown}"
            )
            continue
        not_verified_when_confirmed = sorted(
            supporting - verified_at_confirmation[finding_id]
        )
        if not_verified_when_confirmed:
            violations.append(
                f"checkpointed finding {finding_id} was not backed by "
                "replay-verified evidence when confirmed: "
                f"{not_verified_when_confirmed}"
            )
        no_longer_verified = sorted(supporting - currently_verified)
        if no_longer_verified:
            violations.append(
                f"checkpointed finding {finding_id} is not backed by currently "
                f"replay-verified evidence: {no_longer_verified}"
            )
        maximum_support = max(
            (EVIDENCE_RANK[evidence[item].level] for item in supporting),
            default=0,
        )
        if maximum_support < EVIDENCE_RANK[finding.evidence_level]:
            violations.append(
                f"checkpointed finding {finding_id} exceeds its supporting evidence tier"
            )
        if EVIDENCE_RANK[ceiling_at_confirmation[finding_id]] < EVIDENCE_RANK[
            finding.evidence_level
        ]:
            violations.append(
                f"checkpointed finding {finding_id} exceeded the run evidence ceiling when confirmed"
            )
    if EVIDENCE_RANK[scope.evidence_ceiling] < max(
        (EVIDENCE_RANK[item.evidence_level] for item in findings.values()),
        default=0,
    ):
        violations.append(
            "checkpointed findings exceed the ledger-derived run evidence ceiling"
        )
    return findings, currently_verified, violations


def _relative_path(
    manifest_path: Path,
    value: str,
    *,
    kind: str,
    label: str,
    max_bytes: int = MAX_BENCHMARK_LEDGER_BYTES,
) -> Path:
    if not value:
        raise ValueError(f"{label} path must be a non-empty relative POSIX path")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or not relative.parts
        or value in {".", "./"}
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError(f"{label} path must stay inside the benchmark directory")

    current = manifest_path.resolve(strict=True).parent
    for part in relative.parts:
        current = current / part
        item_stat = current.lstat()
        if stat.S_ISLNK(item_stat.st_mode):
            raise ValueError(f"{label} path must not contain symlinks")
    if kind == "directory":
        if not current.is_dir():
            raise ValueError(f"{label} must be a directory")
        return current.resolve(strict=True)
    return _regular_file(current, max_bytes, label)


def _regular_file(path: Path, max_bytes: int, label: str) -> Path:
    item_stat = path.lstat()
    if (
        not stat.S_ISREG(item_stat.st_mode)
        or stat.S_ISLNK(item_stat.st_mode)
        or item_stat.st_size > max_bytes
    ):
        raise ValueError(
            f"{label} must be a regular non-symlink file no larger than {max_bytes} bytes"
        )
    return path.resolve(strict=True)


def _checkpoint_output(path: Path) -> Path:
    parent = path.parent.resolve(strict=True)
    parent_stat = parent.lstat()
    if not stat.S_ISDIR(parent_stat.st_mode) or stat.S_ISLNK(parent_stat.st_mode):
        raise ValueError("benchmark trial checkpoint parent must be a non-symlink directory")
    candidate = parent / path.name
    if candidate.exists() or candidate.is_symlink():
        candidate_stat = candidate.lstat()
        if not stat.S_ISREG(candidate_stat.st_mode) or stat.S_ISLNK(
            candidate_stat.st_mode
        ):
            raise ValueError(
                "benchmark trial checkpoint output must be a regular non-symlink file"
            )
    return candidate.resolve()
