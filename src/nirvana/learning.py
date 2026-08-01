from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .contracts import validate_contract
from .ledger import EvidenceLedger
from .util import atomic_write_json, sha256_file, utc_now


PROMOTION_GATES = (
    "positive_regression",
    "negative_benign_cases",
    "cross_project_generalisation",
    "performance_noise_budget",
    "human_review",
    "provenance_licence",
)


def review_detector_candidate(
    run_directory: Path, review_path: Path
) -> dict[str, Any]:
    run_root = run_directory.resolve(strict=True)
    ledger = EvidenceLedger(run_root / "evidence.jsonl")
    records = ledger.records()
    ledger.verify()
    resolved = review_path.resolve(strict=True)
    review = json.loads(resolved.read_text(encoding="utf-8"))
    validate_contract(review, "detector-review.schema.json")
    finding_id = str(review["finding_id"])
    bundles = [
        record["payload"]
        for record in records
        if record["payload"].get("event") == "learning_bundle_created"
        and record["payload"].get("finding_id") == finding_id
    ]
    if len(bundles) != 1:
        raise ValueError(f"detector review requires one learning bundle: {finding_id}")
    bundle_path = Path(str(bundles[0]["artifact_path"])).resolve(strict=True)
    if sha256_file(bundle_path) != bundles[0]["artifact_sha256"]:
        raise ValueError("learning bundle does not match the evidence ledger")
    for artifact in review["evidence_artifacts"]:
        if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256"}:
            raise ValueError("review evidence artifacts require only path and sha256")
        artifact_path = Path(str(artifact["path"])).resolve(strict=True)
        if sha256_file(artifact_path) != artifact["sha256"]:
            raise ValueError(f"detector review artifact hash mismatch: {artifact_path}")
    promoted = all(review[gate] is True for gate in PROMOTION_GATES)
    outcome = {
        "schema_version": "1.0.0",
        "created_at": utc_now(),
        "finding_id": finding_id,
        "learning_bundle_sha256": bundles[0]["artifact_sha256"],
        "review_sha256": sha256_file(resolved),
        "reviewer": review["reviewer"],
        "gates": {gate: review[gate] for gate in PROMOTION_GATES},
        "evidence_artifacts": review["evidence_artifacts"],
        "notes": review["notes"],
        "status": "promoted" if promoted else "rejected",
        "scope": "run-local detector candidate; production source is never modified automatically",
    }
    validate_contract(outcome, "detector-outcome.schema.json")
    output = run_root / "learning" / f"{finding_id}-detector-review.json"
    atomic_write_json(output, outcome)
    ledger.append(
        {
            "event": "detector_promoted" if promoted else "detector_rejected",
            "finding_id": finding_id,
            "artifact_path": str(output),
            "artifact_sha256": sha256_file(output),
            "reviewer": review["reviewer"],
            "scope": outcome["scope"],
        }
    )
    from .workflow import refresh_report

    refresh_report(run_root)
    return outcome
