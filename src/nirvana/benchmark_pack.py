from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from .contracts import validate_contract
from .util import (
    atomic_write_json,
    canonical_json,
    sha256_bytes,
    sha256_file,
    utc_now,
)
from .verification import snapshot_harness


MAX_PACK_BYTES = 256 * 1024 * 1024
MAX_PACK_ARTIFACT_BYTES = 100 * 1024 * 1024
TARGET_SNAPSHOT_ALGORITHM = "nirvana-regular-file-tree-v1"
GROUND_TRUTH_COMMITMENT_ALGORITHM = "sha256-canonical-ground-truth-v1"


def benchmark_target_snapshot(target_path: Path) -> dict[str, Any]:
    snapshot = snapshot_harness(target_path)
    report = {
        "schema_version": "1.0.0",
        "algorithm": TARGET_SNAPSHOT_ALGORITHM,
        "target_snapshot_sha256": snapshot.snapshot_sha256,
        "file_count": snapshot.file_count,
        "total_bytes": snapshot.total_bytes,
    }
    validate_contract(report, "benchmark-target-snapshot.schema.json")
    return report


def canonical_ground_truth_document(
    case_id: str, eligible: bool, ground_truth: list[Any]
) -> dict[str, Any]:
    document = {
        "schema_version": "1.0.0",
        "case_id": case_id,
        "eligible": eligible,
        "classification": "vulnerable" if ground_truth else "benign",
        "ground_truth": ground_truth,
    }
    validate_contract(document, "benchmark-ground-truth.schema.json")
    _validate_ground_truth_document(document)
    return document


def ground_truth_commitment_sha256(document: dict[str, Any]) -> str:
    validate_contract(document, "benchmark-ground-truth.schema.json")
    _validate_ground_truth_document(document)
    return sha256_bytes(canonical_json(document).encode("utf-8"))


def write_ground_truth_commitment(
    ground_truth_path: Path, output: Path
) -> dict[str, Any]:
    resolved = _regular_input(
        ground_truth_path,
        MAX_PACK_ARTIFACT_BYTES,
        "benchmark ground-truth reveal",
    )
    document = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("benchmark ground-truth reveal must be one JSON object")
    resolved_output = output.resolve()
    if resolved_output == resolved:
        raise ValueError("ground-truth commitment output must not overwrite the reveal")
    commitment = {
        "schema_version": "1.0.0",
        "algorithm": GROUND_TRUTH_COMMITMENT_ALGORITHM,
        "case_id": document.get("case_id"),
        "public_commitment_sha256": ground_truth_commitment_sha256(document),
    }
    validate_contract(commitment, "benchmark-ground-truth-commitment.schema.json")
    atomic_write_json(resolved_output, commitment)
    return commitment


def verify_case_pack(pack_path: Path) -> dict[str, Any]:
    resolved = _regular_input(pack_path, MAX_PACK_BYTES, "benchmark case pack")
    pack = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(pack, dict):
        raise ValueError("benchmark case pack must be one JSON object")
    validate_contract(pack, "benchmark-case-pack.schema.json")
    if pack["target_snapshot_algorithm"] != TARGET_SNAPSHOT_ALGORITHM:
        raise ValueError("benchmark case pack selects an unsupported target snapshot algorithm")
    if pack["ground_truth_commitment_algorithm"] != GROUND_TRUTH_COMMITMENT_ALGORITHM:
        raise ValueError("benchmark case pack selects an unsupported ground-truth commitment algorithm")

    root = resolved.parent
    attestation = pack["author_attestation"]
    attestation_path = _pack_path(
        root,
        attestation["artifact_path"],
        kind="file",
        label="author attestation",
    )
    if sha256_file(attestation_path) != attestation["artifact_sha256"]:
        raise ValueError("benchmark case-pack author attestation hash mismatch")

    cutoff = _date(pack["cutoff"])
    created_at = _date(pack["created_at"])
    if created_at <= cutoff:
        raise ValueError("benchmark case pack must be created after its cutoff")

    case_ids: set[str] = set()
    verified_cases: list[dict[str, Any]] = []
    for case in pack["cases"]:
        case_id = str(case["case_id"])
        if case_id in case_ids:
            raise ValueError(f"duplicate benchmark case-pack case: {case_id}")
        case_ids.add(case_id)
        if _date(case["originated_at"]) <= cutoff:
            raise ValueError(f"case-pack case {case_id} does not originate after cutoff")

        target = _pack_path(
            root,
            case["target_path"],
            kind="directory",
            label=f"case {case_id} target",
        )
        target_snapshot = benchmark_target_snapshot(target)
        if target_snapshot["target_snapshot_sha256"] != case["target_snapshot_sha256"]:
            raise ValueError(f"case-pack target snapshot hash mismatch: {case_id}")

        commitment = _pack_path(
            root,
            case["public_commitment_path"],
            kind="file",
            label=f"case {case_id} public commitment",
        )
        if sha256_file(commitment) != case["public_commitment_artifact_sha256"]:
            raise ValueError(f"case-pack public commitment artifact hash mismatch: {case_id}")
        commitment_document = _load_public_commitment(commitment)
        if commitment_document["case_id"] != case_id:
            raise ValueError(f"case-pack public commitment case id mismatch: {case_id}")
        if (
            commitment_document["public_commitment_sha256"]
            != case["public_commitment_sha256"]
        ):
            raise ValueError(f"case-pack public commitment value mismatch: {case_id}")

        sealed_ground_truth = _pack_path(
            root,
            case["sealed_ground_truth_path"],
            kind="file",
            label=f"case {case_id} sealed ground truth",
        )
        if sealed_ground_truth == commitment:
            raise ValueError(
                f"case-pack public commitment and sealed ground truth must differ: {case_id}"
            )
        if sealed_ground_truth == target or target in sealed_ground_truth.parents:
            raise ValueError(
                f"case-pack sealed ground truth must stay outside the trial target: {case_id}"
            )
        if sha256_file(sealed_ground_truth) != case["sealed_ground_truth_sha256"]:
            raise ValueError(f"case-pack sealed ground-truth hash mismatch: {case_id}")
        _verify_sealed_envelope(
            sealed_ground_truth,
            str(pack["ground_truth_sealing"]["method"]),
            case_id,
        )

        verified_cases.append(
            {
                "case_id": case_id,
                "originated_at": case["originated_at"],
                "target_snapshot_sha256": target_snapshot["target_snapshot_sha256"],
                "public_commitment_sha256": case["public_commitment_sha256"],
                "public_commitment_artifact_sha256": case[
                    "public_commitment_artifact_sha256"
                ],
                "sealed_ground_truth_sha256": case["sealed_ground_truth_sha256"],
            }
        )

    report = {
        "schema_version": "1.1.0",
        "created_at": utc_now(),
        "pack_id": pack["pack_id"],
        "case_pack_sha256": sha256_file(resolved),
        "cutoff": pack["cutoff"],
        "valid": True,
        "independent": attestation["independent_from_trial_operator"] is True,
        "target_snapshot_algorithm": pack["target_snapshot_algorithm"],
        "ground_truth_commitment_algorithm": pack[
            "ground_truth_commitment_algorithm"
        ],
        "ground_truth_sealing": dict(pack["ground_truth_sealing"]),
        "author_attestation": {
            "author_id": attestation["author_id"],
            "custody_model": attestation["custody_model"],
            "artifact_sha256": attestation["artifact_sha256"],
        },
        "generator": dict(pack["generator"]),
        "case_count": len(verified_cases),
        "case_ids": sorted(case_ids),
        "cases": verified_cases,
    }
    validate_contract(report, "benchmark-case-pack-report.schema.json")
    return report


def write_case_pack_report(pack_path: Path, output: Path) -> dict[str, Any]:
    report = verify_case_pack(pack_path)
    atomic_write_json(output.resolve(), report)
    return report


def resolve_case_pack_reference(manifest_path: Path, relative_path: str) -> Path:
    return _pack_path(
        manifest_path.resolve(strict=True).parent,
        relative_path,
        kind="file",
        label="benchmark case pack",
        max_bytes=MAX_PACK_BYTES,
    )


def _pack_path(
    root: Path,
    value: str,
    *,
    kind: str,
    label: str,
    max_bytes: int = MAX_PACK_ARTIFACT_BYTES,
) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} path must be a non-empty relative POSIX path")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or not relative.parts
        or value in {".", "./"}
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError(f"{label} path must stay inside the case pack")

    current = root.resolve(strict=True)
    for part in relative.parts:
        current = current / part
        item_stat = current.lstat()
        if stat.S_ISLNK(item_stat.st_mode):
            raise ValueError(f"{label} path must not contain symlinks")

    if kind == "directory":
        if not current.is_dir():
            raise ValueError(f"{label} must be a directory")
        return current.resolve(strict=True)
    return _regular_input(current, max_bytes, label)


def _regular_input(path: Path, max_bytes: int, label: str) -> Path:
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


def _verify_sealed_envelope(path: Path, method: str, case_id: str) -> None:
    with path.open("rb") as stream:
        prefix = stream.read(128)
    if method == "age":
        valid = prefix.startswith(b"age-encryption.org/v1") or prefix.startswith(
            b"-----BEGIN AGE ENCRYPTED FILE-----"
        )
    elif method == "openpgp":
        valid = prefix.startswith(b"-----BEGIN PGP MESSAGE-----") or bool(
            prefix and prefix[0] & 0x80
        )
    else:
        valid = False
    if not valid:
        raise ValueError(
            f"case-pack sealed ground truth does not match its declared {method} "
            f"envelope: {case_id}"
        )


def _load_public_commitment(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("benchmark public commitment must be one JSON object")
    validate_contract(value, "benchmark-ground-truth-commitment.schema.json")
    if value["algorithm"] != GROUND_TRUTH_COMMITMENT_ALGORITHM:
        raise ValueError("benchmark public commitment selects an unsupported algorithm")
    return value


def _validate_ground_truth_document(document: dict[str, Any]) -> None:
    ground_truth = document["ground_truth"]
    expected_classification = "vulnerable" if ground_truth else "benign"
    if document["classification"] != expected_classification:
        raise ValueError(
            "benchmark ground-truth classification does not match its vulnerability list"
        )
    vulnerability_ids: set[str] = set()
    for vulnerability in ground_truth:
        vulnerability_id = str(vulnerability["vulnerability_id"])
        if vulnerability_id in vulnerability_ids:
            raise ValueError(
                f"duplicate benchmark ground-truth vulnerability id: {vulnerability_id}"
            )
        vulnerability_ids.add(vulnerability_id)


def _date(value: str) -> datetime:
    normalized = str(value).replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
