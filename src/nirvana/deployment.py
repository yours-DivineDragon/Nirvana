from __future__ import annotations

import json
import re
import stat
from pathlib import Path
from typing import Any

from .contracts import validate_contract
from .ledger import EvidenceLedger
from .util import atomic_write_json, sha256_bytes, sha256_file, utc_now


MAX_BYTECODE_BYTES = 20_000_000


def verify_deployments(
    run_directory: Path, attestation_path: Path
) -> dict[str, Any]:
    run_root = run_directory.resolve(strict=True)
    ledger = EvidenceLedger(run_root / "evidence.jsonl")
    ledger.verify()
    source = attestation_path.resolve(strict=True)
    value = json.loads(source.read_text(encoding="utf-8"))
    validate_contract(value, "deployment-attestation.schema.json")
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in value["entries"]:
        deployment_id = str(entry["deployment_id"])
        if deployment_id in seen:
            raise ValueError(f"duplicate deployment id: {deployment_id}")
        seen.add(deployment_id)
        built_input = Path(entry["built_bytecode_path"])
        deployed_input = Path(entry["deployed_bytecode_path"])
        if built_input.is_symlink() or deployed_input.is_symlink():
            raise ValueError("bytecode attestation inputs must not be symlinks")
        built_path = built_input.resolve(strict=True)
        deployed_path = deployed_input.resolve(strict=True)
        built = _read_bytecode(built_path)
        deployed = _read_bytecode(deployed_path)
        built_digest = sha256_bytes(built)
        deployed_digest = sha256_bytes(deployed)
        results.append(
            {
                "deployment_id": deployment_id,
                "source": entry["source"],
                "compiler_config_sha256": entry["compiler_config_sha256"],
                "network": entry["network"],
                "address": entry["address"],
                "capture_provenance": entry["capture_provenance"],
                "built_bytecode_path": str(built_path),
                "deployed_bytecode_path": str(deployed_path),
                "built_bytecode_sha256": built_digest,
                "deployed_bytecode_sha256": deployed_digest,
                "match": built_digest == deployed_digest,
            }
        )
    report = {
        "schema_version": "1.0.0",
        "created_at": utc_now(),
        "attestation_sha256": sha256_file(source),
        "entries": results,
        "all_match": all(item["match"] for item in results),
        "network_access_performed": False,
    }
    validate_contract(report, "deployment-report.schema.json")
    output = run_root / "deployment" / f"attestation-{report['attestation_sha256'][:16]}.json"
    atomic_write_json(output, report)
    ledger.append(
        {
            "event": "deployment_bytecode_verified",
            "artifact_path": str(output),
            "artifact_sha256": sha256_file(output),
            "attestation_sha256": report["attestation_sha256"],
            "all_match": report["all_match"],
            "entry_count": len(results),
            "network_access_performed": False,
        }
    )
    from .workflow import refresh_report

    refresh_report(run_root)
    return report


def _read_bytecode(path: Path) -> bytes:
    item_stat = path.lstat()
    if not stat.S_ISREG(item_stat.st_mode) or path.is_symlink():
        raise ValueError("bytecode attestation inputs must be regular, non-symlink files")
    if item_stat.st_size > MAX_BYTECODE_BYTES:
        raise ValueError("bytecode attestation input exceeds 20 MB")
    text = path.read_text(encoding="ascii").strip()
    compact = re.sub(r"\s+", "", text)
    if compact.startswith("0x"):
        compact = compact[2:]
    if not compact or len(compact) % 2 or re.fullmatch(r"[0-9a-fA-F]+", compact) is None:
        raise ValueError(f"bytecode input is not a canonical hexadecimal value: {path}")
    return bytes.fromhex(compact)
