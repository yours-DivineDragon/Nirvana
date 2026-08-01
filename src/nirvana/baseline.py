from __future__ import annotations

import base64
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .contracts import validate_contract
from .intake import RepositoryIntake, ScopeManifest, validate_scope_against_ledger
from .ledger import EvidenceLedger
from .policy import CommandRunner, ExecutionMode
from .util import atomic_write_json, canonical_json, jsonable, sha256_bytes, sha256_file, utc_now
from .verification import policy_sha256, resolve_execution_cwd


@dataclass(frozen=True, slots=True)
class BaselineStep:
    step_id: str
    kind: str
    command: list[str]
    cwd: str
    expected_return_code: int


@dataclass(frozen=True, slots=True)
class BaselineRequest:
    schema_version: str
    steps: list[BaselineStep]

    @classmethod
    def from_path(cls, path: Path) -> "BaselineRequest":
        value = json.loads(path.resolve(strict=True).read_text(encoding="utf-8"))
        validate_contract(value, "baseline-request.schema.json")
        steps = [BaselineStep(**item) for item in value["steps"]]
        if len({item.step_id for item in steps}) != len(steps):
            raise ValueError("baseline step identifiers must be unique")
        for step in steps:
            if re.fullmatch(r"B-[A-Za-z0-9._-]+", step.step_id) is None:
                raise ValueError("baseline step identifier must start with B-")
            if step.expected_return_code != 0:
                raise ValueError("build and test baselines must require a successful zero exit")
        return cls(str(value["schema_version"]), steps)


@dataclass(slots=True)
class BaselineReceipt:
    schema_version: str
    created_at: str
    target_snapshot_sha256: str
    runner: dict[str, Any]
    steps: list[dict[str, Any]]
    build_status: str
    test_status: str
    discovered_artifacts: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        value = jsonable(self)
        validate_contract(value, "baseline-receipt.schema.json")
        return value


def run_baseline(
    run_directory: Path,
    request_path: Path,
    runner: CommandRunner,
) -> BaselineReceipt:
    if runner.mode is not ExecutionMode.DOCKER:
        raise ValueError("repository build and test baselines require digest-pinned Docker execution")
    run_root = run_directory.resolve(strict=True)
    ledger = EvidenceLedger(run_root / "evidence.jsonl")
    records = ledger.records()
    ledger.verify()
    scope_value = json.loads((run_root / "scope.json").read_text(encoding="utf-8"))
    scope = validate_scope_against_ledger(ScopeManifest.from_dict(scope_value), records)
    request = BaselineRequest.from_path(request_path)
    allowed = {
        "build": {tuple(item) for item in scope.build_plan},
        "test": {tuple(item) for item in scope.test_plan},
    }
    for step in request.steps:
        if tuple(step.command) not in allowed[step.kind]:
            raise ValueError(
                f"baseline step {step.step_id} is not an intake-detected {step.kind} command"
            )
    target = Path(scope.target_root).resolve(strict=True)
    _require_snapshot(scope, target)
    results: list[dict[str, Any]] = []
    generated_artifacts: list[dict[str, Any]] = []
    for step in request.steps:
        cwd = resolve_execution_cwd(target, step.cwd)
        artifact_directory = run_root / "baseline" / "artifacts" / step.step_id
        artifact_directory.mkdir(parents=True, exist_ok=False)
        artifact_directory.chmod(0o777)
        result = runner.run(
            step.command,
            cwd,
            artifact_directory=artifact_directory,
        )
        step_artifacts = _snapshot_artifacts(artifact_directory, step.step_id)
        artifact_directory.chmod(0o700)
        generated_artifacts.extend(step_artifacts)
        accepted = (
            result.blocked_reason is None
            and not result.timed_out
            and result.return_code == step.expected_return_code
        )
        results.append(
            {
                "step_id": step.step_id,
                "kind": step.kind,
                "command": list(step.command),
                "cwd": step.cwd,
                "expected_return_code": step.expected_return_code,
                "accepted": accepted,
                "return_code": result.return_code,
                "blocked_reason": result.blocked_reason,
                "timed_out": result.timed_out,
                "duration_ms": result.duration_ms,
                "stdout_sha256": sha256_bytes(result.stdout),
                "stderr_sha256": sha256_bytes(result.stderr),
                "stdout_base64": base64.b64encode(result.stdout).decode("ascii"),
                "stderr_base64": base64.b64encode(result.stderr).decode("ascii"),
                "generated_artifacts": step_artifacts,
            }
        )
        _require_snapshot(scope, target)
    receipt = BaselineReceipt(
        schema_version="1.0.0",
        created_at=utc_now(),
        target_snapshot_sha256=scope.target_snapshot_sha256,
        runner={
            "mode": runner.mode.value,
            "docker_image": runner.policy.docker_image,
            "policy_sha256": policy_sha256(runner),
        },
        steps=results,
        build_status=_aggregate_status("build", results),
        test_status=_aggregate_status("test", results),
        discovered_artifacts=list(scope.discovered_artifacts) + generated_artifacts,
    )
    receipt_path = run_root / "baseline" / "receipt.json"
    atomic_write_json(receipt_path, receipt)
    digest = sha256_file(receipt_path)
    ledger.append(
        {
            "event": "baseline_executed",
            "target_snapshot_sha256": scope.target_snapshot_sha256,
            "build_status": receipt.build_status,
            "test_status": receipt.test_status,
            "artifact_path": str(receipt_path),
            "artifact_sha256": digest,
            "request_sha256": sha256_file(request_path.resolve(strict=True)),
        }
    )
    # Import lazily to keep the workflow module free of an intake/baseline cycle.
    from .workflow import refresh_report

    refresh_report(run_root)
    return receipt


def _aggregate_status(kind: str, results: list[dict[str, Any]]) -> str:
    selected = [item for item in results if item["kind"] == kind]
    if not selected:
        return "not_selected"
    return "passed" if all(item["accepted"] for item in selected) else "failed"


def _require_snapshot(scope: ScopeManifest, target: Path) -> None:
    current = RepositoryIntake(
        max_file_bytes=scope.max_analysis_file_bytes,
        ignored_directories=frozenset(scope.excluded_directories),
    ).inspect(target)
    if current.target_snapshot_sha256 != scope.target_snapshot_sha256:
        raise ValueError("baseline execution changed the audited target snapshot")


def _snapshot_artifacts(root: Path, step_id: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    total = 0
    for current_root, directories, filenames in os.walk(root, followlinks=False):
        current = Path(current_root)
        for name in directories:
            if (current / name).is_symlink():
                raise ValueError("baseline artifact output contains a symlink directory")
        directories[:] = sorted(directories)
        for name in sorted(filenames):
            path = current / name
            item_stat = path.lstat()
            if not stat.S_ISREG(item_stat.st_mode) or path.is_symlink():
                raise ValueError("baseline artifact output may contain regular files only")
            total += item_stat.st_size
            if len(records) >= 4_096 or total > 500_000_000:
                raise ValueError("baseline artifact output exceeds 4096 files or 500 MB")
            records.append(
                {
                    "step_id": step_id,
                    "path": path.relative_to(root).as_posix(),
                    "size": item_stat.st_size,
                    "sha256": sha256_file(path),
                    "kind": _artifact_kind(path),
                    "trusted_for_execution": False,
                }
            )
    return records


def _artifact_kind(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".abi", ".bin", ".bytecode", ".hex"}:
        return "evm-artifact"
    if suffix in {".wasm", ".wat"}:
        return "wasm-artifact"
    if suffix in {".json"}:
        return "structured-build-artifact"
    return "generated-build-artifact"
