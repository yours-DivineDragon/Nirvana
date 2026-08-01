from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .policy import CommandResult, CommandRunner
from .util import canonical_json, jsonable, sha256_bytes, utc_now


MAX_STDIN_BYTES = 1_000_000
MAX_RECEIPT_BYTES = 5_000_000


@dataclass(frozen=True, slots=True)
class ExecutionRequest:
    evidence_id: str
    hypothesis_id: str
    kind: str
    summary: str
    command: list[str]
    cwd: str = "."
    stdin: str = ""
    expected_return_codes: list[int] = field(default_factory=lambda: [0])
    tool_version: str | None = None
    assumptions: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ExecutionRequest":
        allowed = {
            "evidence_id",
            "hypothesis_id",
            "kind",
            "summary",
            "command",
            "cwd",
            "stdin",
            "expected_return_codes",
            "tool_version",
            "assumptions",
        }
        unknown = value.keys() - allowed
        if unknown:
            raise ValueError(f"execution request has unknown fields: {sorted(unknown)}")
        required = {"evidence_id", "hypothesis_id", "kind", "summary", "command"}
        missing = required - value.keys()
        if missing:
            raise ValueError(f"execution request lacks required fields: {sorted(missing)}")
        evidence_id = str(value["evidence_id"])
        hypothesis_id = str(value["hypothesis_id"])
        if re.fullmatch(r"E-[A-Za-z0-9._-]+", evidence_id) is None:
            raise ValueError("execution evidence identifier must start with E-")
        if re.fullmatch(r"H-[A-Za-z0-9._-]+", hypothesis_id) is None:
            raise ValueError("execution hypothesis identifier must start with H-")
        command = value["command"]
        if not isinstance(command, list) or not command:
            raise ValueError("execution command must be a non-empty string array")
        if any(not isinstance(part, str) or not part or "\x00" in part for part in command):
            raise ValueError("execution command contains an invalid argument")
        expected = value.get("expected_return_codes", [0])
        if not isinstance(expected, list) or not expected:
            raise ValueError("expected_return_codes must be a non-empty integer array")
        if any(isinstance(item, bool) or not isinstance(item, int) for item in expected):
            raise ValueError("expected_return_codes must contain only integers")
        standard_input = value.get("stdin", "")
        if not isinstance(standard_input, str):
            raise ValueError("execution stdin must be a string")
        if len(standard_input.encode("utf-8")) > MAX_STDIN_BYTES:
            raise ValueError("execution stdin exceeds the 1 MB safety limit")
        cwd = str(value.get("cwd", "."))
        if not cwd or "\x00" in cwd or Path(cwd).is_absolute():
            raise ValueError("execution cwd must be a relative path")
        kind = str(value["kind"])
        summary = str(value["summary"])
        if not kind.strip() or not summary.strip():
            raise ValueError("execution kind and summary are required")
        assumptions = value.get("assumptions", [])
        if not isinstance(assumptions, list) or any(not isinstance(item, str) for item in assumptions):
            raise ValueError("execution assumptions must be a string array")
        tool_version = value.get("tool_version")
        if tool_version is not None and not isinstance(tool_version, str):
            raise ValueError("execution tool_version must be a string or null")
        return cls(
            evidence_id=evidence_id,
            hypothesis_id=hypothesis_id,
            kind=kind,
            summary=summary,
            command=list(command),
            cwd=cwd,
            stdin=standard_input,
            expected_return_codes=list(expected),
            tool_version=tool_version,
            assumptions=list(assumptions),
        )

    def to_dict(self) -> dict[str, Any]:
        return jsonable(self)


def resolve_execution_cwd(target_root: Path, relative: str) -> Path:
    root = target_root.resolve(strict=True)
    candidate = (root / relative).resolve(strict=True)
    if candidate != root and root not in candidate.parents:
        raise ValueError("execution cwd escapes the audited target")
    if not candidate.is_dir():
        raise ValueError("execution cwd is not a directory")
    return candidate


def policy_sha256(runner: CommandRunner) -> str:
    return sha256_bytes(canonical_json(runner.policy).encode("utf-8"))


def result_is_accepted(result: CommandResult, expected_return_codes: list[int]) -> bool:
    return (
        result.blocked_reason is None
        and not result.timed_out
        and result.return_code in expected_return_codes
    )


def result_signature(result: CommandResult) -> dict[str, Any]:
    return {
        "return_code": result.return_code,
        "stdout_sha256": sha256_bytes(result.stdout),
        "stderr_sha256": sha256_bytes(result.stderr),
        "blocked_reason": result.blocked_reason,
        "timed_out": result.timed_out,
    }


def execution_receipt(
    request: ExecutionRequest,
    runner: CommandRunner,
    result: CommandResult,
    target_root: Path,
    target_snapshot_sha256: str,
    replay_of: str | None = None,
) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "schema_version": "1.0.0",
        "created_at": utc_now(),
        "evidence_id": request.evidence_id,
        "target": {
            "root": str(target_root),
            "snapshot_sha256": target_snapshot_sha256,
        },
        "runner": {
            "mode": runner.mode.value,
            "policy_sha256": policy_sha256(runner),
            "docker_image": runner.policy.docker_image,
        },
        "request": {
            **request.to_dict(),
            "stdin_base64": base64.b64encode(request.stdin.encode("utf-8")).decode("ascii"),
            "stdin_sha256": sha256_bytes(request.stdin.encode("utf-8")),
        },
        "result": {
            **result_signature(result),
            "command": list(result.command),
            "stdout_base64": base64.b64encode(result.stdout).decode("ascii"),
            "stderr_base64": base64.b64encode(result.stderr).decode("ascii"),
            "duration_ms": result.duration_ms,
        },
    }
    receipt["request"].pop("stdin", None)
    if replay_of is not None:
        receipt["replay_of"] = replay_of
    return receipt


def request_from_receipt(receipt: dict[str, Any]) -> ExecutionRequest:
    try:
        request = dict(receipt["request"])
        encoded_stdin = str(request.pop("stdin_base64"))
        expected_stdin_hash = str(request.pop("stdin_sha256"))
        stdin_bytes = base64.b64decode(encoded_stdin, validate=True)
        if sha256_bytes(stdin_bytes) != expected_stdin_hash:
            raise ValueError("execution receipt stdin hash does not match")
        request["stdin"] = stdin_bytes.decode("utf-8")
    except (KeyError, TypeError, ValueError, UnicodeDecodeError) as error:
        raise ValueError(f"execution receipt has an invalid request: {error}") from error
    return ExecutionRequest.from_dict(request)


def load_receipt(path: Path) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    if resolved.stat().st_size > MAX_RECEIPT_BYTES:
        raise ValueError("execution receipt exceeds the 5 MB safety limit")
    value = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("execution receipt must contain one JSON object")
    return value
