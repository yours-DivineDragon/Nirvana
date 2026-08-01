from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from .contracts import validate_contract
from .models import EvidenceLevel
from .policy import CommandResult, CommandRunner
from .util import canonical_json, jsonable, sha256_bytes, utc_now


MAX_STDIN_BYTES = 1_000_000
MAX_RECEIPT_BYTES = 5_000_000
MAX_ASSERTION_PATTERN_BYTES = 4_096


class ReplayMode(StrEnum):
    ASSERTIONS = "assertions"
    STRICT = "strict"


class AssertionSource(StrEnum):
    STDOUT = "stdout"
    STDERR = "stderr"


class AssertionOperator(StrEnum):
    CONTAINS = "contains"
    REGEX = "regex"
    JSON_POINTER_EQUALS = "json_pointer_equals"


@dataclass(frozen=True, slots=True)
class ExecutionClaim:
    security_property: str
    suspected_violation: str

    @classmethod
    def from_dict(cls, value: Any) -> "ExecutionClaim":
        if not isinstance(value, dict):
            raise ValueError("execution claim must be an object")
        unknown = value.keys() - {"security_property", "suspected_violation"}
        if unknown:
            raise ValueError(f"execution claim has unknown fields: {sorted(unknown)}")
        missing = {"security_property", "suspected_violation"} - value.keys()
        if missing:
            raise ValueError(f"execution claim lacks required fields: {sorted(missing)}")
        security_property = str(value["security_property"])
        suspected_violation = str(value["suspected_violation"])
        if not security_property.strip() or not suspected_violation.strip():
            raise ValueError("execution claim fields must not be empty")
        return cls(security_property, suspected_violation)


@dataclass(frozen=True, slots=True)
class ExecutionAssertion:
    assertion_id: str
    source: AssertionSource
    operator: AssertionOperator
    value: Any
    pointer: str | None = None

    @classmethod
    def from_dict(cls, value: Any) -> "ExecutionAssertion":
        if not isinstance(value, dict):
            raise ValueError("execution assertion must be an object")
        allowed = {"assertion_id", "source", "operator", "value", "pointer"}
        unknown = value.keys() - allowed
        if unknown:
            raise ValueError(f"execution assertion has unknown fields: {sorted(unknown)}")
        missing = {"assertion_id", "source", "operator", "value"} - value.keys()
        if missing:
            raise ValueError(f"execution assertion lacks required fields: {sorted(missing)}")
        assertion_id = str(value["assertion_id"])
        if re.fullmatch(r"A-[A-Za-z0-9._-]+", assertion_id) is None:
            raise ValueError("execution assertion identifier must start with A-")
        source = AssertionSource(value["source"])
        operator = AssertionOperator(value["operator"])
        expected = value["value"]
        pointer = value.get("pointer")
        if operator in {AssertionOperator.CONTAINS, AssertionOperator.REGEX}:
            if not isinstance(expected, str) or not expected:
                raise ValueError(f"{operator.value} assertion value must be a non-empty string")
            if len(expected.encode("utf-8")) > MAX_ASSERTION_PATTERN_BYTES:
                raise ValueError("execution assertion pattern exceeds 4 KB")
            if pointer is not None:
                raise ValueError(f"{operator.value} assertions must not define a JSON pointer")
            if operator is AssertionOperator.REGEX:
                try:
                    re.compile(expected)
                except re.error as error:
                    raise ValueError(f"execution assertion regex is invalid: {error}") from error
        else:
            if not isinstance(pointer, str) or (pointer and not pointer.startswith("/")):
                raise ValueError("json_pointer_equals requires an RFC 6901 pointer")
        return cls(assertion_id, source, operator, expected, pointer)

    def to_dict(self) -> dict[str, Any]:
        return jsonable(self)


@dataclass(frozen=True, slots=True)
class ExecutionRequest:
    evidence_id: str
    hypothesis_id: str
    evidence_level: EvidenceLevel
    kind: str
    summary: str
    adapter: str
    claim: ExecutionClaim
    assertions: list[ExecutionAssertion]
    command: list[str]
    cwd: str = "."
    stdin: str = ""
    expected_return_codes: list[int] = field(default_factory=lambda: [0])
    replay_mode: ReplayMode = ReplayMode.ASSERTIONS
    tool_version: str | None = None
    assumptions: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ExecutionRequest":
        if not isinstance(value, dict):
            raise ValueError("execution request must be an object")
        validate_contract(value, "execution-request.schema.json")
        allowed = {
            "evidence_id",
            "hypothesis_id",
            "evidence_level",
            "kind",
            "summary",
            "adapter",
            "claim",
            "assertions",
            "command",
            "cwd",
            "stdin",
            "expected_return_codes",
            "replay_mode",
            "tool_version",
            "assumptions",
        }
        unknown = value.keys() - allowed
        if unknown:
            raise ValueError(f"execution request has unknown fields: {sorted(unknown)}")
        required = {
            "evidence_id",
            "hypothesis_id",
            "evidence_level",
            "kind",
            "summary",
            "adapter",
            "claim",
            "assertions",
            "command",
            "tool_version",
        }
        missing = required - value.keys()
        if missing:
            raise ValueError(f"execution request lacks required fields: {sorted(missing)}")
        evidence_id = str(value["evidence_id"])
        hypothesis_id = str(value["hypothesis_id"])
        if re.fullmatch(r"E-[A-Za-z0-9._-]+", evidence_id) is None:
            raise ValueError("execution evidence identifier must start with E-")
        if re.fullmatch(r"H-[A-Za-z0-9._-]+", hypothesis_id) is None:
            raise ValueError("execution hypothesis identifier must start with H-")
        evidence_level = EvidenceLevel(value["evidence_level"])
        if evidence_level not in {
            EvidenceLevel.STRUCTURALLY_CONFIRMED,
            EvidenceLevel.EXECUTABLE,
        }:
            raise ValueError("runner evidence level must be structurally_confirmed or executable")
        adapter = str(value["adapter"])
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", adapter) is None:
            raise ValueError("execution adapter must be a stable identifier")
        command = value["command"]
        if not isinstance(command, list) or not command:
            raise ValueError("execution command must be a non-empty string array")
        if any(not isinstance(part, str) or not part or "\x00" in part for part in command):
            raise ValueError("execution command contains an invalid argument")
        _validate_adapter_contract(adapter, command, evidence_level)
        expected = value.get("expected_return_codes", [0])
        if not isinstance(expected, list) or len(expected) != 1:
            raise ValueError("expected_return_codes must contain exactly one integer")
        if any(
            isinstance(item, bool) or not isinstance(item, int) or item < 0 or item > 255
            for item in expected
        ):
            raise ValueError("expected return code must be an integer from 0 through 255")
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
        raw_assertions = value["assertions"]
        if not isinstance(raw_assertions, list) or not raw_assertions:
            raise ValueError("execution request requires at least one checked assertion")
        assertions = [ExecutionAssertion.from_dict(item) for item in raw_assertions]
        assertion_ids = [item.assertion_id for item in assertions]
        if len(set(assertion_ids)) != len(assertion_ids):
            raise ValueError("execution assertion identifiers must be unique")
        assumptions = value.get("assumptions", [])
        if not isinstance(assumptions, list) or any(not isinstance(item, str) for item in assumptions):
            raise ValueError("execution assumptions must be a string array")
        tool_version = value.get("tool_version")
        if not isinstance(tool_version, str) or not tool_version.strip():
            raise ValueError("execution tool_version must be a non-empty string")
        return cls(
            evidence_id=evidence_id,
            hypothesis_id=hypothesis_id,
            evidence_level=evidence_level,
            kind=kind,
            summary=summary,
            adapter=adapter,
            claim=ExecutionClaim.from_dict(value["claim"]),
            assertions=assertions,
            command=list(command),
            cwd=cwd,
            stdin=standard_input,
            expected_return_codes=list(expected),
            replay_mode=ReplayMode(value.get("replay_mode", ReplayMode.ASSERTIONS.value)),
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


def evaluate_assertions(
    request: ExecutionRequest, result: CommandResult
) -> list[dict[str, Any]]:
    streams = {
        AssertionSource.STDOUT: result.stdout,
        AssertionSource.STDERR: result.stderr,
    }
    evaluations: list[dict[str, Any]] = []
    for assertion in request.assertions:
        passed = False
        observed_hash: str | None = None
        error: str | None = None
        try:
            text = streams[assertion.source].decode("utf-8")
            observed: Any = None
            if assertion.operator is AssertionOperator.CONTAINS:
                if assertion.value in text:
                    passed = True
                    observed = assertion.value
            elif assertion.operator is AssertionOperator.REGEX:
                match = re.search(assertion.value, text)
                if match is not None:
                    passed = True
                    observed = match.group(0)
            else:
                document = json.loads(text)
                observed = _resolve_json_pointer(document, assertion.pointer or "")
                passed = observed == assertion.value
            if observed is not None:
                observed_hash = sha256_bytes(canonical_json(observed).encode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            error = str(exc)
        evaluations.append(
            {
                "assertion_id": assertion.assertion_id,
                "passed": passed,
                "observed_sha256": observed_hash,
                "error": error,
            }
        )
    return evaluations


def result_is_accepted(
    result: CommandResult,
    expected_return_codes: list[int],
    assertion_results: list[dict[str, Any]],
) -> bool:
    return (
        result.blocked_reason is None
        and not result.timed_out
        and result.return_code in expected_return_codes
        and bool(assertion_results)
        and all(item.get("passed") is True for item in assertion_results)
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
    assertion_results: list[dict[str, Any]],
    target_root: Path,
    target_snapshot_sha256: str,
    replay_of: str | None = None,
) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "schema_version": "1.1.0",
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
            "assertions": assertion_results,
        },
    }
    receipt["request"].pop("stdin", None)
    if replay_of is not None:
        receipt["replay_of"] = replay_of
    validate_contract(receipt, "execution-receipt.schema.json")
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
    validate_contract(value, "execution-receipt.schema.json")
    return value


def _resolve_json_pointer(document: Any, pointer: str) -> Any:
    if pointer == "":
        return document
    current = document
    for raw_part in pointer[1:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            if not part.isdigit():
                raise TypeError("JSON pointer array segment is not an index")
            current = current[int(part)]
        elif isinstance(current, dict):
            current = current[part]
        else:
            raise TypeError("JSON pointer traverses a scalar value")
    return current


def _validate_adapter_contract(
    adapter: str, command: list[str], evidence_level: EvidenceLevel
) -> None:
    executable = Path(command[0]).name.lower()
    arguments = [item.lower() for item in command[1:]]
    executable_adapters: dict[str, bool] = {
        "forge-test": executable == "forge" and "test" in arguments,
        "echidna": executable in {"echidna", "echidna-test"},
        "medusa": executable == "medusa" and "fuzz" in arguments,
        "halmos": executable == "halmos",
        "cargo-test": executable == "cargo" and "test" in arguments,
        "pytest": executable in {"pytest", "py.test"}
        or (
            executable in {"python", "python3"}
            and len(arguments) >= 2
            and arguments[:2] == ["-m", "pytest"]
        ),
        "node-test": executable in {"npm", "pnpm", "yarn"} and "test" in arguments,
    }
    structural_adapters: dict[str, bool] = {
        "solc-ast": executable in {"solc", "solcjs"} and "--standard-json" in arguments,
        "slither": executable == "slither",
        "semgrep": executable == "semgrep",
    }
    if adapter in executable_adapters:
        if not executable_adapters[adapter]:
            raise ValueError(f"execution command does not match the {adapter} adapter")
        return
    if adapter in structural_adapters:
        if evidence_level is not EvidenceLevel.STRUCTURALLY_CONFIRMED:
            raise ValueError(f"{adapter} may mint structural evidence only")
        if not structural_adapters[adapter]:
            raise ValueError(f"execution command does not match the {adapter} adapter")
        return
    raise ValueError(f"unsupported execution adapter: {adapter}")
