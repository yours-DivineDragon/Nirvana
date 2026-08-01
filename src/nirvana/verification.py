from __future__ import annotations

import base64
import json
import os
import re
import stat
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from .contracts import validate_contract
from .models import EvidenceLevel
from .policy import CommandResult, CommandRunner
from .util import canonical_json, jsonable, sha256_bytes, sha256_file, utc_now


MAX_STDIN_BYTES = 1_000_000
MAX_RECEIPT_BYTES = 10_000_000
MAX_ASSERTION_PATTERN_BYTES = 4_096
MAX_ASSERTIONS = 16
MAX_HARNESS_FILES = 4_096
MAX_HARNESS_BYTES = 100_000_000
MAX_CONTROL_CHANGED_FILES = 64
ADAPTER_CONTRACT_VERSIONS = {
    "forge-test": 1,
    "echidna": 1,
    "medusa": 1,
    "halmos": 1,
    "cargo-test": 1,
    "pytest": 1,
    "node-test": 1,
    "solc-ast": 1,
    "slither": 1,
    "semgrep": 1,
}


class ReplayMode(StrEnum):
    ASSERTIONS = "assertions"
    STRICT = "strict"


class AssertionSource(StrEnum):
    STDOUT = "stdout"
    STDERR = "stderr"


class AssertionOperator(StrEnum):
    CONTAINS = "contains"
    JSON_POINTER_EQUALS = "json_pointer_equals"


class AdapterOutcome(StrEnum):
    SUCCESS = "success"
    TEST_FAILURE = "test_failure"
    INVALID = "invalid"


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
        if operator is AssertionOperator.CONTAINS:
            if not isinstance(expected, str) or not expected:
                raise ValueError(f"{operator.value} assertion value must be a non-empty string")
            if len(expected.encode("utf-8")) > MAX_ASSERTION_PATTERN_BYTES:
                raise ValueError("execution assertion pattern exceeds 4 KB")
            if pointer is not None:
                raise ValueError(f"{operator.value} assertions must not define a JSON pointer")
        else:
            if not isinstance(pointer, str) or (pointer and not pointer.startswith("/")):
                raise ValueError("json_pointer_equals requires an RFC 6901 pointer")
        return cls(assertion_id, source, operator, expected, pointer)

    def to_dict(self) -> dict[str, Any]:
        return jsonable(self)


@dataclass(frozen=True, slots=True)
class HarnessSpec:
    path: str

    @classmethod
    def from_dict(cls, value: Any) -> "HarnessSpec":
        if not isinstance(value, dict):
            raise ValueError("execution harness must be an object")
        unknown = value.keys() - {"path"}
        if unknown:
            raise ValueError(f"execution harness has unknown fields: {sorted(unknown)}")
        path = value.get("path")
        if not isinstance(path, str) or not path or "\x00" in path:
            raise ValueError("execution harness path must be a non-empty string")
        if not Path(path).is_absolute():
            raise ValueError("execution harness path must be absolute")
        return cls(path)

    def to_dict(self) -> dict[str, Any]:
        return jsonable(self)


@dataclass(frozen=True, slots=True)
class NegativeControlSpec:
    target_root: str
    changed_files: list[str]
    expected_return_codes: list[int]

    @classmethod
    def from_dict(cls, value: Any) -> "NegativeControlSpec":
        if not isinstance(value, dict):
            raise ValueError("negative control must be an object")
        allowed = {"target_root", "changed_files", "expected_return_codes"}
        unknown = value.keys() - allowed
        if unknown:
            raise ValueError(f"negative control has unknown fields: {sorted(unknown)}")
        missing = allowed - value.keys()
        if missing:
            raise ValueError(f"negative control lacks required fields: {sorted(missing)}")
        target_root = value["target_root"]
        if (
            not isinstance(target_root, str)
            or not target_root
            or "\x00" in target_root
            or not Path(target_root).is_absolute()
        ):
            raise ValueError("negative control target_root must be an absolute path")
        changed_files = value["changed_files"]
        if (
            not isinstance(changed_files, list)
            or not changed_files
            or len(changed_files) > MAX_CONTROL_CHANGED_FILES
            or any(not _safe_relative_path(item) for item in changed_files)
            or len(set(changed_files)) != len(changed_files)
        ):
            raise ValueError(
                "negative control changed_files must contain 1 through "
                f"{MAX_CONTROL_CHANGED_FILES} unique safe relative paths"
            )
        expected = value["expected_return_codes"]
        _validate_return_codes(expected, "negative control expected_return_codes")
        return cls(target_root, list(changed_files), list(expected))

    def to_dict(self) -> dict[str, Any]:
        return jsonable(self)


@dataclass(frozen=True, slots=True)
class HarnessSnapshot:
    root: str
    snapshot_sha256: str
    file_count: int
    total_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return jsonable(self)


@dataclass(slots=True)
class NegativeControlExecution:
    target_root: str
    snapshot_sha256: str
    changed_files: list[dict[str, str | None]]
    expected_return_codes: list[int]
    result: CommandResult
    adapter_outcome: AdapterOutcome
    assertion_results: list[dict[str, Any]]
    invariant_results: list[dict[str, Any]]

    def to_receipt(self) -> dict[str, Any]:
        return {
            "target": {
                "root": self.target_root,
                "snapshot_sha256": self.snapshot_sha256,
            },
            "changed_files": self.changed_files,
            "expected_return_codes": list(self.expected_return_codes),
            "result": _result_payload(
                self.result,
                self.adapter_outcome,
                self.assertion_results,
                self.invariant_results,
            ),
        }


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
    control_invariants: list[ExecutionAssertion]
    command: list[str]
    cwd: str = "."
    stdin: str = ""
    expected_return_codes: list[int] = field(default_factory=lambda: [0])
    replay_mode: ReplayMode = ReplayMode.ASSERTIONS
    tool_version: str | None = None
    assumptions: list[str] = field(default_factory=list)
    harness: HarnessSpec | None = None
    negative_control: NegativeControlSpec | None = None

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
            "control_invariants",
            "command",
            "cwd",
            "stdin",
            "expected_return_codes",
            "replay_mode",
            "tool_version",
            "assumptions",
            "harness",
            "negative_control",
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
        _validate_return_codes(expected, "expected_return_codes")
        _validate_adapter_return_codes(
            adapter, command, expected, "expected_return_codes"
        )
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
        if (
            not isinstance(raw_assertions, list)
            or not raw_assertions
            or len(raw_assertions) > MAX_ASSERTIONS
        ):
            raise ValueError(
                f"execution request requires 1 through {MAX_ASSERTIONS} checked assertions"
            )
        assertions = [ExecutionAssertion.from_dict(item) for item in raw_assertions]
        assertion_ids = [item.assertion_id for item in assertions]
        if len(set(assertion_ids)) != len(assertion_ids):
            raise ValueError("execution assertion identifiers must be unique")
        raw_control_invariants = value.get("control_invariants", [])
        if (
            not isinstance(raw_control_invariants, list)
            or len(raw_control_invariants) > MAX_ASSERTIONS
        ):
            raise ValueError(
                f"execution request allows at most {MAX_ASSERTIONS} control invariants"
            )
        if evidence_level is EvidenceLevel.EXECUTABLE and not raw_control_invariants:
            raise ValueError(
                "executable evidence requires at least one control invariant that passes "
                "on both the audited and patched targets"
            )
        if (
            evidence_level is EvidenceLevel.STRUCTURALLY_CONFIRMED
            and raw_control_invariants
        ):
            raise ValueError("control invariants apply to executable evidence only")
        control_invariants = [
            ExecutionAssertion.from_dict(item) for item in raw_control_invariants
        ]
        invariant_ids = [item.assertion_id for item in control_invariants]
        if len(set(invariant_ids)) != len(invariant_ids):
            raise ValueError("control invariant identifiers must be unique")
        overlapping_ids = sorted(set(assertion_ids) & set(invariant_ids))
        if overlapping_ids:
            raise ValueError(
                "control invariant identifiers must be distinct from exploit assertions: "
                f"{overlapping_ids}"
            )
        assumptions = value.get("assumptions", [])
        if not isinstance(assumptions, list) or any(not isinstance(item, str) for item in assumptions):
            raise ValueError("execution assumptions must be a string array")
        tool_version = value.get("tool_version")
        if not isinstance(tool_version, str) or not tool_version.strip():
            raise ValueError("execution tool_version must be a non-empty string")
        harness = (
            HarnessSpec.from_dict(value["harness"])
            if value.get("harness") is not None
            else None
        )
        negative_control = (
            NegativeControlSpec.from_dict(value["negative_control"])
            if value.get("negative_control") is not None
            else None
        )
        if (
            negative_control is not None
            and evidence_level is not EvidenceLevel.EXECUTABLE
        ):
            raise ValueError("negative controls apply to executable evidence only")
        if (
            evidence_level is EvidenceLevel.EXECUTABLE
            and negative_control is None
        ):
            raise ValueError(
                "executable evidence requires a patched-target negative control"
            )
        if negative_control is not None:
            _validate_adapter_return_codes(
                adapter,
                command,
                negative_control.expected_return_codes,
                "negative control expected_return_codes",
            )
        return cls(
            evidence_id=evidence_id,
            hypothesis_id=hypothesis_id,
            evidence_level=evidence_level,
            kind=kind,
            summary=summary,
            adapter=adapter,
            claim=ExecutionClaim.from_dict(value["claim"]),
            assertions=assertions,
            control_invariants=control_invariants,
            command=list(command),
            cwd=cwd,
            stdin=standard_input,
            expected_return_codes=list(expected),
            replay_mode=ReplayMode(value.get("replay_mode", ReplayMode.ASSERTIONS.value)),
            tool_version=tool_version,
            assumptions=list(assumptions),
            harness=harness,
            negative_control=negative_control,
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


def adapter_contract_id(adapter: str) -> str:
    try:
        version = ADAPTER_CONTRACT_VERSIONS[adapter]
    except KeyError as error:
        raise ValueError(f"unsupported execution adapter: {adapter}") from error
    return f"{adapter}@{version}"


def snapshot_harness(path: Path) -> HarnessSnapshot:
    root = path.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("execution harness is not a directory")
    records: list[dict[str, Any]] = []
    total_bytes = 0
    for current_root, directories, filenames in os.walk(root, followlinks=False):
        current = Path(current_root)
        for name in directories:
            directory = current / name
            if directory.is_symlink():
                raise ValueError("execution harness must not contain symlink directories")
        directories[:] = sorted(directories)
        for name in sorted(filenames):
            item = current / name
            item_stat = item.lstat()
            if not stat.S_ISREG(item_stat.st_mode) or item.is_symlink():
                raise ValueError("execution harness may contain regular files only")
            total_bytes += item_stat.st_size
            if len(records) >= MAX_HARNESS_FILES or total_bytes > MAX_HARNESS_BYTES:
                raise ValueError(
                    "execution harness exceeds the 4096-file or 100 MB safety limit"
                )
            records.append(
                {
                    "path": item.relative_to(root).as_posix(),
                    "size": item_stat.st_size,
                    "sha256": sha256_file(item),
                }
            )
    if not records:
        raise ValueError("execution harness must contain at least one regular file")
    return HarnessSnapshot(
        root=str(root),
        snapshot_sha256=sha256_bytes(canonical_json(records).encode("utf-8")),
        file_count=len(records),
        total_bytes=total_bytes,
    )


def evaluate_assertions(
    request: ExecutionRequest,
    result: CommandResult,
    assertions: list[ExecutionAssertion] | None = None,
) -> list[dict[str, Any]]:
    streams = {
        AssertionSource.STDOUT: result.stdout,
        AssertionSource.STDERR: result.stderr,
    }
    evaluations: list[dict[str, Any]] = []
    for assertion in request.assertions if assertions is None else assertions:
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
    adapter_outcome: AdapterOutcome,
    expected_return_codes: list[int],
    assertion_results: list[dict[str, Any]],
    invariant_results: list[dict[str, Any]] | None = None,
) -> bool:
    return (
        result.blocked_reason is None
        and not result.timed_out
        and adapter_outcome is not AdapterOutcome.INVALID
        and result.return_code in expected_return_codes
        and bool(assertion_results)
        and all(item.get("passed") is True for item in assertion_results)
        and all(
            item.get("passed") is True for item in (invariant_results or [])
        )
    )


def negative_control_is_accepted(
    result: CommandResult,
    adapter_outcome: AdapterOutcome,
    expected_return_codes: list[int],
    assertion_results: list[dict[str, Any]],
    invariant_results: list[dict[str, Any]],
) -> bool:
    return (
        result.blocked_reason is None
        and not result.timed_out
        and adapter_outcome is not AdapterOutcome.INVALID
        and result.return_code in expected_return_codes
        and bool(assertion_results)
        and all(item.get("error") is None for item in assertion_results)
        and any(item.get("passed") is not True for item in assertion_results)
        and bool(invariant_results)
        and all(item.get("passed") is True for item in invariant_results)
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
    control_invariant_results: list[dict[str, Any]],
    target_root: Path,
    target_snapshot_sha256: str,
    replay_of: str | None = None,
    harness_snapshot: HarnessSnapshot | None = None,
    negative_control: NegativeControlExecution | None = None,
) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "schema_version": "1.4.0",
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
            "adapter_contract": adapter_contract_id(request.adapter),
        },
        "harness": harness_snapshot.to_dict() if harness_snapshot is not None else None,
        "negative_control": (
            negative_control.to_receipt() if negative_control is not None else None
        ),
        "request": {
            **request.to_dict(),
            "stdin_base64": base64.b64encode(request.stdin.encode("utf-8")).decode("ascii"),
            "stdin_sha256": sha256_bytes(request.stdin.encode("utf-8")),
        },
        "result": _result_payload(
            result,
            classify_adapter_outcome(request, result),
            assertion_results,
            control_invariant_results,
        ),
    }
    receipt["request"].pop("stdin", None)
    if replay_of is not None:
        receipt["replay_of"] = replay_of
    validate_contract(receipt, "execution-receipt.schema.json")
    return receipt


def _result_payload(
    result: CommandResult,
    adapter_outcome: AdapterOutcome,
    assertion_results: list[dict[str, Any]],
    control_invariant_results: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        **result_signature(result),
        "adapter_outcome": adapter_outcome.value,
        "command": list(result.command),
        "stdout_base64": base64.b64encode(result.stdout).decode("ascii"),
        "stderr_base64": base64.b64encode(result.stderr).decode("ascii"),
        "duration_ms": result.duration_ms,
        "assertions": assertion_results,
        "control_invariants": control_invariant_results,
    }


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
        raise ValueError("execution receipt exceeds the 10 MB safety limit")
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


def _validate_return_codes(value: Any, label: str) -> None:
    if not isinstance(value, list) or len(value) != 1:
        raise ValueError(f"{label} must contain exactly one integer")
    if any(
        isinstance(item, bool) or not isinstance(item, int) or item < 0 or item > 255
        for item in value
    ):
        raise ValueError(f"{label} must contain an integer from 0 through 255")


def _validate_adapter_return_codes(
    adapter: str, command: list[str], value: list[int], label: str
) -> None:
    allowed: dict[str, set[int]] = {
        "forge-test": {0, 1},
        "echidna": {0, 1},
        "medusa": {0, 7},
        "halmos": {0, 1},
        "cargo-test": {0, 101},
        "pytest": {0, 1},
        "node-test": {0, 1},
    }
    if adapter not in allowed or value[0] in allowed[adapter]:
        pass
    else:
        if adapter == "pytest":
            raise ValueError(
                f"pytest {label} must be 0 or 1; collection, interruption, usage, "
                "and infrastructure exit states cannot prove a fix"
            )
        rendered = ", ".join(str(item) for item in sorted(allowed[adapter]))
        raise ValueError(
            f"{adapter} {label} must be one of {rendered}; "
            "other exit states represent unsupported or infrastructure outcomes"
        )

    executable = Path(command[0]).name.lower()
    arguments = [item.lower() for item in command[1:]]
    if adapter == "cargo-test" and value[0] == 101:
        if _option_value(arguments, "--message-format") != "json":
            raise ValueError(
                f"cargo-test {label} 101 requires --message-format=json so Nirvana "
                "can distinguish a test failure from a build or tool failure"
            )
    if adapter == "echidna" and value[0] == 1:
        if _option_value(arguments, "--format") != "json":
            raise ValueError(
                f"echidna {label} 1 requires --format=json so Nirvana can verify "
                "that a property, rather than the tool, failed"
            )
    if adapter == "node-test" and value[0] == 1:
        if executable != "node":
            raise ValueError(
                f"node-test {label} 1 requires native node --test; package-manager "
                "wrapper failures are ambiguous"
            )
        if _option_value(arguments, "--test-reporter") != "tap":
            raise ValueError(
                f"node-test {label} 1 requires --test-reporter=tap so Nirvana can "
                "verify that tests actually failed"
            )


def classify_adapter_outcome(
    request: ExecutionRequest, result: CommandResult
) -> AdapterOutcome:
    if (
        result.blocked_reason is not None
        or result.timed_out
        or result.return_code is None
    ):
        return AdapterOutcome.INVALID
    if result.return_code == 0:
        return AdapterOutcome.SUCCESS
    if request.evidence_level is EvidenceLevel.STRUCTURALLY_CONFIRMED:
        return AdapterOutcome.INVALID

    text = _combined_result_text(result)
    if request.adapter == "pytest" and result.return_code == 1:
        return AdapterOutcome.TEST_FAILURE
    if request.adapter == "medusa" and result.return_code == 7:
        return AdapterOutcome.TEST_FAILURE
    if request.adapter == "forge-test" and result.return_code == 1:
        if _summary_reports_failures(
            text,
            r"Suite result:\s*FAILED\.\s*\d+ passed;\s*(\d+) failed;",
        ):
            return AdapterOutcome.TEST_FAILURE
    if request.adapter == "cargo-test" and result.return_code == 101:
        if _cargo_build_succeeded(result.stdout) and _summary_reports_failures(
            text,
            r"test result:\s*FAILED\.\s*\d+ passed;\s*(\d+) failed;",
        ):
            return AdapterOutcome.TEST_FAILURE
    if request.adapter == "node-test" and result.return_code == 1:
        tests = _last_summary_count(text, r"(?m)^# tests (\d+)\s*$")
        failures = _last_summary_count(text, r"(?m)^# fail (\d+)\s*$")
        if tests is not None and tests > 0 and failures is not None and failures > 0:
            return AdapterOutcome.TEST_FAILURE
    if request.adapter == "echidna" and result.return_code == 1:
        if _echidna_reports_property_failure(result.stdout):
            return AdapterOutcome.TEST_FAILURE
    if request.adapter == "halmos" and result.return_code == 1:
        if _summary_reports_failures(
            text,
            r"Symbolic test result:\s*\d+ passed;\s*(\d+) failed;",
        ):
            return AdapterOutcome.TEST_FAILURE
    return AdapterOutcome.INVALID


def _combined_result_text(result: CommandResult) -> str:
    return "\n".join(
        (
            result.stdout.decode("utf-8", errors="replace"),
            result.stderr.decode("utf-8", errors="replace"),
        )
    )


def _summary_reports_failures(text: str, pattern: str) -> bool:
    return any(int(match.group(1)) > 0 for match in re.finditer(pattern, text))


def _last_summary_count(text: str, pattern: str) -> int | None:
    matches = list(re.finditer(pattern, text))
    return int(matches[-1].group(1)) if matches else None


def _cargo_build_succeeded(stdout: bytes) -> bool:
    build_results: list[bool] = []
    for line in stdout.decode("utf-8", errors="replace").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            isinstance(value, dict)
            and value.get("reason") == "build-finished"
            and isinstance(value.get("success"), bool)
        ):
            build_results.append(value["success"])
    return bool(build_results) and all(build_results)


def _echidna_reports_property_failure(stdout: bytes) -> bool:
    try:
        value = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if (
        not isinstance(value, dict)
        or value.get("success") is not True
        or value.get("error") is not None
        or not isinstance(value.get("tests"), list)
        or not value["tests"]
    ):
        return False
    statuses = [
        item.get("status")
        for item in value["tests"]
        if isinstance(item, dict)
    ]
    return (
        len(statuses) == len(value["tests"])
        and "error" not in statuses
        and any(status in {"solved", "shrinking"} for status in statuses)
    )


def _option_value(arguments: list[str], option: str) -> str | None:
    prefix = option + "="
    for index, argument in enumerate(arguments):
        if argument.startswith(prefix):
            return argument[len(prefix) :]
        if argument == option and index + 1 < len(arguments):
            return arguments[index + 1]
    return None


def _safe_relative_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        return False
    candidate = Path(value)
    return not candidate.is_absolute() and all(part not in {"", ".", ".."} for part in candidate.parts)


def _validate_adapter_contract(
    adapter: str, command: list[str], evidence_level: EvidenceLevel
) -> None:
    if (
        "/" in command[0]
        or "\\" in command[0]
        or command[0] != Path(command[0]).name
    ):
        raise ValueError(
            "execution adapter executable must be a bare tool name resolved by the sandbox"
        )
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
        "node-test": (
            executable == "node" and "--test" in arguments
        ) or (
            executable in {"npm", "pnpm", "yarn"} and "test" in arguments
        ),
    }
    structural_adapters: dict[str, bool] = {
        "solc-ast": executable in {"solc", "solcjs"} and "--standard-json" in arguments,
        "slither": executable == "slither",
        "semgrep": executable == "semgrep",
    }
    if adapter in executable_adapters:
        if evidence_level is not EvidenceLevel.EXECUTABLE:
            raise ValueError(f"{adapter} may mint executable evidence only")
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
