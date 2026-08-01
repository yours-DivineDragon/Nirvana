from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import DifferentialMismatch, DifferentialOutcome
from .policy import CommandRunner
from .util import canonical_json, jsonable, sha256_bytes, utc_now


@dataclass(frozen=True, slots=True)
class Implementation:
    name: str
    command: list[str]
    cwd: Path


@dataclass(frozen=True, slots=True)
class DifferentialManifest:
    spec: Path
    corpus: Path
    normalizer: str
    implementations: list[Implementation]

    @classmethod
    def load(cls, path: Path) -> "DifferentialManifest":
        manifest_path = path.resolve(strict=True)
        root = manifest_path.parent
        with manifest_path.open("rb") as stream:
            raw = tomllib.load(stream)
        implementations: list[Implementation] = []
        for item in raw.get("implementations", []):
            cwd = _within(root, root / item.get("cwd", "."))
            command = item.get("command")
            if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
                raise ValueError("every implementation command must be a non-empty string array")
            implementations.append(Implementation(str(item["name"]), command, cwd))
        if len({item.name for item in implementations}) != len(implementations):
            raise ValueError("implementation names must be unique")
        if len(implementations) < 2:
            raise ValueError("differential analysis requires at least two implementations")
        normalizer = str(raw.get("normalizer", "json"))
        if normalizer not in {"json", "text"}:
            raise ValueError("normalizer must be 'json' or 'text'")
        return cls(
            spec=_within(root, root / raw["spec"]),
            corpus=_within(root, root / raw["corpus"]),
            normalizer=normalizer,
            implementations=implementations,
        )


@dataclass(slots=True)
class DifferentialReport:
    schema_version: str
    created_at: str
    spec_sha256: str
    corpus_sha256: str
    case_count: int
    mismatches: list[DifferentialMismatch]
    blocked_executions: int

    def to_dict(self) -> dict[str, Any]:
        return jsonable(self)


def compare(manifest: DifferentialManifest, runner: CommandRunner) -> DifferentialReport:
    cases = _load_cases(manifest.corpus)
    mismatches: list[DifferentialMismatch] = []
    blocked = 0
    for case in cases:
        case_id = str(case["id"])
        input_bytes = (canonical_json(case["input"]) + "\n").encode()
        outcomes: list[DifferentialOutcome] = []
        signatures: set[tuple[int | None, str | None, str | None]] = set()
        for implementation in manifest.implementations:
            result = runner.run(implementation.command, implementation.cwd, input_bytes)
            if result.blocked_reason:
                blocked += 1
            normalized, normalization_error = _normalize(result.stdout, manifest.normalizer)
            error = result.blocked_reason or normalization_error
            if result.timed_out:
                error = "execution timed out"
            signatures.add((result.return_code, normalized, error))
            outcomes.append(
                DifferentialOutcome(
                    implementation=implementation.name,
                    return_code=result.return_code,
                    normalized_output=normalized,
                    stdout_sha256=sha256_bytes(result.stdout),
                    stderr_sha256=sha256_bytes(result.stderr),
                    duration_ms=result.duration_ms,
                    error=error,
                )
            )
        if len(signatures) > 1:
            mismatches.append(
                DifferentialMismatch(
                    case_id=case_id,
                    input_sha256=sha256_bytes(input_bytes),
                    outcomes=outcomes,
                    notes=["Classify only after ruling out comparator and harness defects."],
                )
            )
    return DifferentialReport(
        schema_version="1.0.0",
        created_at=utc_now(),
        spec_sha256=_hash_path(manifest.spec),
        corpus_sha256=_hash_path(manifest.corpus),
        case_count=len(cases),
        mismatches=mismatches,
        blocked_executions=blocked,
    )


def _load_cases(path: Path) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            item = json.loads(line)
            if not isinstance(item, dict) or "id" not in item or "input" not in item:
                raise ValueError(f"corpus line {line_number} requires id and input")
            cases.append(item)
    if len({str(item["id"]) for item in cases}) != len(cases):
        raise ValueError("corpus case ids must be unique")
    return cases


def _normalize(output: bytes, mode: str) -> tuple[str | None, str | None]:
    try:
        text = output.decode("utf-8")
    except UnicodeDecodeError:
        return None, "stdout is not UTF-8"
    if mode == "text":
        return text.strip(), None
    try:
        return canonical_json(json.loads(text)), None
    except json.JSONDecodeError as error:
        return None, f"stdout is not one JSON value: {error.msg}"


def _within(root: Path, candidate: Path) -> Path:
    resolved_root = root.resolve(strict=True)
    resolved_candidate = candidate.resolve(strict=True)
    if resolved_candidate != resolved_root and resolved_root not in resolved_candidate.parents:
        raise ValueError(f"manifest path escapes its directory: {candidate}")
    return resolved_candidate


def _hash_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())
