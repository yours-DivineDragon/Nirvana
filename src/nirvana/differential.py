from __future__ import annotations

import copy
import json
import random
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .contracts import validate_contract
from .models import DifferentialMismatch, DifferentialOutcome
from .policy import CommandRunner
from .util import canonical_json, jsonable, sha256_bytes, sha256_file, utc_now


@dataclass(frozen=True, slots=True)
class Implementation:
    name: str
    command: list[str]
    cwd: Path
    language: str
    sources: list[Path]
    producer: str
    model: str | None
    prompt_sha256: str | None
    tool_version: str
    source_sha256: str

    def provenance(self, root: Path) -> dict[str, Any]:
        return {
            "name": self.name,
            "command": list(self.command),
            "cwd": self.cwd.relative_to(root).as_posix() or ".",
            "language": self.language,
            "sources": [item.relative_to(root).as_posix() for item in self.sources],
            "source_sha256": self.source_sha256,
            "producer": self.producer,
            "model": self.model,
            "prompt_sha256": self.prompt_sha256,
            "tool_version": self.tool_version,
        }


@dataclass(frozen=True, slots=True)
class DifferentialManifest:
    root: Path
    spec: Path
    corpus: Path
    normalizer: str
    implementations: list[Implementation]
    repetitions: int
    fuzz_cases: int
    fuzz_seed: int

    @classmethod
    def load(cls, path: Path) -> "DifferentialManifest":
        manifest_path = path.resolve(strict=True)
        root = manifest_path.parent
        with manifest_path.open("rb") as stream:
            raw = tomllib.load(stream)
        implementations: list[Implementation] = []
        for item in raw.get("implementations", []):
            if not isinstance(item, dict):
                raise ValueError("every implementation entry must be a table")
            cwd = _within(root, root / item.get("cwd", "."))
            command = item.get("command")
            if (
                not isinstance(command, list)
                or not command
                or not all(isinstance(part, str) and part for part in command)
            ):
                raise ValueError("every implementation command must be a non-empty string array")
            raw_sources = item.get("sources")
            if (
                not isinstance(raw_sources, list)
                or not raw_sources
                or any(not isinstance(source, str) or not source for source in raw_sources)
            ):
                raise ValueError("every implementation requires a non-empty sources array")
            sources = [_within(root, root / source) for source in raw_sources]
            if any(not source.is_file() for source in sources):
                raise ValueError("implementation sources must be files")
            language = str(item.get("language", ""))
            producer = str(item.get("producer", ""))
            tool_version = str(item.get("tool_version", ""))
            if not language.strip() or not producer.strip() or not tool_version.strip():
                raise ValueError(
                    "implementation language, producer, and tool_version are required"
                )
            model = item.get("model")
            if model is not None and not isinstance(model, str):
                raise ValueError("implementation model must be a string or null")
            prompt_sha256 = item.get("prompt_sha256")
            if prompt_sha256 is not None and (
                not isinstance(prompt_sha256, str)
                or len(prompt_sha256) != 64
                or any(char not in "0123456789abcdef" for char in prompt_sha256)
            ):
                raise ValueError("implementation prompt_sha256 must be a lowercase SHA-256 digest")
            allowed_producers = {"human", "codex", "claude-code", "kimi-code", "other-agent"}
            if producer not in allowed_producers:
                raise ValueError(f"unsupported implementation producer: {producer}")
            if producer != "human" and (
                not isinstance(model, str)
                or not model.strip()
                or prompt_sha256 is None
            ):
                raise ValueError(
                    "agent-produced implementations require model and prompt_sha256 provenance"
                )
            source_sha256 = _source_set_sha256(root, sources)
            expected_source_sha256 = item.get("source_sha256")
            if expected_source_sha256 is not None and expected_source_sha256 != source_sha256:
                raise ValueError(f"implementation source hash does not match: {item.get('name')}")
            implementations.append(
                Implementation(
                    name=str(item["name"]),
                    command=list(command),
                    cwd=cwd,
                    language=language,
                    sources=sources,
                    producer=producer,
                    model=model,
                    prompt_sha256=prompt_sha256,
                    tool_version=tool_version,
                    source_sha256=source_sha256,
                )
            )
        if len({item.name for item in implementations}) != len(implementations):
            raise ValueError("implementation names must be unique")
        if len(implementations) < 2:
            raise ValueError("differential analysis requires at least two implementations")
        normalizer = str(raw.get("normalizer", "json"))
        if normalizer not in {"json", "text"}:
            raise ValueError("normalizer must be 'json' or 'text'")
        analysis = raw.get("analysis", {})
        repetitions = int(analysis.get("repetitions", 2))
        fuzz_cases = int(analysis.get("fuzz_cases", 0))
        fuzz_seed = int(analysis.get("fuzz_seed", 0))
        if repetitions < 2 or repetitions > 20:
            raise ValueError("analysis repetitions must be between 2 and 20")
        if fuzz_cases < 0 or fuzz_cases > 10_000:
            raise ValueError("analysis fuzz_cases must be between 0 and 10000")
        return cls(
            root=root,
            spec=_within(root, root / raw["spec"]),
            corpus=_within(root, root / raw["corpus"]),
            normalizer=normalizer,
            implementations=implementations,
            repetitions=repetitions,
            fuzz_cases=fuzz_cases,
            fuzz_seed=fuzz_seed,
        )


@dataclass(slots=True)
class DifferentialReport:
    schema_version: str
    created_at: str
    spec_sha256: str
    corpus_sha256: str
    implementations: list[dict[str, Any]]
    corpus_case_count: int
    requested_fuzz_case_count: int
    fuzz_case_count: int
    case_count: int
    repetitions: int
    fuzz_seed: int
    mismatches: list[DifferentialMismatch]
    blocked_executions: int
    flaky_executions: int
    warnings: list[str]

    def to_dict(self) -> dict[str, Any]:
        value = jsonable(self)
        validate_contract(value, "differential-report.schema.json")
        return value


def compare(manifest: DifferentialManifest, runner: CommandRunner) -> DifferentialReport:
    corpus_cases = _load_cases(manifest.corpus)
    fuzzed = _fuzz_cases(corpus_cases, manifest.fuzz_cases, manifest.fuzz_seed)
    warnings: list[str] = []
    if len(fuzzed) < manifest.fuzz_cases:
        warnings.append(
            "generated "
            f"{len(fuzzed)} of {manifest.fuzz_cases} requested fuzz cases; "
            "the deterministic mutation space was exhausted"
        )
    cases = corpus_cases + fuzzed
    mismatches: list[DifferentialMismatch] = []
    blocked = 0
    flaky = 0
    for case in cases:
        case_id = str(case["id"])
        input_bytes = (canonical_json(case["input"]) + "\n").encode()
        outcomes: list[DifferentialOutcome] = []
        implementation_signatures: set[tuple[int | None, str | None, str | None]] = set()
        case_is_flaky = False
        for implementation in manifest.implementations:
            observations: list[tuple[Any, str | None, str | None]] = []
            results = []
            for _ in range(manifest.repetitions):
                result = runner.run(implementation.command, implementation.cwd, input_bytes)
                results.append(result)
                if result.blocked_reason:
                    blocked += 1
                normalized, normalization_error = _normalize(result.stdout, manifest.normalizer)
                error = result.blocked_reason or normalization_error
                if result.timed_out:
                    error = "execution timed out"
                observations.append((result.return_code, normalized, error))
            unique_observations = {
                (return_code, normalized, error)
                for return_code, normalized, error in observations
            }
            outcome_is_flaky = len(unique_observations) > 1
            if outcome_is_flaky:
                flaky += 1
                case_is_flaky = True
            representative = results[0]
            return_code, normalized, error = observations[0]
            implementation_signatures.add((return_code, normalized, error))
            outcomes.append(
                DifferentialOutcome(
                    implementation=implementation.name,
                    return_code=return_code,
                    normalized_output=normalized,
                    stdout_sha256=sha256_bytes(representative.stdout),
                    stderr_sha256=sha256_bytes(representative.stderr),
                    duration_ms=representative.duration_ms,
                    run_count=manifest.repetitions,
                    flaky=outcome_is_flaky,
                    observed_signatures=sorted(
                        sha256_bytes(canonical_json(item).encode("utf-8"))
                        for item in unique_observations
                    ),
                    error="flaky implementation output" if outcome_is_flaky else error,
                )
            )
        if len(implementation_signatures) > 1 or case_is_flaky:
            notes = ["Classify only after ruling out comparator and harness defects."]
            if case_is_flaky:
                notes.append("At least one implementation was non-deterministic across repeated runs.")
            mismatches.append(
                DifferentialMismatch(
                    case_id=case_id,
                    input_sha256=sha256_bytes(input_bytes),
                    outcomes=outcomes,
                    notes=notes,
                )
            )
    return DifferentialReport(
        schema_version="1.2.0",
        created_at=utc_now(),
        spec_sha256=sha256_file(manifest.spec),
        corpus_sha256=sha256_file(manifest.corpus),
        implementations=[item.provenance(manifest.root) for item in manifest.implementations],
        corpus_case_count=len(corpus_cases),
        requested_fuzz_case_count=manifest.fuzz_cases,
        fuzz_case_count=len(fuzzed),
        case_count=len(cases),
        repetitions=manifest.repetitions,
        fuzz_seed=manifest.fuzz_seed,
        mismatches=mismatches,
        blocked_executions=blocked,
        flaky_executions=flaky,
        warnings=warnings,
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


def _fuzz_cases(cases: list[dict[str, Any]], count: int, seed: int) -> list[dict[str, Any]]:
    if not cases or count == 0:
        return []
    rng = random.Random(seed)
    known = {canonical_json(item["input"]) for item in cases}
    generated: list[dict[str, Any]] = []
    attempts = 0
    while len(generated) < count and attempts < max(100, count * 50):
        attempts += 1
        source = copy.deepcopy(rng.choice(cases)["input"])
        candidate = _mutate_json(source, rng)
        encoded = canonical_json(candidate)
        if encoded in known:
            continue
        known.add(encoded)
        digest = sha256_bytes(encoded.encode("utf-8"))
        generated.append(
            {"id": f"fuzz-{len(generated) + 1:06d}-{digest[:8]}", "input": candidate}
        )
    return generated


def _mutate_json(value: Any, rng: random.Random) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return rng.choice([0, 1, -1, value - 1, value + 1, 2**63 - 1, -(2**63)])
    if isinstance(value, float):
        return rng.choice([0.0, -0.0, value - 1.0, value + 1.0, 1e-308, 1e308])
    if isinstance(value, str):
        return rng.choice(["", value + "\x00", value + "é", value * 2])
    if value is None:
        return rng.choice([False, 0, ""])
    if isinstance(value, list):
        if not value:
            return [0]
        candidate = copy.deepcopy(value)
        choice = rng.randrange(3)
        if choice == 0:
            candidate.pop(rng.randrange(len(candidate)))
        elif choice == 1:
            index = rng.randrange(len(candidate))
            candidate[index] = _mutate_json(candidate[index], rng)
        else:
            candidate.append(copy.deepcopy(rng.choice(candidate)))
        return candidate
    if isinstance(value, dict):
        if not value:
            return {"fuzz": 0}
        candidate = copy.deepcopy(value)
        key = rng.choice(sorted(candidate, key=str))
        if rng.randrange(4) == 0:
            del candidate[key]
        else:
            candidate[key] = _mutate_json(candidate[key], rng)
        return candidate
    raise TypeError(f"unsupported corpus value: {type(value).__name__}")


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


def _source_set_sha256(root: Path, sources: list[Path]) -> str:
    records = [
        {
            "path": source.relative_to(root).as_posix(),
            "sha256": sha256_file(source),
        }
        for source in sorted(sources)
    ]
    return sha256_bytes(canonical_json(records).encode("utf-8"))
