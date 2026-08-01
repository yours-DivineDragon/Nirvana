from __future__ import annotations

import copy
import base64
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
from .verification import policy_sha256


MAX_TRANSCRIPT_BYTES = 65_536


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
    manifest: Path
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
            manifest=manifest_path,
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
    manifest_sha256: str
    spec_path: str
    corpus_path: str
    normalizer: str
    runner: dict[str, Any]
    implementations: list[dict[str, Any]]
    corpus_case_count: int
    requested_fuzz_case_count: int
    fuzz_case_count: int
    case_count: int
    repetitions: int
    fuzz_seed: int
    mismatches: list[DifferentialMismatch]
    valid: bool
    scheduled_executions: int
    successful_executions: int
    blocked_executions: int
    flaky_executions: int
    truncated_transcripts: int
    invalid_reasons: list[str]
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
    successful = 0
    timed_out = 0
    normalization_failures = 0
    flaky = 0
    truncated = 0
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
                    timed_out += 1
                elif result.blocked_reason is None and normalization_error is not None:
                    normalization_failures += 1
                elif result.blocked_reason is None:
                    # The return code is part of the observable contract. A
                    # non-zero result with normalizable output can be a valid
                    # implementation outcome (and often the divergence).
                    successful += 1
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
            transcript_truncated = (
                len(representative.stdout) > MAX_TRANSCRIPT_BYTES
                or len(representative.stderr) > MAX_TRANSCRIPT_BYTES
            )
            if transcript_truncated:
                truncated += 1
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
                    stdout_base64=base64.b64encode(representative.stdout[:MAX_TRANSCRIPT_BYTES]).decode("ascii"),
                    stderr_base64=base64.b64encode(representative.stderr[:MAX_TRANSCRIPT_BYTES]).decode("ascii"),
                    transcript_truncated=transcript_truncated,
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
                    input=copy.deepcopy(case["input"]),
                    notes=notes,
                )
            )
    if truncated:
        warnings.append(
            f"{truncated} implementation transcripts were truncated to {MAX_TRANSCRIPT_BYTES} bytes; full-stream hashes remain recorded"
        )
    scheduled = len(cases) * len(manifest.implementations) * manifest.repetitions
    invalid_reasons: list[str] = []
    if blocked:
        invalid_reasons.append(f"{blocked} scheduled executions were blocked by policy")
    if timed_out:
        invalid_reasons.append(f"{timed_out} scheduled executions timed out")
    if normalization_failures:
        invalid_reasons.append(
            f"{normalization_failures} scheduled executions produced output the comparator could not normalize"
        )
    if successful != scheduled and not invalid_reasons:
        invalid_reasons.append(
            f"only {successful} of {scheduled} scheduled executions completed successfully"
        )
    valid = successful == scheduled
    if not valid:
        warnings.insert(
            0,
            "differential report is invalid; mismatch and agreement counts are diagnostic only",
        )
    return DifferentialReport(
        schema_version="2.1.0",
        created_at=utc_now(),
        spec_sha256=sha256_file(manifest.spec),
        corpus_sha256=sha256_file(manifest.corpus),
        manifest_sha256=sha256_file(manifest.manifest),
        spec_path=manifest.spec.relative_to(manifest.root).as_posix(),
        corpus_path=manifest.corpus.relative_to(manifest.root).as_posix(),
        normalizer=manifest.normalizer,
        runner={
            "mode": runner.mode.value,
            "policy_sha256": policy_sha256(runner),
            "docker_image": runner.policy.docker_image,
            "network_allowed": (
                True
                if runner.mode.value == "host"
                else runner.policy.allow_network
            ),
            "host_execution_allowed": runner.policy.allow_host_execution,
            "host_network_risk_accepted": runner.policy.accept_host_network_risk,
        },
        implementations=[item.provenance(manifest.root) for item in manifest.implementations],
        corpus_case_count=len(corpus_cases),
        requested_fuzz_case_count=manifest.fuzz_cases,
        fuzz_case_count=len(fuzzed),
        case_count=len(cases),
        repetitions=manifest.repetitions,
        fuzz_seed=manifest.fuzz_seed,
        mismatches=mismatches,
        valid=valid,
        scheduled_executions=scheduled,
        successful_executions=successful,
        blocked_executions=blocked,
        flaky_executions=flaky,
        truncated_transcripts=truncated,
        invalid_reasons=invalid_reasons,
        warnings=warnings,
    )


def minimize_mismatch(
    manifest: DifferentialManifest,
    runner: CommandRunner,
    case_id: str,
    max_steps: int = 128,
) -> dict[str, Any]:
    if max_steps < 1 or max_steps > 10_000:
        raise ValueError("minimization max_steps must be between 1 and 10000")
    corpus_cases = _load_cases(manifest.corpus)
    cases = corpus_cases + _fuzz_cases(
        corpus_cases, manifest.fuzz_cases, manifest.fuzz_seed
    )
    matches = [item for item in cases if str(item["id"]) == case_id]
    if len(matches) != 1:
        raise ValueError(f"differential case is not uniquely available: {case_id}")
    original = copy.deepcopy(matches[0]["input"])
    original_outcomes, original_mismatch, original_flaky = _execute_input(
        manifest, runner, original
    )
    if not original_mismatch or original_flaky:
        raise ValueError("case is not a stable differential mismatch")
    current = copy.deepcopy(original)
    current_outcomes = original_outcomes
    attempts = 0
    accepted = 0
    changed = True
    while changed and attempts < max_steps:
        changed = False
        for candidate in _reduction_candidates(current):
            if attempts >= max_steps:
                break
            attempts += 1
            if _json_complexity(candidate) >= _json_complexity(current):
                continue
            outcomes, mismatch, flaky = _execute_input(manifest, runner, candidate)
            if mismatch and not flaky:
                current = candidate
                current_outcomes = outcomes
                accepted += 1
                changed = True
                break
    original_bytes = (canonical_json(original) + "\n").encode()
    minimized_bytes = (canonical_json(current) + "\n").encode()
    return {
        "schema_version": "1.0.0",
        "created_at": utc_now(),
        "case_id": case_id,
        "manifest_sha256": sha256_file(manifest.manifest),
        "spec_sha256": sha256_file(manifest.spec),
        "original_input": original,
        "original_input_sha256": sha256_bytes(original_bytes),
        "minimized_input": current,
        "minimized_input_sha256": sha256_bytes(minimized_bytes),
        "attempted_reductions": attempts,
        "accepted_reductions": accepted,
        "outcomes": [item.to_dict() if hasattr(item, "to_dict") else jsonable(item) for item in current_outcomes],
    }


def _execute_input(
    manifest: DifferentialManifest,
    runner: CommandRunner,
    value: Any,
) -> tuple[list[DifferentialOutcome], bool, bool]:
    input_bytes = (canonical_json(value) + "\n").encode()
    outcomes: list[DifferentialOutcome] = []
    signatures: set[tuple[int | None, str | None, str | None]] = set()
    any_flaky = False
    for implementation in manifest.implementations:
        results = [
            runner.run(implementation.command, implementation.cwd, input_bytes)
            for _ in range(manifest.repetitions)
        ]
        observations: list[tuple[int | None, str | None, str | None]] = []
        for result in results:
            normalized, error = _normalize(result.stdout, manifest.normalizer)
            error = result.blocked_reason or ("execution timed out" if result.timed_out else error)
            observations.append((result.return_code, normalized, error))
        unique = set(observations)
        flaky = len(unique) > 1
        any_flaky = any_flaky or flaky
        representative = results[0]
        transcript_truncated = (
            len(representative.stdout) > MAX_TRANSCRIPT_BYTES
            or len(representative.stderr) > MAX_TRANSCRIPT_BYTES
        )
        return_code, normalized, error = observations[0]
        signatures.add((return_code, normalized, error))
        outcomes.append(
            DifferentialOutcome(
                implementation=implementation.name,
                return_code=return_code,
                normalized_output=normalized,
                stdout_sha256=sha256_bytes(representative.stdout),
                stderr_sha256=sha256_bytes(representative.stderr),
                duration_ms=representative.duration_ms,
                stdout_base64=base64.b64encode(representative.stdout[:MAX_TRANSCRIPT_BYTES]).decode("ascii"),
                stderr_base64=base64.b64encode(representative.stderr[:MAX_TRANSCRIPT_BYTES]).decode("ascii"),
                transcript_truncated=transcript_truncated,
                run_count=manifest.repetitions,
                flaky=flaky,
                observed_signatures=sorted(
                    sha256_bytes(canonical_json(item).encode()) for item in unique
                ),
                error="flaky implementation output" if flaky else error,
            )
        )
    return outcomes, len(signatures) > 1 or any_flaky, any_flaky


def _reduction_candidates(value: Any) -> list[Any]:
    candidates: list[Any] = []
    if isinstance(value, bool) or value is None:
        return candidates
    if isinstance(value, int):
        candidates.extend(item for item in (0, 1, -1) if item != value)
    elif isinstance(value, float):
        candidates.extend(item for item in (0.0, 1.0, -1.0) if item != value)
    elif isinstance(value, str):
        candidates.extend(item for item in ("", value[: len(value) // 2], value[:1]) if item != value)
    elif isinstance(value, list):
        for index in range(len(value)):
            candidates.append(value[:index] + value[index + 1 :])
        for index, item in enumerate(value):
            for reduced in _reduction_candidates(item):
                candidate = copy.deepcopy(value)
                candidate[index] = reduced
                candidates.append(candidate)
    elif isinstance(value, dict):
        for key in sorted(value, key=str):
            candidate = copy.deepcopy(value)
            del candidate[key]
            candidates.append(candidate)
        for key in sorted(value, key=str):
            for reduced in _reduction_candidates(value[key]):
                candidate = copy.deepcopy(value)
                candidate[key] = reduced
                candidates.append(candidate)
    unique: dict[str, Any] = {}
    for candidate in candidates:
        unique.setdefault(canonical_json(candidate), candidate)
    return list(unique.values())


def _json_complexity(value: Any) -> tuple[int, int]:
    encoded = canonical_json(value)
    nodes = 1
    if isinstance(value, list):
        nodes += sum(_json_complexity(item)[1] for item in value)
    elif isinstance(value, dict):
        nodes += sum(_json_complexity(item)[1] for item in value.values())
    return len(encoded), nodes


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
    if not cases:
        raise ValueError("differential corpus must contain at least one case")
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
