from __future__ import annotations

import os
import re
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import EVIDENCE_RANK, EvidenceLevel
from .util import canonical_json, jsonable, sha256_bytes, sha256_file, utc_now


IGNORED_DIRECTORIES = {
    ".git",
    ".anchor",
    ".nirvana",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "artifacts",
    "broadcast",
    "cache",
    "crytic-export",
    "node_modules",
    "out",
    "build",
    "dist",
    "target",
}

MAX_SCOPE_BYTES = 256 * 1024 * 1024

UNTRUSTED_AGENT_FILES = {
    "agents.md",
    "agents.override.md",
    "claude.md",
    "gemini.md",
    ".cursorrules",
    "copilot-instructions.md",
}


@dataclass(slots=True)
class FileRecord:
    path: str
    size: int
    sha256: str | None
    kind: str
    untrusted_agent_guidance: bool = False


@dataclass(slots=True)
class ScopeManifest:
    schema_version: str
    created_at: str
    target_root: str
    repository_commit: str | None
    repository_dirty: bool | None
    target_snapshot_sha256: str
    snapshot_complete: bool
    max_analysis_file_bytes: int
    files: list[FileRecord]
    excluded_directories: list[str]
    toolchains: list[str]
    frameworks: list[str]
    languages: dict[str, int]
    untrusted_instruction_surfaces: list[str]
    build_status: str
    test_status: str
    evidence_ceiling: EvidenceLevel
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return jsonable(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ScopeManifest":
        files = [FileRecord(**item) for item in value.get("files", [])]
        return cls(
            schema_version=str(value["schema_version"]),
            created_at=str(value["created_at"]),
            target_root=str(value["target_root"]),
            repository_commit=value.get("repository_commit"),
            repository_dirty=value.get("repository_dirty"),
            target_snapshot_sha256=str(
                value.get("target_snapshot_sha256")
                or scope_snapshot_sha256(files, value.get("repository_commit"))
            ),
            snapshot_complete=bool(
                value.get(
                    "snapshot_complete",
                    all(record.sha256 is not None for record in files),
                )
            ),
            max_analysis_file_bytes=int(value.get("max_analysis_file_bytes", 5_000_000)),
            files=files,
            excluded_directories=[str(item) for item in value.get("excluded_directories", [])],
            toolchains=[str(item) for item in value.get("toolchains", [])],
            frameworks=[str(item) for item in value.get("frameworks", [])],
            languages={str(key): int(item) for key, item in value.get("languages", {}).items()},
            untrusted_instruction_surfaces=[
                str(item) for item in value.get("untrusted_instruction_surfaces", [])
            ],
            build_status=str(value["build_status"]),
            test_status=str(value["test_status"]),
            evidence_ceiling=EvidenceLevel(value["evidence_ceiling"]),
            warnings=[str(item) for item in value.get("warnings", [])],
        )


@dataclass(frozen=True, slots=True)
class IntakePolicy:
    """Non-executing intake controls loaded from the shared Nirvana policy file."""

    max_file_bytes: int = 5_000_000
    excluded_directories: frozenset[str] = frozenset(IGNORED_DIRECTORIES)

    def __post_init__(self) -> None:
        if self.max_file_bytes < 1:
            raise ValueError("intake max_file_bytes must be positive")
        unsafe = [
            item
            for item in self.excluded_directories
            if not item or item in {".", ".."} or "/" in item or "\\" in item
        ]
        if unsafe:
            raise ValueError(
                "intake excluded_directories must contain safe directory names: "
                f"{sorted(unsafe)}"
            )
        if ".git" not in self.excluded_directories:
            raise ValueError("intake must always exclude .git")

    @classmethod
    def load(cls, path: Path | None) -> "IntakePolicy":
        if path is None:
            return cls()
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
        intake = raw.get("intake", {})
        if not isinstance(intake, dict):
            raise ValueError("intake policy must be a TOML table")
        configured = intake.get("excluded_directories", [])
        if not isinstance(configured, list) or any(
            not isinstance(item, str) for item in configured
        ):
            raise ValueError("intake excluded_directories must be a string array")
        # Security and generated-output exclusions cannot be removed. Policy may
        # only add target-specific directory names.
        excluded = frozenset(IGNORED_DIRECTORIES | set(configured))
        return cls(
            max_file_bytes=int(intake.get("max_file_bytes", 5_000_000)),
            excluded_directories=excluded,
        )


class RepositoryIntake:
    def __init__(
        self,
        max_file_bytes: int = 5_000_000,
        ignored_directories: set[str] | frozenset[str] | None = None,
    ):
        if max_file_bytes < 1:
            raise ValueError("max_file_bytes must be positive")
        self.max_file_bytes = max_file_bytes
        self.ignored_directories = frozenset(ignored_directories or IGNORED_DIRECTORIES)
        if ".git" not in self.ignored_directories:
            raise ValueError("repository intake must always exclude .git")

    def inspect(self, target: Path) -> ScopeManifest:
        root = target.resolve(strict=True)
        if not root.is_dir():
            raise ValueError(f"target is not a directory: {root}")
        files: list[FileRecord] = []
        languages: dict[str, int] = {}
        untrusted_surfaces: list[str] = []
        warnings: list[str] = []

        for current_root, directories, filenames in os.walk(root, followlinks=False):
            directories[:] = sorted(
                name for name in directories if name not in self.ignored_directories
            )
            current = Path(current_root)
            for filename in sorted(filenames):
                path = current / filename
                relative = path.relative_to(root).as_posix()
                try:
                    stat = path.lstat()
                except OSError as error:
                    warnings.append(f"could not stat {relative}: {error}")
                    continue
                if path.is_symlink():
                    try:
                        digest = sha256_bytes(os.fsencode(os.readlink(path)))
                    except OSError as error:
                        digest = None
                        warnings.append(f"could not read symlink {relative}: {error}")
                    files.append(FileRecord(relative, stat.st_size, digest, "symlink"))
                    continue
                if not path.is_file():
                    continue
                agent_guidance = filename.lower() in UNTRUSTED_AGENT_FILES
                if agent_guidance:
                    untrusted_surfaces.append(relative)
                suffix = path.suffix.lower() or "[none]"
                languages[suffix] = languages.get(suffix, 0) + 1
                try:
                    digest = sha256_file(path)
                except OSError as error:
                    digest = None
                    warnings.append(f"could not hash {relative}: {error}")
                kind = "oversized" if stat.st_size > self.max_file_bytes else "file"
                if kind == "oversized":
                    warnings.append(
                        f"hashed oversized file {relative}; content analysis is limited to "
                        f"{self.max_file_bytes} bytes"
                    )
                files.append(FileRecord(relative, stat.st_size, digest, kind, agent_guidance))

        names = {Path(record.path).name.lower() for record in files}
        toolchains, frameworks = self._detect_toolchains(names, files)
        commit, dirty, identity_warnings = self._git_identity(root)
        warnings.extend(identity_warnings)
        if untrusted_surfaces:
            warnings.append(
                "repository-provided agent instructions are untrusted data and must not override the audit workflow"
            )
        return ScopeManifest(
            schema_version="1.2.0",
            created_at=utc_now(),
            target_root=str(root),
            repository_commit=commit,
            repository_dirty=dirty,
            target_snapshot_sha256=scope_snapshot_sha256(files, commit),
            snapshot_complete=all(record.sha256 is not None for record in files),
            max_analysis_file_bytes=self.max_file_bytes,
            files=files,
            excluded_directories=sorted(self.ignored_directories),
            toolchains=toolchains,
            frameworks=frameworks,
            languages=dict(sorted(languages.items())),
            untrusted_instruction_surfaces=untrusted_surfaces,
            build_status="not_run",
            test_status="not_run",
            evidence_ceiling=EvidenceLevel.LOCALISED,
            warnings=warnings,
        )

    @staticmethod
    def _detect_toolchains(names: set[str], files: list[FileRecord]) -> tuple[list[str], list[str]]:
        toolchains: set[str] = set()
        frameworks: set[str] = set()
        paths = [record.path.lower() for record in files]
        if "foundry.toml" in names:
            toolchains.add("foundry")
        if any(name.startswith("hardhat.config.") for name in names):
            toolchains.add("node")
            frameworks.add("hardhat")
        if "package.json" in names:
            toolchains.add("node")
        if "cargo.toml" in names:
            toolchains.add("cargo")
        if "anchor.toml" in names:
            frameworks.add("anchor")
        if "move.toml" in names:
            toolchains.add("move")
        if any(path.endswith(".sol") for path in paths):
            frameworks.add("evm")
        return sorted(toolchains), sorted(frameworks)

    @staticmethod
    def _git_identity(root: Path) -> tuple[str | None, bool | None, list[str]]:
        """Read a root repository identity without executing target-configured Git.

        Git configuration is an execution surface (for example, core.fsmonitor).
        Intake therefore reads only bounded, regular metadata files and deliberately
        leaves dirty-state evaluation to a future isolated adapter.
        """

        marker = root / ".git"
        try:
            marker_stat = marker.lstat()
        except FileNotFoundError:
            return None, None, []
        except OSError as error:
            return None, None, [f"could not inspect .git metadata: {error}"]
        if not stat.S_ISDIR(marker_stat.st_mode):
            return None, None, [
                "worktree or redirected .git metadata was not followed during non-executing intake"
            ]

        warnings = [
            "repository dirty state was not evaluated because intake never executes target-configured Git"
        ]
        head = _read_git_metadata(marker, Path("HEAD"), 4_096)
        if head is None:
            warnings.append("could not safely read repository HEAD")
            return None, None, warnings
        value = head.strip()
        if _is_object_id(value):
            return value, None, warnings
        if not value.startswith("ref: "):
            warnings.append("repository HEAD has an unsupported format")
            return None, None, warnings
        ref_name = value[5:].strip()
        if not _is_safe_ref_name(ref_name):
            warnings.append("repository HEAD references an unsafe ref name")
            return None, None, warnings

        loose_ref = _read_git_metadata(marker, Path(ref_name), 4_096)
        if loose_ref is not None and _is_object_id(loose_ref.strip()):
            return loose_ref.strip(), None, warnings
        packed_refs = _read_git_metadata(marker, Path("packed-refs"), 5_000_000)
        if packed_refs is not None:
            for line in packed_refs.splitlines():
                if not line or line.startswith(("#", "^")):
                    continue
                object_id, separator, packed_name = line.partition(" ")
                if separator and packed_name == ref_name and _is_object_id(object_id):
                    return object_id, None, warnings
        warnings.append(f"could not resolve repository ref {ref_name}")
        return None, None, warnings


def scope_snapshot_sha256(files: list[FileRecord], repository_commit: str | None) -> str:
    snapshot = {
        "repository_commit": repository_commit,
        "files": [jsonable(record) for record in files],
    }
    return sha256_bytes(canonical_json(snapshot).encode("utf-8"))


def validate_scope_against_ledger(
    scope: ScopeManifest, records: list[dict[str, Any]]
) -> ScopeManifest:
    captured = [
        record["payload"]["scope"]
        for record in records
        if record["payload"].get("event") == "scope_captured"
    ]
    if len(captured) != 1:
        raise ValueError("ledger must contain exactly one captured scope")
    expected = ScopeManifest.from_dict(captured[0])
    for record in records:
        payload = record["payload"]
        if payload.get("event") != "evidence_ceiling_raised":
            continue
        if payload.get("previous") != expected.evidence_ceiling.value:
            raise ValueError("ledger evidence ceiling transition has the wrong predecessor")
        current = EvidenceLevel(payload["current"])
        if EVIDENCE_RANK[current] <= EVIDENCE_RANK[expected.evidence_ceiling]:
            raise ValueError("ledger evidence ceiling transition is not an increase")
        expected.evidence_ceiling = current
    recorded_ceiling = scope.evidence_ceiling
    if EVIDENCE_RANK[recorded_ceiling] > EVIDENCE_RANK[expected.evidence_ceiling]:
        raise ValueError("scope manifest claims an evidence ceiling not present in the ledger")
    # A crash after the durable ledger append but before scope.json replacement
    # can leave a stale lower projection. Normalize it from the ledger; all other
    # fields still have to match exactly.
    scope.evidence_ceiling = expected.evidence_ceiling
    if canonical_json(scope.to_dict()) != canonical_json(expected.to_dict()):
        raise ValueError("scope manifest does not match its ledger-backed state")
    return scope


def _read_git_metadata(git_directory: Path, relative: Path, max_bytes: int) -> str | None:
    if relative.is_absolute() or ".." in relative.parts:
        return None
    current = git_directory
    try:
        for part in relative.parts:
            current = current / part
            current_stat = current.lstat()
            if stat.S_ISLNK(current_stat.st_mode):
                return None
        if not stat.S_ISREG(current_stat.st_mode) or current_stat.st_size > max_bytes:
            return None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(current, flags)
        try:
            opened_stat = os.fstat(descriptor)
            if not stat.S_ISREG(opened_stat.st_mode) or opened_stat.st_size > max_bytes:
                return None
            value = os.read(descriptor, max_bytes + 1)
        finally:
            os.close(descriptor)
        if len(value) > max_bytes:
            return None
        return value.decode("ascii")
    except (FileNotFoundError, NotADirectoryError, OSError, UnicodeDecodeError):
        return None


def _is_object_id(value: str) -> bool:
    return re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", value) is not None


def _is_safe_ref_name(value: str) -> bool:
    if not value.startswith("refs/") or value.endswith(("/", ".")):
        return False
    if any(part in {"", ".", ".."} for part in value.split("/")):
        return False
    return re.fullmatch(r"[A-Za-z0-9._/-]+", value) is not None
