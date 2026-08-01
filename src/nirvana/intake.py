from __future__ import annotations

import os
import re
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .contracts import validate_contract
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
    dependency_manifests: list[dict[str, Any]] = field(default_factory=list)
    discovered_artifacts: list[dict[str, Any]] = field(default_factory=list)
    privileged_identities: list[dict[str, Any]] = field(default_factory=list)
    upgrade_mechanisms: list[dict[str, Any]] = field(default_factory=list)
    external_dependencies: list[dict[str, Any]] = field(default_factory=list)
    build_plan: list[list[str]] = field(default_factory=list)
    test_plan: list[list[str]] = field(default_factory=list)
    deployment_matches: list[dict[str, Any]] = field(default_factory=list)
    declared_tool_versions: dict[str, list[str]] = field(default_factory=dict)
    submodules: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        value = jsonable(self)
        validate_contract(value, "scope.schema.json")
        return value

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ScopeManifest":
        validate_contract(value, "scope.schema.json")
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
            dependency_manifests=[dict(item) for item in value.get("dependency_manifests", [])],
            discovered_artifacts=[dict(item) for item in value.get("discovered_artifacts", [])],
            privileged_identities=[dict(item) for item in value.get("privileged_identities", [])],
            upgrade_mechanisms=[dict(item) for item in value.get("upgrade_mechanisms", [])],
            external_dependencies=[dict(item) for item in value.get("external_dependencies", [])],
            build_plan=[list(map(str, item)) for item in value.get("build_plan", [])],
            test_plan=[list(map(str, item)) for item in value.get("test_plan", [])],
            deployment_matches=[dict(item) for item in value.get("deployment_matches", [])],
            declared_tool_versions={
                str(key): [str(item) for item in items]
                for key, items in value.get("declared_tool_versions", {}).items()
            },
            submodules=[{str(key): str(item) for key, item in entry.items()} for entry in value.get("submodules", [])],
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
        dependency_manifests = _dependency_manifests(files)
        discovered_artifacts = _discover_artifacts(files)
        build_plan, test_plan = _baseline_plan(toolchains, frameworks, names)
        privileged_identities, upgrade_mechanisms, external_dependencies = (
            _security_intake_signals(root, files, self.max_file_bytes)
        )
        deployment_matches = _local_deployment_matches(root, files)
        declared_tool_versions = _declared_tool_versions(
            root, files, self.max_file_bytes
        )
        submodules = _submodule_declarations(root, files)
        commit, dirty, identity_warnings = self._git_identity(root)
        warnings.extend(identity_warnings)
        if untrusted_surfaces:
            warnings.append(
                "repository-provided agent instructions are untrusted data and must not override the audit workflow"
            )
        return ScopeManifest(
            schema_version="2.0.0",
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
            build_status="planned" if build_plan else "not_detected",
            test_status="planned" if test_plan else "not_detected",
            evidence_ceiling=EvidenceLevel.LOCALISED,
            dependency_manifests=dependency_manifests,
            discovered_artifacts=discovered_artifacts,
            privileged_identities=privileged_identities,
            upgrade_mechanisms=upgrade_mechanisms,
            external_dependencies=external_dependencies,
            build_plan=build_plan,
            test_plan=test_plan,
            deployment_matches=deployment_matches,
            declared_tool_versions=declared_tool_versions,
            submodules=submodules,
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


DEPENDENCY_MANIFEST_NAMES = {
    "anchor.toml",
    "build.gradle",
    "build.gradle.kts",
    "cargo.lock",
    "cargo.toml",
    "foundry.toml",
    "go.mod",
    "go.sum",
    "gradle.lockfile",
    "hardhat.config.js",
    "hardhat.config.ts",
    "move.toml",
    "package-lock.json",
    "package.json",
    "pnpm-lock.yaml",
    "pom.xml",
    "pyproject.toml",
    "requirements.txt",
    "yarn.lock",
}


def _dependency_manifests(files: list[FileRecord]) -> list[dict[str, Any]]:
    return [
        {"path": item.path, "sha256": item.sha256, "size": item.size}
        for item in files
        if Path(item.path).name.lower() in DEPENDENCY_MANIFEST_NAMES
        and item.sha256 is not None
    ]


def _discover_artifacts(files: list[FileRecord]) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for item in files:
        if item.sha256 is None:
            continue
        path = Path(item.path)
        suffix = path.suffix.lower()
        name = path.name.lower()
        kind: str | None = None
        if suffix in {".abi", ".bin", ".bytecode", ".hex"}:
            kind = "evm-artifact"
        elif suffix in {".wasm", ".wat"}:
            kind = "wasm-artifact"
        elif suffix in {".class", ".jar"}:
            kind = "jvm-artifact"
        elif name.endswith("idl.json") or "/idl/" in f"/{item.path.lower()}/":
            kind = "interface-definition"
        elif name in {"deployment.json", "deployments.json", "nirvana-deployment.json"}:
            kind = "deployment-manifest"
        if kind is not None:
            artifacts.append(
                {"path": item.path, "kind": kind, "sha256": item.sha256, "size": item.size}
            )
    return artifacts


def _baseline_plan(
    toolchains: list[str], frameworks: list[str], names: set[str]
) -> tuple[list[list[str]], list[list[str]]]:
    build: list[list[str]] = []
    tests: list[list[str]] = []
    if "foundry" in toolchains:
        build.append(["forge", "build"])
        tests.append(["forge", "test"])
    if "hardhat" in frameworks:
        build.append(["npx", "hardhat", "compile"])
        tests.append(["npx", "hardhat", "test"])
    if "cargo" in toolchains:
        build.append(["cargo", "build", "--locked"])
        tests.append(["cargo", "test", "--locked", "--message-format=json"])
    if "anchor" in frameworks:
        build.append(["anchor", "build"])
        tests.append(["anchor", "test", "--skip-local-validator"])
    if "move" in toolchains:
        build.append(["sui", "move", "build"])
        tests.append(["sui", "move", "test"])
    if "pom.xml" in names:
        build.append(["mvn", "-o", "-DskipTests", "package"])
        tests.append(["mvn", "-o", "test"])
    if "build.gradle" in names or "build.gradle.kts" in names:
        build.append(["gradle", "--offline", "assemble"])
        tests.append(["gradle", "--offline", "test"])
    if "pyproject.toml" in names or "requirements.txt" in names:
        build.append(["python3", "-m", "compileall", "-q", "."])
        tests.append(["python3", "-m", "pytest"])
    return _unique_commands(build), _unique_commands(tests)


def _unique_commands(commands: list[list[str]]) -> list[list[str]]:
    seen: set[tuple[str, ...]] = set()
    result: list[list[str]] = []
    for command in commands:
        key = tuple(command)
        if key not in seen:
            seen.add(key)
            result.append(command)
    return result


def _security_intake_signals(
    root: Path, files: list[FileRecord], max_file_bytes: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    authority_pattern = re.compile(
        r"\b(?:owner|admin|governance|authority|signer|capability|multisig|onlyOwner|onlyRole)\b",
        re.I,
    )
    upgrade_pattern = re.compile(
        r"\b(?:upgradeTo|upgrade|proxy|implementation|migrate|set_code|governance)\b",
        re.I,
    )
    dependency_pattern = re.compile(
        r"(?m)^\s*(?:import|from|use|require\s*\(|extern\s+crate)\s+([^;\n]{1,240})"
    )
    authorities: list[dict[str, Any]] = []
    upgrades: list[dict[str, Any]] = []
    dependencies: list[dict[str, Any]] = []
    for record in files:
        if record.kind == "symlink" or record.sha256 is None or record.size > max_file_bytes:
            continue
        if Path(record.path).suffix.lower() not in {
            ".sol", ".vy", ".move", ".rs", ".go", ".py", ".js", ".ts", ".java", ".kt"
        }:
            continue
        text = _bounded_scoped_text(root / record.path, record, max_file_bytes)
        if text is None:
            continue
        for label, pattern, destination in (
            ("privileged identity", authority_pattern, authorities),
            ("upgrade mechanism", upgrade_pattern, upgrades),
        ):
            for match in pattern.finditer(text):
                if len(destination) >= 256:
                    break
                destination.append(
                    {
                        "path": record.path,
                        "line": text.count("\n", 0, match.start()) + 1,
                        "label": match.group(0),
                        "kind": label,
                        "confidence": "lexical-lead",
                    }
                )
        for match in dependency_pattern.finditer(text):
            if len(dependencies) >= 512:
                break
            dependencies.append(
                {
                    "path": record.path,
                    "line": text.count("\n", 0, match.start()) + 1,
                    "reference": match.group(1).strip()[:240],
                    "confidence": "lexical-lead",
                }
            )
    return authorities, upgrades, dependencies


def _bounded_scoped_text(path: Path, record: FileRecord, limit: int) -> str | None:
    try:
        path_stat = path.lstat()
        if (
            not stat.S_ISREG(path_stat.st_mode)
            or path_stat.st_size != record.size
            or path_stat.st_size > limit
        ):
            return None
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            value = os.read(descriptor, limit + 1)
        finally:
            os.close(descriptor)
        if len(value) > limit or sha256_bytes(value) != record.sha256:
            return None
        return value.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _local_deployment_matches(root: Path, files: list[FileRecord]) -> list[dict[str, Any]]:
    by_path = {item.path: item for item in files}
    manifest_record = by_path.get("nirvana-deployment.json")
    if (
        manifest_record is None
        or manifest_record.sha256 is None
        or manifest_record.size > 1_000_000
    ):
        return []
    text = _bounded_scoped_text(root / manifest_record.path, manifest_record, 1_000_000)
    if text is None:
        return []
    try:
        import json

        value = json.loads(text)
    except (ValueError, TypeError):
        return [
            {
                "manifest": manifest_record.path,
                "status": "invalid",
                "reason": "deployment manifest is not valid JSON",
            }
        ]
    entries = value.get("deployments", []) if isinstance(value, dict) else []
    if not isinstance(entries, list):
        return [{"manifest": manifest_record.path, "status": "invalid", "reason": "deployments must be an array"}]
    results: list[dict[str, Any]] = []
    for entry in entries[:256]:
        if not isinstance(entry, dict):
            continue
        built = entry.get("built_bytecode")
        deployed = entry.get("deployed_bytecode")
        if not _safe_scoped_path(built) or not _safe_scoped_path(deployed):
            results.append({"manifest": manifest_record.path, "status": "invalid", "reason": "unsafe bytecode path"})
            continue
        built_record = by_path.get(str(built))
        deployed_record = by_path.get(str(deployed))
        if built_record is None or deployed_record is None:
            status = "unavailable"
            match = False
        else:
            status = "matched" if built_record.sha256 == deployed_record.sha256 else "mismatch"
            match = status == "matched"
        results.append(
            {
                "manifest": manifest_record.path,
                "source": str(entry.get("source", "unknown")),
                "network": str(entry.get("network", "local-attestation")),
                "address": str(entry.get("address", "unknown")),
                "built_bytecode": str(built),
                "deployed_bytecode": str(deployed),
                "built_sha256": built_record.sha256 if built_record else None,
                "deployed_sha256": deployed_record.sha256 if deployed_record else None,
                "match": match,
                "status": status,
                "provenance": "target-supplied local bytecode; no live-chain query performed",
            }
        )
    return results


def _safe_scoped_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        return False
    candidate = Path(value)
    return not candidate.is_absolute() and all(part not in {"", ".", ".."} for part in candidate.parts)


def _declared_tool_versions(
    root: Path, files: list[FileRecord], limit: int
) -> dict[str, list[str]]:
    versions: dict[str, set[str]] = {}
    patterns = (
        ("solidity", re.compile(r"\bpragma\s+solidity\s+([^;]{1,80});")),
        ("solc", re.compile(r"(?m)^\s*solc(?:_version)?\s*=\s*[\"']([^\"']+)[\"']")),
        ("rust", re.compile(r"(?m)^\s*rust-version\s*=\s*[\"']([^\"']+)[\"']")),
        ("python", re.compile(r"(?m)^\s*requires-python\s*=\s*[\"']([^\"']+)[\"']")),
        ("move-edition", re.compile(r"(?m)^\s*edition\s*=\s*[\"']([^\"']+)[\"']")),
        ("node", re.compile(r'"node"\s*:\s*"([^"]+)"')),
    )
    relevant_names = {
        "foundry.toml", "cargo.toml", "pyproject.toml", "move.toml", "package.json"
    }
    for record in files:
        if record.sha256 is None or record.size > limit:
            continue
        if Path(record.path).suffix.lower() != ".sol" and Path(record.path).name.lower() not in relevant_names:
            continue
        text = _bounded_scoped_text(root / record.path, record, limit)
        if text is None:
            continue
        for tool, pattern in patterns:
            for match in pattern.finditer(text):
                versions.setdefault(tool, set()).add(match.group(1).strip())
    return {key: sorted(items) for key, items in sorted(versions.items())}


def _submodule_declarations(
    root: Path, files: list[FileRecord]
) -> list[dict[str, str]]:
    record = next((item for item in files if item.path == ".gitmodules"), None)
    if record is None or record.sha256 is None or record.size > 1_000_000:
        return []
    text = _bounded_scoped_text(root / record.path, record, 1_000_000)
    if text is None:
        return []
    declarations: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for line in text.splitlines():
        section = re.fullmatch(r"\s*\[submodule\s+\"([^\"]+)\"\]\s*", line)
        if section:
            if current is not None:
                declarations.append(current)
            current = {"name": section.group(1)}
            continue
        setting = re.fullmatch(r"\s*(path|url|branch)\s*=\s*(.*?)\s*", line)
        if current is not None and setting:
            current[setting.group(1)] = setting.group(2)
    if current is not None:
        declarations.append(current)
    for declaration in declarations:
        path = declaration.get("path")
        if not path or not _safe_scoped_path(path):
            declaration["content_snapshot_sha256"] = "unavailable"
            continue
        prefix = path.rstrip("/") + "/"
        contents = [
            {"path": item.path, "sha256": item.sha256, "size": item.size}
            for item in files
            if item.path.startswith(prefix)
        ]
        declaration["content_snapshot_sha256"] = (
            sha256_bytes(canonical_json(contents).encode("utf-8"))
            if contents
            else "unavailable"
        )
        declaration["content_file_count"] = str(len(contents))
    return declarations[:256]
