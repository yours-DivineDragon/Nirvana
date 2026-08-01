from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
import tomllib
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class ExecutionMode(StrEnum):
    DENY = "deny"
    HOST = "host"
    DOCKER = "docker"


@dataclass(slots=True)
class ExecutionPolicy:
    allow_host_execution: bool = False
    allow_network: bool = False
    allow_git_writes: bool = False
    allow_live_chain: bool = False
    allow_secret_environment: bool = False
    timeout_seconds: int = 30
    max_output_bytes: int = 1_000_000
    docker_image: str | None = None
    environment_allowlist: list[str] = field(default_factory=lambda: ["LANG", "LC_ALL", "PATH"])

    def __post_init__(self) -> None:
        if self.timeout_seconds < 1 or self.max_output_bytes < 1:
            raise ValueError("execution limits must be positive")

    @classmethod
    def load(cls, path: Path | None) -> "ExecutionPolicy":
        if path is None:
            return cls()
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
        execution = raw.get("execution", {})
        return cls(
            allow_host_execution=bool(execution.get("allow_host_execution", False)),
            allow_network=bool(execution.get("allow_network", False)),
            allow_git_writes=bool(execution.get("allow_git_writes", False)),
            allow_live_chain=bool(execution.get("allow_live_chain", False)),
            allow_secret_environment=bool(execution.get("allow_secret_environment", False)),
            timeout_seconds=int(execution.get("timeout_seconds", 30)),
            max_output_bytes=int(execution.get("max_output_bytes", 1_000_000)),
            docker_image=execution.get("docker_image"),
            environment_allowlist=list(execution.get("environment_allowlist", ["LANG", "LC_ALL", "PATH"])),
        )


@dataclass(slots=True)
class CommandResult:
    command: list[str]
    return_code: int | None
    stdout: bytes
    stderr: bytes
    duration_ms: int
    blocked_reason: str | None = None
    timed_out: bool = False


class CommandRunner:
    def __init__(self, policy: ExecutionPolicy, mode: ExecutionMode):
        self.policy = policy
        self.mode = mode

    def run(self, command: list[str], cwd: Path, stdin: bytes = b"") -> CommandResult:
        if not command or any(not isinstance(part, str) or "\x00" in part for part in command):
            raise ValueError("command must be a non-empty list of safe strings")
        resolved_cwd = cwd.resolve(strict=True)
        if self.mode is ExecutionMode.DENY:
            return CommandResult(command, None, b"", b"", 0, "execution is denied by default")
        blocked_reason = self._blocked_capability(command)
        if blocked_reason:
            return CommandResult(command, None, b"", b"", 0, blocked_reason)
        if self.mode is ExecutionMode.HOST:
            if not self.policy.allow_host_execution:
                return CommandResult(command, None, b"", b"", 0, "host execution is not allowed by policy")
            if not self.policy.allow_network:
                return CommandResult(
                    command,
                    None,
                    b"",
                    b"",
                    0,
                    "host mode cannot enforce network isolation; use Docker or explicitly accept host networking",
                )
            return self._run_host(command, resolved_cwd, stdin)
        return self._run_docker(command, resolved_cwd, stdin)

    def _safe_environment(self) -> dict[str, str]:
        sensitive = re.compile(r"TOKEN|SECRET|PASSWORD|CREDENTIAL|COOKIE|AUTH|PRIVATE|API[_-]?KEY", re.I)
        environment: dict[str, str] = {}
        for key in self.policy.environment_allowlist:
            if key not in os.environ:
                continue
            if not self.policy.allow_secret_environment and sensitive.search(key):
                continue
            environment[key] = os.environ[key]
        if "PATH" in environment:
            path_parts = [
                item
                for item in environment["PATH"].split(os.pathsep)
                if item and Path(item).is_absolute()
            ]
            environment["PATH"] = os.pathsep.join(path_parts)
        environment.setdefault("LANG", "C.UTF-8")
        environment.setdefault("LC_ALL", "C.UTF-8")
        return environment

    def _blocked_capability(self, command: list[str]) -> str | None:
        executable = Path(command[0]).name.lower()
        arguments = {item.lower() for item in command[1:]}
        git_writes = {
            "add",
            "am",
            "apply",
            "branch",
            "checkout",
            "cherry-pick",
            "commit",
            "merge",
            "mv",
            "push",
            "rebase",
            "reset",
            "restore",
            "revert",
            "rm",
            "switch",
            "tag",
        }
        if executable == "git" and not self.policy.allow_git_writes and arguments & git_writes:
            return "git mutation is not allowed by policy"
        if not self.policy.allow_live_chain:
            if "--broadcast" in arguments:
                return "live-chain broadcast is not allowed by policy"
            if executable == "cast" and arguments & {"send", "publish", "mktx"}:
                return "live-chain transaction tooling is not allowed by policy"
        return None

    def _run_host(self, command: list[str], cwd: Path, stdin: bytes) -> CommandResult:
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                cwd=cwd,
                input=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.policy.timeout_seconds,
                env=self._safe_environment(),
                shell=False,
                check=False,
            )
            stdout = completed.stdout[: self.policy.max_output_bytes]
            stderr = completed.stderr[: self.policy.max_output_bytes]
            return CommandResult(
                command,
                completed.returncode,
                stdout,
                stderr,
                int((time.monotonic() - started) * 1000),
            )
        except subprocess.TimeoutExpired as error:
            return CommandResult(
                command,
                None,
                (error.stdout or b"")[: self.policy.max_output_bytes],
                (error.stderr or b"")[: self.policy.max_output_bytes],
                int((time.monotonic() - started) * 1000),
                timed_out=True,
            )

    def _run_docker(self, command: list[str], cwd: Path, stdin: bytes) -> CommandResult:
        docker = shutil.which("docker")
        if docker is None:
            return CommandResult(command, None, b"", b"", 0, "docker is unavailable")
        if not self.policy.docker_image:
            return CommandResult(command, None, b"", b"", 0, "policy does not select a pinned docker image")
        if not re.fullmatch(r"[^\s@]+@sha256:[a-f0-9]{64}", self.policy.docker_image):
            return CommandResult(command, None, b"", b"", 0, "docker image must be pinned by SHA-256 digest")
        network = "bridge" if self.policy.allow_network else "none"
        docker_command = [
            docker,
            "run",
            "--rm",
            "--interactive",
            "--network",
            network,
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=256",
            "--memory=2g",
            "--tmpfs=/tmp:rw,noexec,nosuid,size=256m",
            "--mount",
            f"type=bind,src={cwd},dst=/workspace,readonly",
            "--workdir=/workspace",
            self.policy.docker_image,
            *command,
        ]
        return self._run_host_docker(docker_command, cwd, stdin)

    def _run_host_docker(self, command: list[str], cwd: Path, stdin: bytes) -> CommandResult:
        # Docker is the sandbox boundary, so invoking the Docker client does not
        # require allow_host_execution. The target remains read-only and isolated.
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                cwd=cwd,
                input=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.policy.timeout_seconds,
                env=self._safe_environment(),
                shell=False,
                check=False,
            )
            return CommandResult(
                command,
                completed.returncode,
                completed.stdout[: self.policy.max_output_bytes],
                completed.stderr[: self.policy.max_output_bytes],
                int((time.monotonic() - started) * 1000),
            )
        except subprocess.TimeoutExpired as error:
            return CommandResult(
                command,
                None,
                (error.stdout or b"")[: self.policy.max_output_bytes],
                (error.stderr or b"")[: self.policy.max_output_bytes],
                int((time.monotonic() - started) * 1000),
                timed_out=True,
            )
