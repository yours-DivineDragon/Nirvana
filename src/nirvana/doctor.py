from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

from .util import jsonable


TOOLS = {
    "git": ["git", "--version"],
    "docker": ["docker", "--version"],
    "forge": ["forge", "--version"],
    "solc": ["solc", "--version"],
    "slither": ["slither", "--version"],
    "echidna": ["echidna", "--version"],
    "medusa": ["medusa", "version"],
    "halmos": ["halmos", "--version"],
}


@dataclass(slots=True)
class ToolStatus:
    name: str
    available: bool
    path: str | None
    version: str | None


def inspect_tools() -> list[ToolStatus]:
    statuses: list[ToolStatus] = []
    for name, command in TOOLS.items():
        executable = shutil.which(command[0])
        if executable is None:
            statuses.append(ToolStatus(name, False, None, None))
            continue
        version = None
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=5,
                check=False,
            )
            version = result.stdout.strip().splitlines()[0][:240] if result.stdout.strip() else None
        except (OSError, subprocess.TimeoutExpired):
            pass
        statuses.append(ToolStatus(name, True, executable, version))
    return statuses


def doctor_report() -> dict[str, Any]:
    statuses = inspect_tools()
    available = {item.name for item in statuses if item.available}
    return {
        "schema_version": "1.2.0",
        "tools": jsonable(statuses),
        "capabilities": {
            "intake": True,
            "evidence_ledger": True,
            "runtime_schema_validation": True,
            "deterministic_evm_candidates": True,
            "solc_ast_frontend": True,
            "runner_verified_structural_corroboration": True,
            "paired_control_health_invariants": True,
            "sandboxed_execution": "docker" in available,
            # Conservative host probe only. A pinned image may contain Forge even
            # when the host does not; that image still needs an actual test run.
            "executable_evm_verification": {"docker", "forge"} <= available,
        },
    }
