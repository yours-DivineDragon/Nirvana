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
    return {
        "schema_version": "1.0.0",
        "tools": jsonable(statuses),
        "capabilities": {
            "intake": True,
            "evidence_ledger": True,
            "deterministic_evm_candidates": True,
            "sandboxed_execution": any(item.name == "docker" and item.available for item in statuses),
            "executable_evm_verification": any(item.name == "forge" and item.available for item in statuses),
        },
    }
