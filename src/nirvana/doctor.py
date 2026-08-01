from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

from .models import SupportMaturity
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
    "cargo": ["cargo", "--version"],
    "pytest": ["pytest", "--version"],
    "node": ["node", "--version"],
    "java": ["java", "--version"],
    "sui": ["sui", "--version"],
    "anchor": ["anchor", "--version"],
    "wasmtime": ["wasmtime", "--version"],
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
    support = [
        {
            "dialect": "evm",
            "maturity": SupportMaturity.SYNTAX_ONLY.value,
            "potential_maturity": (
                SupportMaturity.TYPED.value
                if "solc" in available
                else SupportMaturity.SYNTAX_ONLY.value
            ),
            "detected_tools": sorted(available & {"solc", "forge", "slither", "echidna", "medusa", "halmos"}),
            "limitation": "doctor reports availability only; typed maturity requires a hash-bound compiler AST in a run, and runtime evidence is established per receipt",
        },
        *[
            {
                "dialect": dialect,
                "maturity": SupportMaturity.SYNTAX_ONLY.value,
                "potential_maturity": SupportMaturity.SYNTAX_ONLY.value,
                "detected_tools": sorted(available & tools),
                "limitation": "generic indexing only; compiler semantics and domain-complete verification are not claimed",
            }
            for dialect, tools in (
                ("solana", {"cargo", "anchor"}),
                ("move-sui", {"sui"}),
                ("rust-native", {"cargo"}),
                ("jvm", {"java"}),
                ("wasm", {"wasmtime"}),
                ("dlt-consensus", set()),
                ("web-api", {"pytest", "node"}),
            )
        ],
    ]
    return {
        "schema_version": "2.0.0",
        "tools": jsonable(statuses),
        "support_maturity": support,
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
