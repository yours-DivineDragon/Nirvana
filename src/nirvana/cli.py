from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path

from .board import HypothesisBoard
from .differential import DifferentialManifest, compare
from .doctor import doctor_report
from .intake import IntakePolicy
from .ledger import EvidenceLedger
from .policy import CommandRunner, ExecutionMode, ExecutionPolicy
from .util import atomic_write_json
from .verification import snapshot_harness
from .workflow import audit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nirvana",
        description="Local, evidence-gated security research orchestration",
    )
    parser.add_argument("--version", action="version", version="nirvana 0.3.1")
    commands = parser.add_subparsers(dest="command", required=True)

    doctor = commands.add_parser("doctor", help="inspect local deterministic and verifier tooling")
    doctor.add_argument("--json", action="store_true", help="emit machine-readable output")

    audit_parser = commands.add_parser("audit", help="perform safe intake and candidate generation")
    audit_parser.add_argument("target", type=Path)
    audit_parser.add_argument("--output", type=Path, default=Path("nirvana-runs"))
    audit_parser.add_argument(
        "--policy", type=Path, help="shared TOML policy, including [intake] controls"
    )
    audit_parser.add_argument(
        "--solc-ast",
        type=Path,
        help="existing solc standard-JSON output for contextual AST candidates",
    )

    hypothesis = commands.add_parser("hypothesis", help="operate on the typed hypothesis board")
    hypothesis_commands = hypothesis.add_subparsers(dest="hypothesis_command", required=True)
    hypothesis_import = hypothesis_commands.add_parser("import", help="append a hypothesis JSON object")
    hypothesis_import.add_argument("run_directory", type=Path)
    hypothesis_import.add_argument("path", type=Path)
    hypothesis_list = hypothesis_commands.add_parser("list", help="list hypotheses from the ledger")
    hypothesis_list.add_argument("run_directory", type=Path)

    evidence = commands.add_parser("evidence", help="append typed evidence to a run ledger")
    evidence_commands = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_import = evidence_commands.add_parser("import")
    evidence_import.add_argument("run_directory", type=Path)
    evidence_import.add_argument("path", type=Path)
    evidence_run = evidence_commands.add_parser(
        "run", help="execute a reviewed request and mint an execution receipt"
    )
    evidence_run.add_argument("run_directory", type=Path)
    evidence_run.add_argument("path", type=Path, help="execution request JSON")
    _add_execution_options(evidence_run)
    evidence_verify = evidence_commands.add_parser(
        "verify", help="replay runner-minted evidence and compare its receipt"
    )
    evidence_verify.add_argument("run_directory", type=Path)
    evidence_verify.add_argument("evidence_id")
    _add_execution_options(evidence_verify)

    harness = commands.add_parser(
        "harness", help="inspect an auditor-owned verifier harness"
    )
    harness_commands = harness.add_subparsers(dest="harness_command", required=True)
    harness_hash = harness_commands.add_parser(
        "hash", help="hash a symlink-free harness directory"
    )
    harness_hash.add_argument("path", type=Path)
    finding = commands.add_parser("finding", help="validate and confirm an evidence-gated finding")
    finding_commands = finding.add_subparsers(dest="finding_command", required=True)
    finding_confirm = finding_commands.add_parser("confirm")
    finding_confirm.add_argument("run_directory", type=Path)
    finding_confirm.add_argument("path", type=Path)

    ledger = commands.add_parser("ledger", help="verify an evidence ledger")
    ledger_commands = ledger.add_subparsers(dest="ledger_command", required=True)
    ledger_verify = ledger_commands.add_parser("verify")
    ledger_verify.add_argument("path", type=Path)

    spec = commands.add_parser("spec", help="differential specification workflows")
    spec_commands = spec.add_subparsers(dest="spec_command", required=True)
    spec_compare = spec_commands.add_parser("compare", help="compare existing independent implementations")
    spec_compare.add_argument("manifest", type=Path)
    spec_compare.add_argument("--policy", type=Path)
    spec_compare.add_argument(
        "--execution-mode",
        choices=[mode.value for mode in ExecutionMode],
        default=ExecutionMode.DENY.value,
    )
    spec_compare.add_argument("--output", type=Path, default=Path("differential-report.json"))
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            report = doctor_report()
            if args.json:
                print(json.dumps(report, indent=2, sort_keys=True))
            else:
                for tool in report["tools"]:
                    marker = "yes" if tool["available"] else "no"
                    detail = f" ({tool['version']})" if tool["version"] else ""
                    print(f"{tool['name']}: {marker}{detail}")
            return 0
        if args.command == "audit":
            result = audit(
                args.target,
                args.output,
                IntakePolicy.load(args.policy),
                args.solc_ast,
            )
            print(result.run_directory)
            print(f"confirmed findings: 0; analyst hypotheses: {len(result.hypotheses)}")
            return 0
        if args.command == "hypothesis":
            board = HypothesisBoard(args.run_directory)
            if args.hypothesis_command == "import":
                imported = board.import_hypothesis(args.path)
                print(imported.hypothesis_id)
            else:
                print(json.dumps(board.list_hypotheses(), indent=2, sort_keys=True))
            return 0
        if args.command == "evidence":
            board = HypothesisBoard(args.run_directory)
            if args.evidence_command == "import":
                evidence_record = board.import_evidence(args.path)
            else:
                policy = ExecutionPolicy.load(args.policy)
                runner = CommandRunner(policy, ExecutionMode(args.execution_mode))
                if args.evidence_command == "run":
                    evidence_record = board.execute_evidence(args.path, runner)
                else:
                    evidence_record = board.verify_evidence(args.evidence_id, runner)
            print(evidence_record.evidence_id)
            return 0
        if args.command == "finding":
            confirmed = HypothesisBoard(args.run_directory).confirm_finding(args.path)
            print(confirmed.finding_id)
            return 0
        if args.command == "harness":
            print(json.dumps(snapshot_harness(args.path).to_dict(), indent=2, sort_keys=True))
            return 0
        if args.command == "ledger":
            count = EvidenceLedger(args.path).verify()
            print(f"ledger valid: {count} records")
            return 0
        if args.command == "spec":
            policy = ExecutionPolicy.load(args.policy)
            runner = CommandRunner(policy, ExecutionMode(args.execution_mode))
            report = compare(DifferentialManifest.load(args.manifest), runner)
            atomic_write_json(args.output.resolve(), report.to_dict())
            print(args.output.resolve())
            print(
                f"cases: {report.case_count}; mismatches: {len(report.mismatches)}; "
                f"blocked executions: {report.blocked_executions}"
            )
            for warning in report.warnings:
                print(f"warning: {warning}", file=sys.stderr)
            return 0
    except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 2


def _add_execution_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--policy", type=Path)
    parser.add_argument(
        "--execution-mode",
        choices=[mode.value for mode in ExecutionMode],
        default=ExecutionMode.DENY.value,
    )


if __name__ == "__main__":
    raise SystemExit(main())
