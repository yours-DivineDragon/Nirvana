from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path

from .adjudication import AdjudicationBoard
from .baseline import run_baseline
from .benchmark_pack import (
    benchmark_target_snapshot,
    write_case_pack_report,
    write_ground_truth_commitment,
)
from .benchmark_ledger import seal_benchmark_trial
from .board import HypothesisBoard
from .coverage import CoverageBoard
from .differential import DifferentialManifest, compare, minimize_mismatch
from .differential_workflow import (
    attach_report,
    classify_mismatch,
    prepare_disclosure_packet,
    write_feedback_package,
)
from .deployment import verify_deployments
from .doctor import doctor_report
from .evaluation import write_benchmark_report
from .intake import IntakePolicy
from .ledger import EvidenceLedger
from .learning import review_detector_candidate
from .models import MismatchClass
from .policy import CommandRunner, ExecutionMode, ExecutionPolicy
from .util import atomic_write_json, sha256_file
from .verification import snapshot_harness
from .variants import mine_historical_variants
from .workflow import audit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nirvana",
        description="Local, evidence-gated security research orchestration",
    )
    parser.add_argument("--version", action="version", version="nirvana 0.4.8")
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
        "--baseline-request",
        type=Path,
        help="reviewed build/test baseline request executed before semantic analysis",
    )
    audit_parser.add_argument(
        "--execution-mode",
        choices=[mode.value for mode in ExecutionMode],
        default=ExecutionMode.DENY.value,
        help="execution mode used only when --baseline-request is supplied",
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
    hypothesis_critique = hypothesis_commands.add_parser(
        "critique", help="record a typed Devil's Advocate or Rescue Critic decision"
    )
    hypothesis_critique.add_argument("run_directory", type=Path)
    hypothesis_critique.add_argument("path", type=Path)

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
    finding_novelty = finding_commands.add_parser(
        "novelty", help="classify a confirmed finding against a provenance-bearing corpus"
    )
    finding_novelty.add_argument("run_directory", type=Path)
    finding_novelty.add_argument("finding_id")
    finding_novelty.add_argument("corpus", type=Path)

    baseline = commands.add_parser("baseline", help="run detected build and test baselines")
    baseline_commands = baseline.add_subparsers(dest="baseline_command", required=True)
    baseline_run = baseline_commands.add_parser("run")
    baseline_run.add_argument("run_directory", type=Path)
    baseline_run.add_argument("request", type=Path)
    _add_execution_options(baseline_run)

    coverage = commands.add_parser("coverage", help="inspect or update flow × threat coverage")
    coverage_commands = coverage.add_subparsers(dest="coverage_command", required=True)
    coverage_list = coverage_commands.add_parser("list")
    coverage_list.add_argument("run_directory", type=Path)
    coverage_mark = coverage_commands.add_parser("mark")
    coverage_mark.add_argument("run_directory", type=Path)
    coverage_mark.add_argument("task_id")
    coverage_mark.add_argument("--status", choices=["in_progress", "covered", "blocked"], required=True)
    coverage_mark.add_argument("--evidence", action="append", default=[])
    coverage_mark.add_argument("--note", action="append", default=[])
    coverage_mark.add_argument("--reached-node", action="append", default=[])

    ledger = commands.add_parser("ledger", help="verify an evidence ledger")
    ledger_commands = ledger.add_subparsers(dest="ledger_command", required=True)
    ledger_verify = ledger_commands.add_parser("verify")
    ledger_verify.add_argument("path", type=Path)
    ledger_checkpoint = ledger_commands.add_parser("checkpoint")
    ledger_checkpoint.add_argument("path", type=Path)
    ledger_checkpoint.add_argument("--output", type=Path, default=Path("ledger-checkpoint.json"))
    ledger_verify_checkpoint = ledger_commands.add_parser("verify-checkpoint")
    ledger_verify_checkpoint.add_argument("path", type=Path)
    ledger_verify_checkpoint.add_argument("checkpoint", type=Path)

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
    spec_compare.add_argument(
        "--run-directory", type=Path, help="attach mismatches to an audit run as localised hypotheses"
    )
    spec_attach = spec_commands.add_parser("attach", help="attach an existing report to a run")
    spec_attach.add_argument("run_directory", type=Path)
    spec_attach.add_argument("report", type=Path)
    spec_classify = spec_commands.add_parser("classify", help="durably classify one mismatch")
    spec_classify.add_argument("report", type=Path)
    spec_classify.add_argument("case_id")
    spec_classify.add_argument("classification", choices=[item.value for item in MismatchClass if item is not MismatchClass.UNCLASSIFIED])
    spec_classify.add_argument("--rationale", action="append", required=True)
    spec_classify.add_argument("--output", type=Path, default=Path("differential-triage.json"))
    spec_classify.add_argument("--run-directory", type=Path)
    spec_minimize = spec_commands.add_parser("minimize", help="delta-minimize a stable divergent JSON seed")
    spec_minimize.add_argument("manifest", type=Path)
    spec_minimize.add_argument("case_id")
    spec_minimize.add_argument("--max-steps", type=int, default=128)
    spec_minimize.add_argument("--output", type=Path, default=Path("differential-minimization.json"))
    _add_execution_options(spec_minimize)
    spec_feedback = spec_commands.add_parser("feedback", help="create a reviewed spec-and-test feedback proposal")
    spec_feedback.add_argument("triage", type=Path)
    spec_feedback.add_argument("minimization", type=Path)
    spec_feedback.add_argument("--spec-amendment", required=True)
    spec_feedback.add_argument("--regression-test", required=True)
    spec_feedback.add_argument("--output", type=Path, default=Path("differential-feedback.json"))
    spec_feedback.add_argument("--run-directory", type=Path)

    disclose = commands.add_parser("disclose", help="prepare, but never send, a private disclosure packet")
    disclose_commands = disclose.add_subparsers(dest="disclose_command", required=True)
    disclose_prepare = disclose_commands.add_parser("prepare")
    disclose_prepare.add_argument("report", type=Path)
    disclose_prepare.add_argument("triage", type=Path)
    disclose_prepare.add_argument("minimization", type=Path)
    disclose_prepare.add_argument("agent_context", type=Path)
    disclose_prepare.add_argument("--impact", required=True)
    disclose_prepare.add_argument("--output", type=Path, default=Path("private-disclosure-packet.json"))
    disclose_prepare.add_argument("--run-directory", type=Path)

    benchmark = commands.add_parser("benchmark", help="compute contamination-aware security evaluation metrics")
    benchmark_commands = benchmark.add_subparsers(dest="benchmark_command", required=True)
    benchmark_evaluate = benchmark_commands.add_parser("evaluate")
    benchmark_evaluate.add_argument("manifest", type=Path)
    benchmark_evaluate.add_argument(
        "--output",
        type=Path,
        help="report path; defaults to benchmark-report.json beside the manifest",
    )
    benchmark_verify_pack = benchmark_commands.add_parser(
        "verify-pack", help="verify an independently authored encrypted case pack"
    )
    benchmark_verify_pack.add_argument("case_pack", type=Path)
    benchmark_verify_pack.add_argument(
        "--output",
        type=Path,
        help="report path; defaults to benchmark-case-pack-report.json beside the pack",
    )
    benchmark_hash_target = benchmark_commands.add_parser(
        "hash-target", help="compute the canonical benchmark target snapshot"
    )
    benchmark_hash_target.add_argument("target", type=Path)
    benchmark_hash_target.add_argument(
        "--json", action="store_true", help="print the complete snapshot record"
    )
    benchmark_commit_ground_truth = benchmark_commands.add_parser(
        "commit-ground-truth",
        help="create a public commitment from a canonical ground-truth reveal",
    )
    benchmark_commit_ground_truth.add_argument("ground_truth", type=Path)
    benchmark_commit_ground_truth.add_argument(
        "--output",
        type=Path,
        help="commitment path; defaults to <ground-truth>.commitment.json",
    )
    benchmark_seal_trial = benchmark_commands.add_parser(
        "seal-trial",
        help="seal a completed run's findings and export its ledger checkpoint",
    )
    benchmark_seal_trial.add_argument("run_directory", type=Path)
    benchmark_seal_trial.add_argument("--trial-id", required=True)
    benchmark_seal_trial.add_argument("--case-id", required=True)
    benchmark_seal_trial.add_argument("--seed", required=True, type=int)
    benchmark_seal_trial.add_argument(
        "--output",
        type=Path,
        help="checkpoint path; defaults to benchmark-trial-checkpoint.json in the run",
    )

    deployment = commands.add_parser("deployment", help="verify local source/build bytecode against captured deployed bytecode")
    deployment_commands = deployment.add_subparsers(dest="deployment_command", required=True)
    deployment_verify = deployment_commands.add_parser("verify")
    deployment_verify.add_argument("run_directory", type=Path)
    deployment_verify.add_argument("attestation", type=Path)

    learning = commands.add_parser("learning", help="review regression and detector-distillation candidates")
    learning_commands = learning.add_subparsers(dest="learning_command", required=True)
    learning_review = learning_commands.add_parser("review")
    learning_review.add_argument("run_directory", type=Path)
    learning_review.add_argument("review", type=Path)

    variant = commands.add_parser("variant", help="mine provenance-bearing historical issue corpora")
    variant_commands = variant.add_subparsers(dest="variant_command", required=True)
    variant_mine = variant_commands.add_parser("mine")
    variant_mine.add_argument("run_directory", type=Path)
    variant_mine.add_argument("corpus", type=Path)
    variant_mine.add_argument("--cutoff", help="exclude corpus entries published after this ISO timestamp")
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
            execution_policy = ExecutionPolicy.load(args.policy)
            result = audit(
                args.target,
                args.output,
                IntakePolicy.load(args.policy),
                args.solc_ast,
                args.baseline_request,
                CommandRunner(execution_policy, ExecutionMode(args.execution_mode))
                if args.baseline_request is not None
                else None,
            )
            print(result.run_directory)
            print(f"confirmed findings: 0; analyst hypotheses: {len(result.hypotheses)}")
            return 0
        if args.command == "hypothesis":
            if args.hypothesis_command == "critique":
                decision = AdjudicationBoard(args.run_directory).submit_critic_decision(args.path)
                print(decision["status"])
                return 0
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
            if args.finding_command == "confirm":
                confirmed = HypothesisBoard(args.run_directory).confirm_finding(args.path)
                print(confirmed.finding_id)
            else:
                assessment = AdjudicationBoard(args.run_directory).assess_novelty(
                    args.finding_id, args.corpus
                )
                print(assessment["classification"])
            return 0
        if args.command == "baseline":
            policy = ExecutionPolicy.load(args.policy)
            runner = CommandRunner(policy, ExecutionMode(args.execution_mode))
            receipt = run_baseline(args.run_directory, args.request, runner)
            print(f"build: {receipt.build_status}; tests: {receipt.test_status}")
            return 0
        if args.command == "coverage":
            board = CoverageBoard(args.run_directory)
            if args.coverage_command == "list":
                print(json.dumps(board.load().to_dict(), indent=2, sort_keys=True))
            else:
                manifest = board.mark(
                    args.task_id,
                    args.status,
                    args.evidence,
                    args.note,
                    args.reached_node,
                )
                print(f"coverage: {manifest.completeness['flow_threat_tasks']:.1%}")
            return 0
        if args.command == "harness":
            print(json.dumps(snapshot_harness(args.path).to_dict(), indent=2, sort_keys=True))
            return 0
        if args.command == "ledger":
            ledger = EvidenceLedger(args.path)
            if args.ledger_command == "verify":
                count = ledger.verify()
                print(f"ledger valid: {count} records")
            elif args.ledger_command == "checkpoint":
                checkpoint = ledger.export_checkpoint(args.output)
                print(args.output.resolve())
                print(f"checkpointed through record {checkpoint['sequence']}")
            else:
                sequence = ledger.verify_checkpoint(args.checkpoint)
                print(f"checkpoint valid through record {sequence}")
            return 0
        if args.command == "spec":
            if args.spec_command == "attach":
                hypotheses = attach_report(args.run_directory, args.report)
                print(f"attached hypotheses: {len(hypotheses)}")
                return 0
            if args.spec_command == "classify":
                triage = classify_mismatch(
                    args.report,
                    args.case_id,
                    MismatchClass(args.classification),
                    args.rationale,
                    args.output,
                    args.run_directory,
                )
                print(args.output.resolve())
                print(triage["classification"])
                return 0
            if args.spec_command == "feedback":
                write_feedback_package(
                    args.triage,
                    args.minimization,
                    args.spec_amendment,
                    args.regression_test,
                    args.output,
                    args.run_directory,
                )
                print(args.output.resolve())
                return 0
            policy = ExecutionPolicy.load(args.policy)
            runner = CommandRunner(policy, ExecutionMode(args.execution_mode))
            if args.spec_command == "minimize":
                minimized = minimize_mismatch(
                    DifferentialManifest.load(args.manifest),
                    runner,
                    args.case_id,
                    args.max_steps,
                )
                from .contracts import validate_contract

                validate_contract(minimized, "differential-minimization.schema.json")
                atomic_write_json(args.output.resolve(), minimized)
                print(args.output.resolve())
                return 0
            report = compare(DifferentialManifest.load(args.manifest), runner)
            atomic_write_json(args.output.resolve(), report.to_dict())
            if not report.valid:
                print(
                    "INVALID differential run: "
                    f"blocked executions: {report.blocked_executions}; "
                    f"successful executions: {report.successful_executions}/"
                    f"{report.scheduled_executions}"
                )
                for reason in report.invalid_reasons:
                    print(f"invalid: {reason}")
                print(f"report: {args.output.resolve()}")
                return 2
            if args.run_directory is not None:
                attach_report(args.run_directory, args.output)
            print(args.output.resolve())
            print(
                f"cases: {report.case_count}; comparable cases: {report.comparable_case_count}; "
                f"mismatches: {len(report.mismatches)}; "
                f"unnormalizable cases: {report.unnormalizable_case_count}; "
                f"blocked executions: {report.blocked_executions}"
            )
            for warning in report.warnings:
                print(f"warning: {warning}", file=sys.stderr)
            return 0
        if args.command == "disclose":
            prepare_disclosure_packet(
                args.report,
                args.triage,
                args.minimization,
                args.agent_context,
                args.impact,
                args.output,
                args.run_directory,
            )
            print(args.output.resolve())
            print("private packet created; no disclosure was sent")
            return 0
        if args.command == "benchmark":
            if args.benchmark_command == "hash-target":
                snapshot = benchmark_target_snapshot(args.target)
                if args.json:
                    print(json.dumps(snapshot, sort_keys=True))
                else:
                    print(snapshot["target_snapshot_sha256"])
                return 0
            if args.benchmark_command == "commit-ground-truth":
                output = (
                    args.output.resolve()
                    if args.output is not None
                    else args.ground_truth.resolve(strict=True).with_suffix(
                        ".commitment.json"
                    )
                )
                commitment = write_ground_truth_commitment(
                    args.ground_truth, output
                )
                print(output)
                print(
                    "public commitment: "
                    f"{commitment['public_commitment_sha256']}"
                )
                print(f"commitment artifact: {sha256_file(output)}")
                return 0
            if args.benchmark_command == "seal-trial":
                run_directory = args.run_directory.resolve(strict=True)
                output = (
                    args.output.resolve()
                    if args.output is not None
                    else run_directory / "benchmark-trial-checkpoint.json"
                )
                sealed = seal_benchmark_trial(
                    run_directory,
                    trial_id=args.trial_id,
                    case_id=args.case_id,
                    seed=args.seed,
                    output=output,
                )
                print(output)
                print(f"checkpoint: {sealed['checkpoint_sha256']}")
                print(
                    f"sealed trial {args.trial_id}: "
                    f"{len(sealed['seal']['findings'])} findings"
                )
                print(f"coverage: {sealed['seal']['coverage_sha256']}")
                print(
                    "coverage values: "
                    + json.dumps(sealed["seal"]["coverage"], sort_keys=True)
                )
                return 0
            if args.benchmark_command == "verify-pack":
                output = (
                    args.output.resolve()
                    if args.output is not None
                    else args.case_pack.resolve(strict=True).with_name(
                        "benchmark-case-pack-report.json"
                    )
                )
                report = write_case_pack_report(args.case_pack, output)
                print(output)
                print(
                    f"verified independent case pack: {report['pack_id']}; "
                    f"cases: {report['case_count']}"
                )
                return 0
            output = (
                args.output.resolve()
                if args.output is not None
                else args.manifest.resolve(strict=True).with_name("benchmark-report.json")
            )
            report = write_benchmark_report(args.manifest, output)
            if not report["valid"]:
                print("INVALID benchmark: validation failed; metrics suppressed")
                for violation in report["invalid_reasons"]:
                    print(f"violation: {violation}")
                print(f"report: {output}")
                return 2
            print(output)
            print(
                f"precision: {report['metrics']['validated_precision']}; "
                f"recall: {report['metrics']['ground_truth_recall']}"
            )
            closed_beta = report["release_gates"]["closed_beta"]
            print(
                f"closed beta: {'passed' if closed_beta['passed'] else 'not passed'}; "
                f"suite qualified: {closed_beta['suite_qualified']}"
            )
            for warning in report["warnings"]:
                print(f"warning: {warning}", file=sys.stderr)
            return 0
        if args.command == "deployment":
            report = verify_deployments(args.run_directory, args.attestation)
            print(f"deployments: {len(report['entries'])}; all match: {report['all_match']}")
            return 0
        if args.command == "learning":
            outcome = review_detector_candidate(args.run_directory, args.review)
            print(outcome["status"])
            return 0
        if args.command == "variant":
            hypotheses = mine_historical_variants(
                args.run_directory, args.corpus, args.cutoff
            )
            print(f"variant hypotheses: {len(hypotheses)}")
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
