import json
import tempfile
import unittest
from pathlib import Path

from nirvana.differential import DifferentialManifest, compare, minimize_mismatch
from nirvana.differential_workflow import (
    attach_comparison_result,
    classify_mismatch,
    prepare_disclosure_packet,
    write_feedback_package,
)
from nirvana.ledger import EvidenceLedger, LedgerIntegrityError
from nirvana.models import MismatchClass
from nirvana.policy import CommandRunner, ExecutionMode, ExecutionPolicy
from nirvana.util import atomic_write_json, sha256_file
from nirvana.workflow import audit


DIFF_FIXTURE = Path(__file__).parent / "fixtures" / "differential"
EVM_FIXTURE = Path(__file__).parent / "fixtures" / "evm"


class DifferentialWorkflowTests(unittest.TestCase):
    def test_mismatch_enters_hypothesis_board_and_produces_disclosure_packet(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = CommandRunner(
                ExecutionPolicy(
                    allow_host_execution=True, accept_host_network_risk=True
                ),
                ExecutionMode.HOST,
            )
            manifest = DifferentialManifest.load(DIFF_FIXTURE / "manifest.toml")
            report = compare(manifest, runner)
            report_path = root / "report.json"
            atomic_write_json(report_path, report)
            audit_result = audit(EVM_FIXTURE, root / "runs")
            hypotheses = attach_comparison_result(
                audit_result.run_directory, report, report_path
            )
            self.assertEqual(len(hypotheses), 1)
            self.assertEqual(hypotheses[0].generator, "differential-analysis")
            attachment = next(
                json.loads(line)["payload"]
                for line in (audit_result.run_directory / "evidence.jsonl")
                .read_text()
                .splitlines()
                if json.loads(line)["payload"].get("event")
                == "differential_report_attached"
            )
            self.assertEqual(
                attachment["attachment_source"], "in_process_spec_compare"
            )
            projected_hypotheses = [
                json.loads(line)
                for line in (audit_result.run_directory / "hypotheses.jsonl")
                .read_text()
                .splitlines()
            ]
            ledger_hypotheses = [
                json.loads(line)["payload"]["hypothesis"]
                for line in (audit_result.run_directory / "evidence.jsonl")
                .read_text()
                .splitlines()
                if json.loads(line)["payload"].get("event")
                == "hypothesis_proposed"
            ]
            self.assertEqual(projected_hypotheses, ledger_hypotheses)
            records_after_first_attachment = len(
                (audit_result.run_directory / "evidence.jsonl").read_text().splitlines()
            )
            repeated = attach_comparison_result(
                audit_result.run_directory, report, report_path
            )
            self.assertEqual(
                [item.hypothesis_id for item in repeated],
                [item.hypothesis_id for item in hypotheses],
            )
            self.assertEqual(
                len((audit_result.run_directory / "evidence.jsonl").read_text().splitlines()),
                records_after_first_attachment,
            )

            triage_path = root / "triage.json"
            triage = classify_mismatch(
                report_path,
                "odd",
                MismatchClass.SPEC_AMBIGUITY,
                ["both interpretations are consistent with the unqualified rounding prose"],
                triage_path,
                audit_result.run_directory,
            )
            self.assertEqual(triage["classification"], "spec_ambiguity")
            classification_event = next(
                json.loads(line)["payload"]
                for line in (audit_result.run_directory / "evidence.jsonl")
                .read_text()
                .splitlines()
                if json.loads(line)["payload"].get("event")
                == "differential_mismatch_classified"
            )
            self.assertEqual(
                classification_event["report_sha256"],
                attachment["artifact_sha256"],
            )

            minimized = minimize_mismatch(manifest, runner, "odd", max_steps=16)
            minimization_path = root / "minimized.json"
            atomic_write_json(minimization_path, minimized)
            self.assertEqual(minimized["case_id"], "odd")
            self.assertLessEqual(
                len(json.dumps(minimized["minimized_input"])),
                len(json.dumps(minimized["original_input"])),
            )

            feedback_path = root / "feedback.json"
            feedback = write_feedback_package(
                triage_path,
                minimization_path,
                "Define integer division as floor toward negative infinity.",
                "Add the minimized odd input to the canonical corpus.",
                feedback_path,
                audit_result.run_directory,
            )
            self.assertEqual(feedback["corpus_case"]["input"], minimized["minimized_input"])

            context_path = root / "agent-context.json"
            context_path.write_text(
                json.dumps(
                    {
                        "agent": "codex",
                        "model": "local-agent-session",
                        "prompt_sha256": "b" * 64,
                        "tool_permissions": ["read", "sandboxed-execute"],
                        "untrusted_content_in_scope": True,
                        "prompt_injection_indicators": [],
                    }
                )
            )
            packet_path = root / "private-packet.json"
            packet = prepare_disclosure_packet(
                report_path,
                triage_path,
                minimization_path,
                context_path,
                "Different rounding can produce cross-client settlement disagreement.",
                packet_path,
                audit_result.run_directory,
            )
            self.assertFalse(packet["handling"]["automatic_delivery"])
            self.assertEqual(packet["classification"], "spec_ambiguity")
            self.assertEqual(len(packet["normalized_outputs"]), 2)

    def test_invalid_report_cannot_enter_the_run_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = compare(
                DifferentialManifest.load(DIFF_FIXTURE / "manifest.toml"),
                CommandRunner(ExecutionPolicy(), ExecutionMode.DENY),
            )
            report_path = root / "invalid-report.json"
            atomic_write_json(report_path, report)
            audit_result = audit(EVM_FIXTURE, root / "runs")
            with self.assertRaisesRegex(ValueError, "report is invalid"):
                attach_comparison_result(
                    audit_result.run_directory, report, report_path
                )

    def test_comparison_attachment_rejects_detached_output_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = compare(
                DifferentialManifest.load(DIFF_FIXTURE / "manifest.toml"),
                CommandRunner(
                    ExecutionPolicy(
                        allow_host_execution=True, accept_host_network_risk=True
                    ),
                    ExecutionMode.HOST,
                ),
            )
            report_path = root / "report.json"
            substituted = report.to_dict()
            substituted["warnings"].append("detached replacement")
            atomic_write_json(report_path, substituted)
            audit_result = audit(EVM_FIXTURE, root / "runs")

            with self.assertRaisesRegex(
                ValueError, "changed before its in-process attachment"
            ):
                attach_comparison_result(
                    audit_result.run_directory, report, report_path
                )

            events = [
                json.loads(line)["payload"]["event"]
                for line in (audit_result.run_directory / "evidence.jsonl")
                .read_text()
                .splitlines()
            ]
            self.assertNotIn("differential_report_attached", events)

    def test_classification_rejects_a_report_not_attached_to_the_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = CommandRunner(
                ExecutionPolicy(
                    allow_host_execution=True, accept_host_network_risk=True
                ),
                ExecutionMode.HOST,
            )
            report = compare(
                DifferentialManifest.load(DIFF_FIXTURE / "manifest.toml"), runner
            )
            report_path = root / "report.json"
            atomic_write_json(report_path, report)
            audit_result = audit(EVM_FIXTURE, root / "runs")
            attach_comparison_result(audit_result.run_directory, report, report_path)

            unattached = report.to_dict()
            unattached["warnings"].append("invented detached report")
            unattached_path = root / "unattached-report.json"
            atomic_write_json(unattached_path, unattached)
            ledger_path = audit_result.run_directory / "evidence.jsonl"
            records_before = ledger_path.read_text()

            with self.assertRaisesRegex(ValueError, "not attached to this run"):
                classify_mismatch(
                    unattached_path,
                    "odd",
                    MismatchClass.IMPLEMENTATION_BUG,
                    ["detached reports must not enter the run ledger"],
                    root / "triage.json",
                    audit_result.run_directory,
                )

            self.assertEqual(ledger_path.read_text(), records_before)
            self.assertFalse((root / "triage.json").exists())

    def test_ledger_verify_revalidates_attached_differential_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = CommandRunner(
                ExecutionPolicy(
                    allow_host_execution=True, accept_host_network_risk=True
                ),
                ExecutionMode.HOST,
            )
            report = compare(
                DifferentialManifest.load(DIFF_FIXTURE / "manifest.toml"), runner
            )
            report_path = root / "report.json"
            atomic_write_json(report_path, report)
            audit_result = audit(EVM_FIXTURE, root / "runs")
            attach_comparison_result(audit_result.run_directory, report, report_path)
            ledger = EvidenceLedger(audit_result.run_directory / "evidence.jsonl")
            attachment = next(
                record["payload"]
                for record in ledger.records()
                if record["payload"].get("event")
                == "differential_report_attached"
            )
            attached_path = Path(attachment["artifact_path"])
            attached = json.loads(attached_path.read_text())
            attached["mismatches"] = []
            atomic_write_json(attached_path, attached)
            self.assertNotEqual(
                sha256_file(attached_path), attachment["artifact_sha256"]
            )

            with self.assertRaisesRegex(
                LedgerIntegrityError, "attached differential report"
            ):
                ledger.verify()

    def test_self_declared_validity_cannot_bypass_downstream_gates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = compare(
                DifferentialManifest.load(DIFF_FIXTURE / "manifest.toml"),
                CommandRunner(ExecutionPolicy(), ExecutionMode.DENY),
            ).to_dict()
            self.assertEqual(report["successful_executions"], 0)
            self.assertGreater(report["blocked_executions"], 0)
            report["valid"] = True
            report_path = root / "boolean-flipped-report.json"
            atomic_write_json(report_path, report)

            operations = {
                "classify": lambda: classify_mismatch(
                    report_path,
                    "odd",
                    MismatchClass.IMPLEMENTATION_BUG,
                    ["must never be reached"],
                    root / "triage.json",
                ),
                "disclose": lambda: prepare_disclosure_packet(
                    report_path,
                    root / "missing-triage.json",
                    root / "missing-minimization.json",
                    root / "missing-context.json",
                    "must never be reached",
                    root / "packet.json",
                ),
            }
            for name, operation in operations.items():
                with self.subTest(workflow=name):
                    with self.assertRaisesRegex(ValueError, "validity conflicts"):
                        operation()


if __name__ == "__main__":
    unittest.main()
