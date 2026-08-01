import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nirvana.board import HypothesisBoard
from nirvana.ledger import EvidenceLedger
from nirvana.models import EvidenceLevel
from nirvana.policy import CommandResult, CommandRunner, ExecutionMode, ExecutionPolicy
from nirvana.util import sha256_file
from nirvana.workflow import audit


FIXTURE = Path(__file__).parent / "fixtures" / "evm"


class BoardTests(unittest.TestCase):
    def test_import_evidence_and_enforce_finding_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            evidence_path = root / "evidence.json"
            evidence_path.write_text(
                json.dumps(
                    {
                        "evidence_id": "E-1",
                        "hypothesis_id": result.hypotheses[0].hypothesis_id,
                        "level": EvidenceLevel.LOCALISED.value,
                        "kind": "manual_slice",
                        "summary": "Exact code site inspected",
                        "source": "analyst",
                    }
                )
            )
            board = HypothesisBoard(result.run_directory)
            board.import_evidence(evidence_path)
            self.assertEqual(EvidenceLedger(result.run_directory / "evidence.jsonl").verify(), 5)

            finding_path = root / "finding.json"
            finding_path.write_text(
                json.dumps(
                    {
                        "finding_id": "F-1",
                        "hypothesis_id": result.hypotheses[0].hypothesis_id,
                        "title": "Unproven",
                        "severity": "high",
                        "evidence_level": "structurally_confirmed",
                        "security_property": "property",
                        "root_cause": "cause",
                        "locations": [{"path": "src/Vault.sol", "line_start": 1}],
                        "attacker_prerequisites": ["caller"],
                        "assumptions": ["assumption"],
                        "causal_path": ["input", "effect"],
                        "reproducer": "test",
                        "impact": "impact",
                        "reproduction_instructions": ["run test"],
                        "remediation": "fix",
                        "regression_test": "test fix",
                    }
                )
            )
            with self.assertRaisesRegex(ValueError, "executable evidence"):
                board.confirm_finding(finding_path)

    def test_confirmed_level_cannot_exceed_recorded_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            hypothesis_id = result.hypotheses[0].hypothesis_id
            evidence_path = root / "evidence.json"
            evidence_path.write_text(
                json.dumps(
                    {
                        "evidence_id": "E-LOCAL",
                        "hypothesis_id": hypothesis_id,
                        "level": "localised",
                        "kind": "manual_slice",
                        "summary": "Exact code site inspected",
                        "source": "analyst",
                    }
                )
            )
            board = HypothesisBoard(result.run_directory)
            board.import_evidence(evidence_path)
            finding_path = root / "finding.json"
            finding_path.write_text(
                json.dumps(
                    {
                        "finding_id": "F-STRUCTURAL",
                        "hypothesis_id": hypothesis_id,
                        "title": "Unsupported promotion",
                        "severity": "medium",
                        "evidence_level": "structurally_confirmed",
                        "security_property": "property",
                        "root_cause": "cause",
                        "locations": [{"path": "src/Vault.sol", "line_start": 13}],
                        "attacker_prerequisites": ["caller"],
                        "assumptions": ["assumption"],
                        "causal_path": ["input", "effect"],
                        "reproducer": "test",
                        "impact": "impact",
                        "reproduction_instructions": ["run test"],
                        "remediation": "fix",
                        "regression_test": "test fix",
                    }
                )
            )
            with self.assertRaisesRegex(ValueError, "run evidence ceiling"):
                board.confirm_finding(finding_path)

    def test_imported_executable_evidence_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            hypothesis_id = result.hypotheses[0].hypothesis_id
            artifact = root / "poc.txt"
            artifact.write_text("fabricated counterexample\n")
            evidence_path = root / "evidence.json"
            evidence_path.write_text(
                json.dumps(
                    {
                        "evidence_id": "E-POC",
                        "hypothesis_id": hypothesis_id,
                        "level": "executable",
                        "kind": "failing_test",
                        "summary": "A reviewed fixture produced the counterexample",
                        "source": "test",
                        "artifact_path": str(artifact),
                        "artifact_sha256": sha256_file(artifact),
                        "command": ["nonexistent-verifier", "--prove"],
                    }
                )
            )
            board = HypothesisBoard(result.run_directory)
            with self.assertRaisesRegex(ValueError, "must be minted"):
                board.import_evidence(evidence_path)

    def test_runner_minted_and_replayed_evidence_can_confirm(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            hypothesis_id = result.hypotheses[0].hypothesis_id
            request_path = root / "execution-request.json"
            command = ["fixture-verifier", "--check"]
            request_path.write_text(
                json.dumps(
                    {
                        "evidence_id": "E-POC",
                        "hypothesis_id": hypothesis_id,
                        "kind": "failing_test",
                        "summary": "The reviewed fixture produced a counterexample",
                        "command": command,
                        "expected_return_codes": [1],
                        "tool_version": "fixture-1",
                    }
                )
            )
            policy = ExecutionPolicy(docker_image="fixture@sha256:" + "a" * 64)
            runner = CommandRunner(policy, ExecutionMode.DOCKER)
            observed = CommandResult(command, 1, b"counterexample\n", b"", 4)
            board = HypothesisBoard(result.run_directory)
            with patch.object(runner, "run", return_value=observed) as run:
                evidence = board.execute_evidence(request_path, runner)
                self.assertEqual(evidence.source, "nirvana:command-runner")
                self.assertTrue(evidence.metadata["runner_minted"])

                finding_path = root / "finding.json"
                finding_path.write_text(
                    json.dumps(
                        {
                            "finding_id": "F-POC",
                            "hypothesis_id": hypothesis_id,
                            "title": "Executable fixture finding",
                            "severity": "high",
                            "evidence_level": "executable",
                            "security_property": "Authorization is bound to the caller",
                            "root_cause": "The fixture uses an unsafe caller identity",
                            "locations": [{"path": "src/Vault.sol", "line_start": 13}],
                            "attacker_prerequisites": ["intermediary contract"],
                            "assumptions": ["fixture semantics"],
                            "causal_path": ["intermediary", "tx.origin", "authority branch"],
                            "reproducer": str(evidence.artifact_path),
                            "impact": "Unauthorized behavior in the fixture",
                            "reproduction_instructions": ["run the fixture verifier"],
                            "remediation": "Bind authorization to the intended caller",
                            "regression_test": "Reject the intermediary caller",
                        }
                    )
                )
                with self.assertRaisesRegex(ValueError, "run evidence ceiling"):
                    board.confirm_finding(finding_path)

                board.verify_evidence(evidence.evidence_id, runner)
                board.confirm_finding(finding_path)

            self.assertEqual(run.call_count, 2)
            report = json.loads((result.run_directory / "report.json").read_text())
            self.assertEqual([item["finding_id"] for item in report["confirmed_findings"]], ["F-POC"])
            self.assertEqual(report["evidence_ceiling"], "executable")
            self.assertEqual(EvidenceLedger(result.run_directory / "evidence.jsonl").verify(), 8)

    def test_replay_mismatch_does_not_raise_the_ceiling(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            command = ["fixture-verifier"]
            request_path = root / "execution-request.json"
            request_path.write_text(
                json.dumps(
                    {
                        "evidence_id": "E-UNSTABLE",
                        "hypothesis_id": result.hypotheses[0].hypothesis_id,
                        "kind": "failing_test",
                        "summary": "Unstable fixture output",
                        "command": command,
                    }
                )
            )
            runner = CommandRunner(
                ExecutionPolicy(docker_image="fixture@sha256:" + "a" * 64),
                ExecutionMode.DOCKER,
            )
            board = HypothesisBoard(result.run_directory)
            first = CommandResult(command, 0, b"first\n", b"", 1)
            second = CommandResult(command, 0, b"second\n", b"", 1)
            with patch.object(runner, "run", side_effect=[first, second]):
                board.execute_evidence(request_path, runner)
                with self.assertRaisesRegex(ValueError, "does not match"):
                    board.verify_evidence("E-UNSTABLE", runner)

            scope = json.loads((result.run_directory / "scope.json").read_text())
            self.assertEqual(scope["evidence_ceiling"], "localised")

    def test_denied_execution_cannot_mint_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            request_path = root / "execution-request.json"
            request_path.write_text(
                json.dumps(
                    {
                        "evidence_id": "E-DENIED",
                        "hypothesis_id": result.hypotheses[0].hypothesis_id,
                        "kind": "failing_test",
                        "summary": "This command must not execute",
                        "command": ["fixture-verifier"],
                    }
                )
            )
            board = HypothesisBoard(result.run_directory)
            with self.assertRaisesRegex(ValueError, "execution was blocked"):
                board.execute_evidence(
                    request_path,
                    CommandRunner(ExecutionPolicy(), ExecutionMode.DENY),
                )

            records = EvidenceLedger(result.run_directory / "evidence.jsonl").records()
            self.assertFalse(
                any(
                    record["payload"].get("event") == "evidence_recorded"
                    and record["payload"]["evidence"].get("evidence_id") == "E-DENIED"
                    for record in records
                )
            )
            self.assertTrue(
                any(record["payload"].get("event") == "execution_rejected" for record in records)
            )

    def test_host_execution_cannot_mint_executable_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            request_path = root / "execution-request.json"
            request_path.write_text(
                json.dumps(
                    {
                        "evidence_id": "E-HOST",
                        "hypothesis_id": result.hypotheses[0].hypothesis_id,
                        "kind": "failing_test",
                        "summary": "Host execution is not reproducible evidence",
                        "command": ["fixture-verifier"],
                    }
                )
            )
            runner = CommandRunner(
                ExecutionPolicy(allow_host_execution=True, allow_network=True),
                ExecutionMode.HOST,
            )
            with patch.object(runner, "run") as run:
                with self.assertRaisesRegex(ValueError, "host execution cannot mint"):
                    HypothesisBoard(result.run_directory).execute_evidence(request_path, runner)
                run.assert_not_called()

    def test_replay_requires_the_original_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            command = ["fixture-verifier"]
            request_path = root / "execution-request.json"
            request_path.write_text(
                json.dumps(
                    {
                        "evidence_id": "E-POLICY",
                        "hypothesis_id": result.hypotheses[0].hypothesis_id,
                        "kind": "failing_test",
                        "summary": "Policy-bound fixture output",
                        "command": command,
                    }
                )
            )
            original_runner = CommandRunner(
                ExecutionPolicy(docker_image="fixture@sha256:" + "a" * 64),
                ExecutionMode.DOCKER,
            )
            observed = CommandResult(command, 0, b"stable\n", b"", 1)
            board = HypothesisBoard(result.run_directory)
            with patch.object(original_runner, "run", return_value=observed):
                board.execute_evidence(request_path, original_runner)

            changed_runner = CommandRunner(
                ExecutionPolicy(
                    docker_image="fixture@sha256:" + "a" * 64,
                    timeout_seconds=31,
                ),
                ExecutionMode.DOCKER,
            )
            with patch.object(changed_runner, "run") as run:
                with self.assertRaisesRegex(ValueError, "policy differs"):
                    board.verify_evidence("E-POLICY", changed_runner)
                run.assert_not_called()

    def test_scope_ceiling_cannot_be_edited_outside_the_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            scope_path = result.run_directory / "scope.json"
            scope = json.loads(scope_path.read_text())
            scope["evidence_ceiling"] = "executable"
            scope_path.write_text(json.dumps(scope))
            finding_path = root / "finding.json"
            finding_path.write_text(
                json.dumps(
                    {
                        "finding_id": "F-TAMPERED-SCOPE",
                        "hypothesis_id": result.hypotheses[0].hypothesis_id,
                        "title": "Tampered ceiling",
                        "severity": "medium",
                        "evidence_level": "structurally_confirmed",
                        "security_property": "Scope state follows the ledger",
                        "root_cause": "The test edits scope.json directly",
                        "locations": [{"path": "src/Vault.sol", "line_start": 1}],
                        "attacker_prerequisites": [],
                        "assumptions": [],
                        "causal_path": ["scope file", "confirmation gate"],
                        "reproducer": "scope.json",
                        "impact": "An unsupported ceiling would bypass degradation",
                        "reproduction_instructions": ["edit scope.json"],
                        "remediation": "Derive mutable scope state from the ledger",
                        "regression_test": "Reject the edited scope",
                    }
                )
            )

            with self.assertRaisesRegex(ValueError, "ledger-backed state"):
                HypothesisBoard(result.run_directory).confirm_finding(finding_path)


if __name__ == "__main__":
    unittest.main()
