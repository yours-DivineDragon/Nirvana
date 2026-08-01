import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nirvana.board import HypothesisBoard
from nirvana.ledger import EvidenceLedger
from nirvana.models import EvidenceLevel
from nirvana.policy import CommandResult, CommandRunner, ExecutionMode, ExecutionPolicy
from nirvana.util import atomic_write_json as real_atomic_write_json
from nirvana.util import sha256_file
from nirvana.workflow import audit


FIXTURE = Path(__file__).parent / "fixtures" / "evm"
CONTROL_FIXTURE = Path(__file__).parent / "fixtures" / "evm-control"


class BoardTests(unittest.TestCase):
    @staticmethod
    def execution_request(
        hypothesis,
        evidence_id: str,
        command: list[str],
        assertion_value: str,
        *,
        expected_return_code: int = 0,
        replay_mode: str = "assertions",
        evidence_level: str = "executable",
        adapter: str = "pytest",
        control_root: Path = CONTROL_FIXTURE,
        control_changed_files: list[str] | None = None,
        control_expected_return_code: int = 0,
    ) -> dict:
        request = {
            "evidence_id": evidence_id,
            "hypothesis_id": hypothesis.hypothesis_id,
            "evidence_level": evidence_level,
            "kind": "failing_test",
            "summary": "The reviewed fixture checked the declared violation",
            "adapter": adapter,
            "claim": {
                "security_property": hypothesis.security_property,
                "suspected_violation": hypothesis.suspected_violation,
            },
            "assertions": [
                {
                    "assertion_id": "A-VIOLATION",
                    "source": "stdout",
                    "operator": "contains",
                    "value": assertion_value,
                }
            ],
            "command": command,
            "expected_return_codes": [expected_return_code],
            "replay_mode": replay_mode,
            "tool_version": "fixture-1",
        }
        if evidence_level == "executable":
            request["control_invariants"] = [
                {
                    "assertion_id": "A-VERIFIER-HEALTHY",
                    "source": "stdout",
                    "operator": "contains",
                    "value": "verifier healthy",
                }
            ]
            request["negative_control"] = {
                "target_root": str(control_root.resolve()),
                "changed_files": control_changed_files or ["src/Vault.sol"],
                "expected_return_codes": [control_expected_return_code],
            }
        return request

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
                        "supporting_evidence": ["E-1"],
                    }
                )
            )
            with self.assertRaisesRegex(ValueError, "executable evidence"):
                board.confirm_finding(finding_path)

    def test_confirmed_level_cannot_exceed_recorded_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            hypothesis = result.hypotheses[0]
            hypothesis_id = hypothesis.hypothesis_id
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
                        "supporting_evidence": ["E-LOCAL"],
                    }
                )
            )
            with self.assertRaisesRegex(ValueError, "run evidence ceiling"):
                board.confirm_finding(finding_path)

    def test_imported_executable_evidence_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            hypothesis = result.hypotheses[0]
            hypothesis_id = hypothesis.hypothesis_id
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
            hypothesis = result.hypotheses[0]
            hypothesis_id = hypothesis.hypothesis_id
            request_path = root / "execution-request.json"
            command = ["pytest", "--collect-only"]
            request_path.write_text(
                json.dumps(
                    self.execution_request(
                        hypothesis,
                        "E-POC",
                        command,
                        "counterexample",
                        expected_return_code=1,
                    )
                )
            )
            policy = ExecutionPolicy(docker_image="fixture@sha256:" + "a" * 64)
            runner = CommandRunner(policy, ExecutionMode.DOCKER)
            observed = CommandResult(
                command, 1, b"counterexample\nverifier healthy\n", b"", 4
            )
            control = CommandResult(
                command, 0, b"patched behavior\nverifier healthy\n", b"", 2
            )
            board = HypothesisBoard(result.run_directory)
            with patch.object(
                runner, "run", side_effect=[observed, control, observed, control]
            ) as run:
                evidence = board.execute_evidence(request_path, runner)
                self.assertEqual(evidence.source, "nirvana:command-runner")
                self.assertTrue(evidence.metadata["runner_minted"])
                receipt = json.loads(Path(evidence.artifact_path).read_text())
                self.assertEqual(receipt["schema_version"], "1.3.0")
                self.assertTrue(
                    receipt["result"]["control_invariants"][0]["passed"]
                )
                self.assertTrue(
                    receipt["negative_control"]["result"]["control_invariants"][0][
                        "passed"
                    ]
                )

                finding_path = root / "finding.json"
                finding_path.write_text(
                    json.dumps(
                        {
                            "finding_id": "F-POC",
                            "hypothesis_id": hypothesis_id,
                            "title": "Executable fixture finding",
                            "severity": "high",
                            "evidence_level": "executable",
                            "security_property": hypothesis.security_property,
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
                            "supporting_evidence": ["E-POC"],
                            "reproducer_evidence_id": "E-POC",
                        }
                    )
                )
                with self.assertRaisesRegex(ValueError, "run evidence ceiling"):
                    board.confirm_finding(finding_path)

                board.verify_evidence(evidence.evidence_id, runner)
                board.confirm_finding(finding_path)

            self.assertEqual(run.call_count, 4)
            report = json.loads((result.run_directory / "report.json").read_text())
            self.assertEqual([item["finding_id"] for item in report["confirmed_findings"]], ["F-POC"])
            self.assertEqual(report["evidence_ceiling"], "executable")
            self.assertEqual(EvidenceLedger(result.run_directory / "evidence.jsonl").verify(), 8)

    def test_replay_mismatch_does_not_raise_the_ceiling(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            hypothesis = result.hypotheses[0]
            command = ["pytest"]
            request_path = root / "execution-request.json"
            request_path.write_text(
                json.dumps(
                    self.execution_request(
                        hypothesis,
                        "E-UNSTABLE",
                        command,
                        "first",
                        replay_mode="strict",
                    )
                )
            )
            runner = CommandRunner(
                ExecutionPolicy(docker_image="fixture@sha256:" + "a" * 64),
                ExecutionMode.DOCKER,
            )
            board = HypothesisBoard(result.run_directory)
            first = CommandResult(command, 0, b"first\nverifier healthy\n", b"", 1)
            second = CommandResult(command, 0, b"second\nverifier healthy\n", b"", 1)
            control = CommandResult(command, 0, b"patched\nverifier healthy\n", b"", 1)
            with patch.object(
                runner, "run", side_effect=[first, control, second, control]
            ):
                board.execute_evidence(request_path, runner)
                with self.assertRaisesRegex(ValueError, "verification contract"):
                    board.verify_evidence("E-UNSTABLE", runner)

            scope = json.loads((result.run_directory / "scope.json").read_text())
            self.assertEqual(scope["evidence_ceiling"], "localised")

    def test_negative_control_must_produce_the_opposite_decision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            hypothesis = result.hypotheses[0]
            request_path = root / "request.json"
            request_path.write_text(
                json.dumps(
                    self.execution_request(
                        hypothesis, "E-NO-CONTROL", ["pytest"], "violation"
                    )
                )
            )
            runner = CommandRunner(
                ExecutionPolicy(docker_image="fixture@sha256:" + "a" * 64),
                ExecutionMode.DOCKER,
            )
            same_result = CommandResult(
                ["pytest"], 0, b"violation\nverifier healthy\n", b"", 1
            )
            with patch.object(
                runner, "run", side_effect=[same_result, same_result]
            ):
                with self.assertRaisesRegex(ValueError, "opposite verifier decision"):
                    HypothesisBoard(result.run_directory).execute_evidence(
                        request_path, runner
                    )

    def test_negative_control_health_invariant_blocks_broken_patch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            request_path = root / "request.json"
            request_path.write_text(
                json.dumps(
                    self.execution_request(
                        result.hypotheses[0],
                        "E-BROKEN-CONTROL",
                        ["pytest"],
                        "violation",
                        control_expected_return_code=1,
                    )
                )
            )
            runner = CommandRunner(
                ExecutionPolicy(docker_image="fixture@sha256:" + "a" * 64),
                ExecutionMode.DOCKER,
            )
            positive = CommandResult(
                ["pytest"], 0, b"violation\nverifier healthy\n", b"", 1
            )
            broken_control = CommandResult(
                ["pytest"],
                1,
                b"",
                b"SyntaxError: invalid syntax\n",
                1,
            )
            board = HypothesisBoard(result.run_directory)
            with patch.object(
                runner, "run", side_effect=[positive, broken_control]
            ):
                with self.assertRaisesRegex(
                    ValueError, "negative control health invariants failed"
                ):
                    board.execute_evidence(request_path, runner)

            self.assertNotIn(
                "E-BROKEN-CONTROL",
                {
                    record["payload"].get("evidence", {}).get("evidence_id")
                    for record in board.ledger.records()
                    if record["payload"].get("event") == "evidence_recorded"
                },
            )

    def test_negative_control_delta_must_be_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            request = self.execution_request(
                result.hypotheses[0], "E-WRONG-DELTA", ["pytest"], "violation"
            )
            request["negative_control"]["changed_files"] = ["foundry.toml"]
            request_path = root / "request.json"
            request_path.write_text(json.dumps(request))
            runner = CommandRunner(
                ExecutionPolicy(docker_image="fixture@sha256:" + "a" * 64),
                ExecutionMode.DOCKER,
            )
            with patch.object(runner, "run") as run:
                with self.assertRaisesRegex(ValueError, "do not exactly match"):
                    HypothesisBoard(result.run_directory).execute_evidence(
                        request_path, runner
                    )
                run.assert_not_called()

    def test_negative_control_delta_must_touch_candidate_location(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control_target = root / "control"
            shutil.copytree(FIXTURE, control_target)
            foundry = control_target / "foundry.toml"
            foundry.write_text(foundry.read_text() + "\n# unrelated control edit\n")
            result = audit(FIXTURE, root / "runs")
            request = self.execution_request(
                result.hypotheses[0],
                "E-UNRELATED-CONTROL",
                ["pytest"],
                "violation",
                control_root=control_target,
                control_changed_files=["foundry.toml"],
            )
            request_path = root / "request.json"
            request_path.write_text(json.dumps(request))
            runner = CommandRunner(
                ExecutionPolicy(docker_image="fixture@sha256:" + "a" * 64),
                ExecutionMode.DOCKER,
            )
            with patch.object(runner, "run") as run:
                with self.assertRaisesRegex(
                    ValueError, "must change at least one hypothesis candidate location"
                ):
                    HypothesisBoard(result.run_directory).execute_evidence(
                        request_path, runner
                    )
                run.assert_not_called()

    def test_negative_control_must_replay_the_same_assertion_decision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            request = self.execution_request(
                result.hypotheses[0], "E-CONTROL-FLAKE", ["pytest"], "violation"
            )
            request["assertions"].append(
                {
                    "assertion_id": "A-STABLE",
                    "source": "stdout",
                    "operator": "contains",
                    "value": "stable",
                }
            )
            request_path = root / "request.json"
            request_path.write_text(json.dumps(request))
            command = ["pytest"]
            positive = CommandResult(
                command, 0, b"violation stable\nverifier healthy\n", b"", 1
            )
            first_control = CommandResult(
                command, 0, b"stable\nverifier healthy\n", b"", 1
            )
            second_control = CommandResult(
                command, 0, b"violation\nverifier healthy\n", b"", 1
            )
            runner = CommandRunner(
                ExecutionPolicy(docker_image="fixture@sha256:" + "a" * 64),
                ExecutionMode.DOCKER,
            )
            board = HypothesisBoard(result.run_directory)
            with patch.object(
                runner,
                "run",
                side_effect=[positive, first_control, positive, second_control],
            ):
                board.execute_evidence(request_path, runner)
                with self.assertRaisesRegex(ValueError, "verification contract"):
                    board.verify_evidence("E-CONTROL-FLAKE", runner)

    def test_negative_control_must_replay_health_invariants(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            request = self.execution_request(
                result.hypotheses[0],
                "E-CONTROL-HEALTH-FLAKE",
                ["pytest"],
                "violation",
            )
            request_path = root / "request.json"
            request_path.write_text(json.dumps(request))
            command = ["pytest"]
            positive = CommandResult(
                command, 0, b"violation\nverifier healthy\n", b"", 1
            )
            healthy_control = CommandResult(
                command, 0, b"patched\nverifier healthy\n", b"", 1
            )
            broken_control = CommandResult(command, 0, b"patched\n", b"", 1)
            runner = CommandRunner(
                ExecutionPolicy(docker_image="fixture@sha256:" + "a" * 64),
                ExecutionMode.DOCKER,
            )
            board = HypothesisBoard(result.run_directory)
            with patch.object(
                runner,
                "run",
                side_effect=[positive, healthy_control, positive, broken_control],
            ):
                board.execute_evidence(request_path, runner)
                with self.assertRaisesRegex(ValueError, "verification contract"):
                    board.verify_evidence("E-CONTROL-HEALTH-FLAKE", runner)

            replay = [
                record["payload"]
                for record in board.ledger.records()
                if record["payload"].get("event") == "evidence_replay_failed"
            ][-1]
            self.assertFalse(
                replay["negative_control"]["invariant_decision_matches"]
            )

    def test_harness_overlay_is_hash_bound_and_replayed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            harness = root / "harness"
            harness.mkdir()
            harness_file = harness / "test_repro.py"
            harness_file.write_text("def test_repro():\n    assert True\n")
            result = audit(FIXTURE, root / "runs")
            request = self.execution_request(
                result.hypotheses[0], "E-HARNESS", ["pytest"], "violation"
            )
            request["harness"] = {"path": str(harness.resolve())}
            request_path = root / "request.json"
            request_path.write_text(json.dumps(request))
            runner = CommandRunner(
                ExecutionPolicy(docker_image="fixture@sha256:" + "a" * 64),
                ExecutionMode.DOCKER,
            )
            positive = CommandResult(
                ["pytest"], 0, b"violation\nverifier healthy\n", b"", 1
            )
            control = CommandResult(
                ["pytest"], 0, b"patched\nverifier healthy\n", b"", 1
            )
            board = HypothesisBoard(result.run_directory)
            with patch.object(
                runner,
                "run",
                side_effect=[positive, control, positive, control],
            ) as run:
                evidence = board.execute_evidence(request_path, runner)
                board.verify_evidence(evidence.evidence_id, runner)

            self.assertEqual(run.call_count, 4)
            self.assertTrue(
                all(call.args[3] == harness.resolve() for call in run.call_args_list)
            )
            receipt = json.loads(Path(evidence.artifact_path).read_text())
            self.assertEqual(receipt["harness"]["file_count"], 1)
            self.assertIsNotNone(receipt["negative_control"])

            harness_file.write_text("def test_repro():\n    assert False\n")
            with patch.object(runner, "run") as replay:
                with self.assertRaisesRegex(ValueError, "different auditor harness"):
                    board.verify_evidence(evidence.evidence_id, runner)
                replay.assert_not_called()

    def test_denied_execution_cannot_mint_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            request_path = root / "execution-request.json"
            request_path.write_text(
                json.dumps(
                    self.execution_request(
                        result.hypotheses[0],
                        "E-DENIED",
                        ["pytest"],
                        "never",
                    )
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
                    self.execution_request(
                        result.hypotheses[0],
                        "E-HOST",
                        ["pytest"],
                        "violation",
                    )
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
            hypothesis = result.hypotheses[0]
            command = ["pytest"]
            request_path = root / "execution-request.json"
            request_path.write_text(
                json.dumps(
                    self.execution_request(
                        hypothesis,
                        "E-POLICY",
                        command,
                        "stable",
                    )
                )
            )
            original_runner = CommandRunner(
                ExecutionPolicy(docker_image="fixture@sha256:" + "a" * 64),
                ExecutionMode.DOCKER,
            )
            observed = CommandResult(
                command, 0, b"stable\nverifier healthy\n", b"", 1
            )
            control = CommandResult(
                command, 0, b"patched\nverifier healthy\n", b"", 1
            )
            board = HypothesisBoard(result.run_directory)
            with patch.object(
                original_runner, "run", side_effect=[observed, control]
            ):
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
                        "supporting_evidence": ["E-NOT-REAL"],
                    }
                )
            )

            with self.assertRaisesRegex(ValueError, "ceiling not present in the ledger"):
                HypothesisBoard(result.run_directory).confirm_finding(finding_path)

    def test_assertion_replay_accepts_noisy_forge_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            hypothesis = result.hypotheses[0]
            command = ["forge", "test", "--match-test", "testExploit"]
            request = self.execution_request(
                hypothesis,
                "E-NOISY",
                command,
                "[PASS] testExploit",
                adapter="forge-test",
            )
            request_path = root / "request.json"
            request_path.write_text(json.dumps(request))
            runner = CommandRunner(
                ExecutionPolicy(docker_image="fixture@sha256:" + "a" * 64),
                ExecutionMode.DOCKER,
            )
            first = CommandResult(
                command,
                0,
                b"[PASS] testExploit (gas: 12001)\nfinished in 1.23ms\nverifier healthy\n",
                b"",
                2,
            )
            second = CommandResult(
                command,
                0,
                b"[PASS] testExploit (gas: 12009)\nfinished in 7.89ms\nverifier healthy\n",
                b"",
                9,
            )
            control = CommandResult(
                command,
                0,
                b"[FAIL] patched target\nverifier healthy\n",
                b"",
                3,
            )
            board = HypothesisBoard(result.run_directory)
            with patch.object(
                runner, "run", side_effect=[first, control, second, control]
            ):
                board.execute_evidence(request_path, runner)
                board.verify_evidence("E-NOISY", runner)

            scope = json.loads((result.run_directory / "scope.json").read_text())
            self.assertEqual(scope["evidence_ceiling"], "executable")

    def test_echo_cannot_masquerade_as_an_executable_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            request = self.execution_request(
                result.hypotheses[0], "E-ECHO", ["echo", "hello"], "hello"
            )
            request_path = root / "request.json"
            request_path.write_text(json.dumps(request))
            runner = CommandRunner(
                ExecutionPolicy(docker_image="fixture@sha256:" + "a" * 64),
                ExecutionMode.DOCKER,
            )
            with patch.object(runner, "run") as run:
                with self.assertRaisesRegex(ValueError, "does not match the pytest adapter"):
                    HypothesisBoard(result.run_directory).execute_evidence(request_path, runner)
                run.assert_not_called()

    def test_verified_evidence_cannot_support_a_different_hypothesis(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            source_hypothesis, finding_hypothesis = result.hypotheses[:2]
            request_path = root / "request.json"
            request_path.write_text(
                json.dumps(
                    self.execution_request(
                        source_hypothesis, "E-BOUND", ["pytest"], "violation"
                    )
                )
            )
            runner = CommandRunner(
                ExecutionPolicy(docker_image="fixture@sha256:" + "a" * 64),
                ExecutionMode.DOCKER,
            )
            observed = CommandResult(
                ["pytest"], 0, b"violation\nverifier healthy\n", b"", 1
            )
            control = CommandResult(
                ["pytest"], 0, b"patched\nverifier healthy\n", b"", 1
            )
            board = HypothesisBoard(result.run_directory)
            with patch.object(
                runner, "run", side_effect=[observed, control, observed, control]
            ):
                board.execute_evidence(request_path, runner)
                board.verify_evidence("E-BOUND", runner)

            finding_path = root / "finding.json"
            finding_path.write_text(
                json.dumps(
                    {
                        "finding_id": "F-WRONG-CLAIM",
                        "hypothesis_id": finding_hypothesis.hypothesis_id,
                        "title": "Evidence from another claim",
                        "severity": "medium",
                        "evidence_level": "executable",
                        "security_property": finding_hypothesis.security_property,
                        "root_cause": "The receipt does not establish this hypothesis",
                        "locations": [{"path": "src/Vault.sol", "line_start": 16}],
                        "attacker_prerequisites": ["caller"],
                        "assumptions": [],
                        "causal_path": ["input", "effect"],
                        "reproducer": "wrong receipt",
                        "impact": "Unsupported impact",
                        "reproduction_instructions": ["replay E-BOUND"],
                        "remediation": "Use relevant evidence",
                        "regression_test": "Bind evidence to the hypothesis",
                        "supporting_evidence": ["E-BOUND"],
                        "reproducer_evidence_id": "E-BOUND",
                    }
                )
            )
            with self.assertRaisesRegex(ValueError, "different hypothesis"):
                board.confirm_finding(finding_path)

    def test_latest_failed_replay_invalidates_support(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            hypothesis = result.hypotheses[0]
            request_path = root / "request.json"
            request_path.write_text(
                json.dumps(
                    self.execution_request(
                        hypothesis, "E-FLAKY", ["pytest"], "violation"
                    )
                )
            )
            runner = CommandRunner(
                ExecutionPolicy(docker_image="fixture@sha256:" + "a" * 64),
                ExecutionMode.DOCKER,
            )
            passing = CommandResult(
                ["pytest"], 0, b"violation\nverifier healthy\n", b"", 1
            )
            failing = CommandResult(
                ["pytest"], 0, b"no decision\nverifier healthy\n", b"", 1
            )
            control = CommandResult(
                ["pytest"], 0, b"patched\nverifier healthy\n", b"", 1
            )
            board = HypothesisBoard(result.run_directory)
            with patch.object(
                runner,
                "run",
                side_effect=[
                    passing,
                    control,
                    passing,
                    control,
                    failing,
                    control,
                ],
            ):
                board.execute_evidence(request_path, runner)
                board.verify_evidence("E-FLAKY", runner)
                with self.assertRaisesRegex(ValueError, "verification contract"):
                    board.verify_evidence("E-FLAKY", runner)

            finding_path = root / "finding.json"
            finding_path.write_text(
                json.dumps(
                    {
                        "finding_id": "F-FLAKY",
                        "hypothesis_id": hypothesis.hypothesis_id,
                        "title": "Flaky evidence must not confirm",
                        "severity": "medium",
                        "evidence_level": "executable",
                        "security_property": hypothesis.security_property,
                        "root_cause": "The verifier no longer reproduces",
                        "locations": [{"path": "src/Vault.sol", "line_start": 13}],
                        "attacker_prerequisites": ["caller"],
                        "assumptions": [],
                        "causal_path": ["input", "effect"],
                        "reproducer": "E-FLAKY",
                        "impact": "Unsupported",
                        "reproduction_instructions": ["replay E-FLAKY"],
                        "remediation": "Stabilize the proof",
                        "regression_test": "Require the latest replay to pass",
                        "supporting_evidence": ["E-FLAKY"],
                        "reproducer_evidence_id": "E-FLAKY",
                    }
                )
            )
            with self.assertRaisesRegex(ValueError, "replay-verified"):
                board.confirm_finding(finding_path)

    def test_structural_corroboration_raises_intermediate_ceiling(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            hypothesis = result.hypotheses[0]
            requests = [
                self.execution_request(
                    hypothesis,
                    "E-SOLC",
                    ["solc", "--standard-json"],
                    "violation",
                    evidence_level="structurally_confirmed",
                    adapter="solc-ast",
                ),
                self.execution_request(
                    hypothesis,
                    "E-SLITHER",
                    ["slither", "."],
                    "violation",
                    evidence_level="structurally_confirmed",
                    adapter="slither",
                ),
            ]
            runner = CommandRunner(
                ExecutionPolicy(allow_host_execution=True, allow_network=True),
                ExecutionMode.HOST,
            )
            board = HypothesisBoard(result.run_directory)

            def observed(command, _cwd, _stdin):
                return CommandResult(command, 0, b"violation\n", b"", 1)

            with patch.object(runner, "run", side_effect=observed):
                for request in requests:
                    request_path = root / f"{request['evidence_id']}.json"
                    request_path.write_text(json.dumps(request))
                    board.execute_evidence(request_path, runner)
                    board.verify_evidence(request["evidence_id"], runner)

            scope = json.loads((result.run_directory / "scope.json").read_text())
            self.assertEqual(scope["evidence_ceiling"], "structurally_confirmed")

            finding_path = root / "finding.json"
            finding_path.write_text(
                json.dumps(
                    {
                        "finding_id": "F-STRUCTURAL",
                        "hypothesis_id": hypothesis.hypothesis_id,
                        "title": "Independently corroborated structural issue",
                        "severity": "medium",
                        "evidence_level": "structurally_confirmed",
                        "security_property": hypothesis.security_property,
                        "root_cause": "Two independent analyzers resolve the same path",
                        "locations": [{"path": "src/Vault.sol", "line_start": 13}],
                        "attacker_prerequisites": ["caller"],
                        "assumptions": ["static analyzer models"],
                        "causal_path": ["input", "authority check", "effect"],
                        "reproducer": "structural analyzer receipts",
                        "impact": "A medium-impact unsafe path requires review",
                        "reproduction_instructions": ["replay both analyzer receipts"],
                        "remediation": "Enforce the intended property",
                        "regression_test": "Keep both analyzers clean",
                        "supporting_evidence": ["E-SOLC", "E-SLITHER"],
                    }
                )
            )
            board.confirm_finding(finding_path)

    def test_imported_structural_artifacts_cannot_raise_the_ceiling(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            hypothesis = result.hypotheses[0]
            claim = {
                "security_property": hypothesis.security_property,
                "suspected_violation": hypothesis.suspected_violation,
            }
            board = HypothesisBoard(result.run_directory)
            artifact = root / "fake.json"
            artifact.write_text(
                json.dumps({"totally": "handwritten, no analyzer ever ran"})
            )
            evidence_path = root / "fake-record.json"
            evidence_path.write_text(
                json.dumps(
                    {
                        "evidence_id": "E-FAKE-AST",
                        "hypothesis_id": hypothesis.hypothesis_id,
                        "level": "structurally_confirmed",
                        "kind": "static_path",
                        "summary": "fabricated structural path",
                        "source": "deterministic:solc-ast",
                        "artifact_path": str(artifact),
                        "artifact_sha256": sha256_file(artifact),
                        "tool_version": "fabricated-1",
                        "metadata": {
                            "adapter": "solc-ast",
                            "target_snapshot_sha256": result.scope.target_snapshot_sha256,
                            "claim": claim,
                        },
                    }
                )
            )
            with self.assertRaisesRegex(ValueError, "structural and stronger"):
                board.import_evidence(evidence_path)
            self.assertEqual(board._load_scope().evidence_ceiling.value, "localised")

    def test_ledger_first_ceiling_update_recovers_a_stale_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            hypothesis = result.hypotheses[0]
            command = ["pytest"]
            request_path = root / "request.json"
            request_path.write_text(
                json.dumps(
                    self.execution_request(
                        hypothesis, "E-CRASH", command, "violation"
                    )
                )
            )
            runner = CommandRunner(
                ExecutionPolicy(docker_image="fixture@sha256:" + "a" * 64),
                ExecutionMode.DOCKER,
            )
            observed = CommandResult(
                command, 0, b"violation\nverifier healthy\n", b"", 1
            )
            control = CommandResult(
                command, 0, b"patched\nverifier healthy\n", b"", 1
            )
            board = HypothesisBoard(result.run_directory)
            with patch.object(
                runner, "run", side_effect=[observed, control, observed, control]
            ):
                board.execute_evidence(request_path, runner)

                def fail_scope_only(path, value):
                    if path.name == "scope.json":
                        raise OSError("simulated crash before scope projection")
                    real_atomic_write_json(path, value)

                with patch("nirvana.board.atomic_write_json", side_effect=fail_scope_only):
                    with self.assertRaisesRegex(OSError, "simulated crash"):
                        board.verify_evidence("E-CRASH", runner)

            recovered = HypothesisBoard(result.run_directory)._load_scope()
            self.assertEqual(recovered.evidence_ceiling.value, "executable")
            self.assertEqual(
                json.loads((result.run_directory / "scope.json").read_text())["evidence_ceiling"],
                "executable",
            )

    def test_large_scope_is_not_subject_to_the_import_json_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            (target / "Vault.sol").write_text(
                "contract Vault { address owner; function f() external view returns(bool) { return tx.origin == owner; } }\n"
            )
            long_suffix = "x" * 180
            for index in range(4_000):
                (target / f"f{index:04d}-{long_suffix}.txt").write_text("")
            control_target = root / "control"
            shutil.copytree(target, control_target)
            (control_target / "Vault.sol").write_text(
                "contract Vault { address owner; function f() external view returns(bool) { return msg.sender == owner; } }\n"
            )
            result = audit(target, root / "runs")
            self.assertGreater((result.run_directory / "scope.json").stat().st_size, 1_000_000)

            request_path = root / "request.json"
            request_path.write_text(
                json.dumps(
                    self.execution_request(
                        result.hypotheses[0],
                        "E-LARGE",
                        ["pytest"],
                        "violation",
                        control_root=control_target,
                        control_changed_files=["Vault.sol"],
                    )
                )
            )
            runner = CommandRunner(
                ExecutionPolicy(docker_image="fixture@sha256:" + "a" * 64),
                ExecutionMode.DOCKER,
            )
            observed = CommandResult(
                ["pytest"], 0, b"violation\nverifier healthy\n", b"", 1
            )
            control = CommandResult(
                ["pytest"], 0, b"patched\nverifier healthy\n", b"", 1
            )
            with patch.object(runner, "run", side_effect=[observed, control]):
                evidence = HypothesisBoard(result.run_directory).execute_evidence(
                    request_path, runner
                )
            self.assertEqual(evidence.evidence_id, "E-LARGE")


if __name__ == "__main__":
    unittest.main()
