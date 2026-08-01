import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nirvana.baseline import run_baseline
from nirvana.deployment import verify_deployments
from nirvana.ledger import EvidenceLedger
from nirvana.policy import CommandResult, CommandRunner, ExecutionMode, ExecutionPolicy
from nirvana.util import sha256_bytes
from nirvana.workflow import audit


class BaselineDeploymentTests(unittest.TestCase):
    def test_detected_baseline_runs_in_docker_and_hashes_generated_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            (target / "foundry.toml").write_text("[profile.default]\n")
            (target / "Vault.sol").write_text("contract Vault {}\n")
            result = audit(target, root / "runs")
            request = root / "baseline.json"
            request.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0.0",
                        "steps": [
                            {
                                "step_id": "B-BUILD",
                                "kind": "build",
                                "command": ["forge", "build"],
                                "cwd": ".",
                                "expected_return_code": 0,
                            },
                            {
                                "step_id": "B-TEST",
                                "kind": "test",
                                "command": ["forge", "test"],
                                "cwd": ".",
                                "expected_return_code": 0,
                            },
                        ],
                    }
                )
            )
            runner = CommandRunner(
                ExecutionPolicy(
                    docker_image="example.invalid/nirvana@sha256:" + "a" * 64
                ),
                ExecutionMode.DOCKER,
            )

            def fake_run(command, _cwd, _stdin=b"", harness_directory=None, artifact_directory=None):
                self.assertIsNone(harness_directory)
                self.assertIsNotNone(artifact_directory)
                if command == ["forge", "build"]:
                    (artifact_directory / "Vault.abi").write_text("[]\n")
                return CommandResult(command, 0, b"ok\n", b"", 2)

            with patch.object(runner, "run", side_effect=fake_run):
                receipt = run_baseline(result.run_directory, request, runner)

            self.assertEqual(receipt.build_status, "passed")
            self.assertEqual(receipt.test_status, "passed")
            self.assertTrue(
                any(item.get("kind") == "evm-artifact" for item in receipt.discovered_artifacts)
            )
            events = [
                item["payload"]["event"]
                for item in EvidenceLedger(result.run_directory / "evidence.jsonl").records()
            ]
            self.assertIn("baseline_executed", events)

    def test_local_bytecode_attestation_is_hash_bound_and_network_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            (target / "source.sol").write_text("contract C {}\n")
            result = audit(target, root / "runs")
            built = root / "built.hex"
            deployed = root / "deployed.hex"
            built.write_text("0x6001600055\n")
            deployed.write_text("6001600055\n")
            attestation = root / "attestation.json"
            attestation.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0.0",
                        "entries": [
                            {
                                "deployment_id": "gateway",
                                "source": "source.sol:C",
                                "compiler_config_sha256": sha256_bytes(b"compiler settings"),
                                "built_bytecode_path": str(built),
                                "deployed_bytecode_path": str(deployed),
                                "network": "captured-local-fixture",
                                "address": "0x0000000000000000000000000000000000000001",
                                "capture_provenance": "auditor-provided local eth_getCode capture",
                            }
                        ],
                    }
                )
            )
            report = verify_deployments(result.run_directory, attestation)
            self.assertTrue(report["all_match"])
            self.assertFalse(report["network_access_performed"])


if __name__ == "__main__":
    unittest.main()
