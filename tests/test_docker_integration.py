import json
import os
import shutil
import tempfile
import unittest
import base64
from pathlib import Path

from nirvana.board import HypothesisBoard
from nirvana.models import EvidenceLevel
from nirvana.policy import CommandRunner, ExecutionMode, ExecutionPolicy
from nirvana.util import sha256_file
from nirvana.verification import load_receipt
from nirvana.workflow import audit


FIXTURE = Path(__file__).parent / "fixtures" / "docker-forge"
FOUNDRY_IMAGE = (
    "ghcr.io/foundry-rs/foundry@"
    "sha256:f6a3fd201ae617fdc67bf7b3db9abdca7678e2589e15eda6bc84f88eb5239e04"
)
SOLC_SHA256 = "f3e987dc6ecebd4bd350c48edcbc320b46cf9e3109bd3fc3d88f1acaf4c428f7"


@unittest.skipUnless(
    os.environ.get("NIRVANA_RUN_DOCKER_INTEGRATION") == "1",
    "real Docker integration is exercised by its dedicated CI job",
)
class RealDockerForgeIntegrationTests(unittest.TestCase):
    def test_mint_and_replay_exploit_evidence_in_real_sandbox(self) -> None:
        configured_solc = os.environ.get("NIRVANA_SOLC")
        if not configured_solc:
            self.fail("NIRVANA_SOLC must point to the checksum-pinned compiler")
        solc = Path(configured_solc).resolve(strict=True)
        self.assertEqual(sha256_file(solc), SOLC_SHA256)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = shutil.copytree(FIXTURE / "target", root / "target")
            control = shutil.copytree(FIXTURE / "control", root / "control")
            harness = shutil.copytree(FIXTURE / "harness", root / "harness")
            harness_solc = harness / "solc"
            shutil.copyfile(solc, harness_solc)
            harness_solc.chmod(0o555)

            result = audit(target, root / "runs")
            hypothesis = next(
                item
                for item in result.hypotheses
                if item.generator == "deterministic:EVM-CALL-REENTRANCY"
                and any(
                    location.path == "src/Vault.sol"
                    for location in item.candidate_locations
                )
            )
            request = {
                "evidence_id": "E-REAL-DOCKER-FORGE",
                "hypothesis_id": hypothesis.hypothesis_id,
                "evidence_level": "exploit_demonstrated",
                "kind": "forge_reentrancy_poc",
                "summary": "A real Forge PoC drains one ether from the vulnerable vault",
                "adapter": "forge-test",
                "claim": {
                    "security_property": hypothesis.security_property,
                    "suspected_violation": hypothesis.suspected_violation,
                },
                "assertions": [
                    {
                        "assertion_id": "A-IMPACT",
                        "source": "stdout",
                        "operator": "json_pointer_equals",
                        "pointer": "/effect",
                        "value": "asset_loss",
                    },
                    {
                        "assertion_id": "A-ASSET",
                        "source": "stdout",
                        "operator": "json_pointer_equals",
                        "pointer": "/asset",
                        "value": "ETH",
                    },
                    {
                        "assertion_id": "A-LOSS",
                        "source": "stdout",
                        "operator": "json_pointer_equals",
                        "pointer": "/loss_wei",
                        "value": "1000000000000000000",
                    },
                ],
                "control_invariants": [
                    {
                        "assertion_id": "A-BASELINE",
                        "source": "stdout",
                        "operator": "contains",
                        "value": "NIRVANA_BASELINE_OK",
                    }
                ],
                "command": [
                    "forge",
                    "test",
                    "--root",
                    "/harness",
                    "--offline",
                    "-vv",
                ],
                "expected_return_codes": [0],
                "replay_mode": "assertions",
                "tool_version": "foundry-v1.4.0+solc-0.8.30",
                "assumptions": [
                    "the patched control changes only checks-effects-interactions ordering"
                ],
                "harness": {"path": str(harness.resolve())},
                "negative_control": {
                    "target_root": str(control.resolve()),
                    "changed_files": ["src/Vault.sol"],
                    "expected_return_codes": [0],
                },
                "impact": {
                    "effect": "asset_loss",
                    "asset": "ETH",
                    "description": "Reentrancy transfers one ether beyond the attacker balance",
                    "assertion_ids": ["A-IMPACT", "A-ASSET", "A-LOSS"],
                },
            }
            request_path = root / "execution-request.json"
            request_path.write_text(json.dumps(request), encoding="utf-8")
            runner = CommandRunner(
                ExecutionPolicy(
                    docker_image=FOUNDRY_IMAGE,
                    timeout_seconds=180,
                    max_output_bytes=2_000_000,
                ),
                ExecutionMode.DOCKER,
            )
            board = HypothesisBoard(result.run_directory)

            try:
                evidence = board.execute_evidence(request_path, runner)
            except ValueError as error:
                rejected = sorted(
                    (result.run_directory / "artifacts" / request["evidence_id"]).glob(
                        "rejected-*.json"
                    )
                )
                if not rejected:
                    raise
                receipt = load_receipt(rejected[-1])
                stdout = base64.b64decode(
                    receipt["result"]["stdout_base64"], validate=True
                ).decode("utf-8", errors="replace")
                stderr = base64.b64decode(
                    receipt["result"]["stderr_base64"], validate=True
                ).decode("utf-8", errors="replace")
                self.fail(
                    f"{error}\nDocker stdout:\n{stdout}\nDocker stderr:\n{stderr}"
                )
            self.assertIs(evidence.level, EvidenceLevel.EXPLOIT_DEMONSTRATED)
            self.assertTrue(evidence.metadata["negative_control_verified"])
            receipt = load_receipt(Path(evidence.artifact_path or ""))
            docker_command = receipt["result"]["command"]
            self.assertEqual(receipt["runner"]["docker_image"], FOUNDRY_IMAGE)
            self.assertEqual(
                docker_command[docker_command.index("--network") + 1], "none"
            )
            self.assertIn("--read-only", docker_command)
            self.assertEqual(
                docker_command[docker_command.index("--user") + 1],
                "65532:65532",
            )
            self.assertEqual(
                docker_command[docker_command.index("--entrypoint") + 1],
                "forge",
            )
            self.assertIn("FOUNDRY_OUT=/work/foundry-out", docker_command)
            self.assertIn(
                "FOUNDRY_CACHE_PATH=/work/foundry-cache", docker_command
            )
            self.assertTrue(
                any("dst=/harness,readonly" in item for item in docker_command)
            )

            replayed = board.verify_evidence(evidence.evidence_id, runner)
            self.assertEqual(replayed.evidence_id, evidence.evidence_id)
            events = [
                record["payload"]["event"] for record in board.ledger.records()
            ]
            self.assertIn("evidence_recorded", events)
            self.assertIn("evidence_verified", events)


if __name__ == "__main__":
    unittest.main()
