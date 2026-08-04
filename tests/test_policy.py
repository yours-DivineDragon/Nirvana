import tempfile
import unittest
import subprocess
from pathlib import Path
from unittest.mock import patch

from nirvana.policy import CommandRunner, ExecutionMode, ExecutionPolicy


class PolicyTests(unittest.TestCase):
    def test_host_mode_requires_network_risk_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = CommandRunner(
                ExecutionPolicy(allow_host_execution=True),
                ExecutionMode.HOST,
            ).run(["python3", "--version"], Path(directory))
            self.assertIn("cannot enforce network isolation", result.blocked_reason or "")

    def test_git_mutation_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = CommandRunner(
                ExecutionPolicy(
                    allow_host_execution=True, accept_host_network_risk=True
                ),
                ExecutionMode.HOST,
            ).run(["git", "commit", "-m", "no"], Path(directory))
            self.assertEqual(result.blocked_reason, "git mutation is not allowed by policy")

    def test_docker_requires_digest_pin(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch("nirvana.policy.shutil.which", return_value="/bin/docker"):
            result = CommandRunner(
                ExecutionPolicy(docker_image="ubuntu:latest"),
                ExecutionMode.DOCKER,
            ).run(["true"], Path(directory))
            self.assertIn("pinned by SHA-256", result.blocked_reason or "")

    def test_opaque_shell_and_forge_create_are_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runner = CommandRunner(
                ExecutionPolicy(
                    allow_host_execution=True, accept_host_network_risk=True
                ),
                ExecutionMode.HOST,
            )
            shell = runner.run(["bash", "-c", "git commit -am pwn"], Path(directory))
            login_shell = runner.run(["bash", "-lc", "git commit -am pwn"], Path(directory))
            git_alias = runner.run(
                ["git", "-c", "alias.pwn=!sh -c id", "pwn"], Path(directory)
            )
            deploy = runner.run(["forge", "create", "Contract"], Path(directory))
            self.assertIn("opaque shell", shell.blocked_reason or "")
            self.assertIn("opaque shell", login_shell.blocked_reason or "")
            self.assertIn("Git execution", git_alias.blocked_reason or "")
            self.assertIn("forge create", deploy.blocked_reason or "")

    def test_docker_uses_nonroot_user_writable_tool_area_and_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch(
            "nirvana.policy.shutil.which", return_value="/usr/bin/docker"
        ), patch("nirvana.policy.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, b"", b"")
            result = CommandRunner(
                ExecutionPolicy(docker_image="fixture@sha256:" + "a" * 64),
                ExecutionMode.DOCKER,
            ).run(["forge", "test"], Path(directory))

            self.assertEqual(result.return_code, 0)
            command = run.call_args.args[0]
            self.assertIn("--user", command)
            self.assertIn("65532:65532", command)
            self.assertTrue(any(item.startswith("--tmpfs=/work:rw,exec") for item in command))
            self.assertIn("FOUNDRY_OUT=/work/foundry-out", command)
            self.assertIn("FOUNDRY_CACHE_PATH=/work/foundry-cache", command)
            self.assertIn("PYTEST_ADDOPTS=-p no:cacheprovider", command)
            self.assertTrue(
                any(item.startswith("--tmpfs=/workspace/artifacts:rw") for item in command)
            )
            self.assertTrue(
                any(
                    item.startswith("--tmpfs=/workspace/crytic-export:rw")
                    for item in command
                )
            )
            mount = command[command.index("--mount") + 1]
            self.assertTrue(mount.endswith(",readonly"))
            entrypoint = command.index("--entrypoint")
            self.assertEqual(command[entrypoint + 1], "forge")
            image = command.index("fixture@sha256:" + "a" * 64)
            self.assertEqual(command[image + 1 :], ["test"])

    def test_docker_mounts_auditor_harness_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as harness_directory, patch(
            "nirvana.policy.shutil.which", return_value="/usr/bin/docker"
        ), patch("nirvana.policy.subprocess.run") as run:
            harness = Path(harness_directory)
            (harness / "test.py").write_text("assert True\n")
            run.return_value = subprocess.CompletedProcess([], 0, b"", b"")
            result = CommandRunner(
                ExecutionPolicy(docker_image="fixture@sha256:" + "a" * 64),
                ExecutionMode.DOCKER,
            ).run(["pytest", "/harness/test.py"], Path(directory), b"", harness)

            self.assertEqual(result.return_code, 0)
            command = run.call_args.args[0]
            mounts = [
                command[index + 1]
                for index, item in enumerate(command[:-1])
                if item == "--mount"
            ]
            self.assertEqual(len(mounts), 2)
            self.assertIn(
                f"type=bind,src={harness.resolve()},dst=/harness,readonly",
                mounts,
            )

    def test_baseline_routes_hardhat_outputs_to_the_auditor_overlay(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as artifact_directory, patch(
            "nirvana.policy.shutil.which", return_value="/usr/bin/docker"
        ), patch("nirvana.policy.subprocess.run") as run:
            artifacts = Path(artifact_directory)
            run.return_value = subprocess.CompletedProcess([], 0, b"", b"")
            result = CommandRunner(
                ExecutionPolicy(docker_image="fixture@sha256:" + "a" * 64),
                ExecutionMode.DOCKER,
            ).run(
                ["npx", "hardhat", "compile"],
                Path(directory),
                artifact_directory=artifacts,
            )

            self.assertEqual(result.return_code, 0)
            command = run.call_args.args[0]
            mounts = [
                command[index + 1]
                for index, item in enumerate(command[:-1])
                if item == "--mount"
            ]
            self.assertIn(
                f"type=bind,src={(artifacts / 'artifacts').resolve()},dst=/workspace/artifacts",
                mounts,
            )
            self.assertFalse(
                any(item.startswith("--tmpfs=/workspace/artifacts:") for item in command)
            )


if __name__ == "__main__":
    unittest.main()
