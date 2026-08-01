import tempfile
import unittest
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
                ExecutionPolicy(allow_host_execution=True, allow_network=True),
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


if __name__ == "__main__":
    unittest.main()
