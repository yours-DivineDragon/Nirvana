import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nirvana.evm import SolidityCandidateScanner
from nirvana.intake import RepositoryIntake


FIXTURE = Path(__file__).parent / "fixtures" / "evm"


class IntakeAndEvmTests(unittest.TestCase):
    def test_intake_marks_agent_guidance_untrusted(self) -> None:
        scope = RepositoryIntake().inspect(FIXTURE)
        self.assertIn("AGENTS.md", scope.untrusted_instruction_surfaces)
        self.assertIn("foundry", scope.toolchains)
        self.assertIn("evm", scope.frameworks)

    def test_intake_never_executes_target_configured_git(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "hostile"
            git_directory = target / ".git"
            (git_directory / "refs" / "heads").mkdir(parents=True)
            (target / "Contract.sol").write_text("contract Contract {}\n")
            commit = "a" * 40
            (git_directory / "HEAD").write_text("ref: refs/heads/main\n")
            (git_directory / "refs" / "heads" / "main").write_text(commit + "\n")
            (git_directory / "config").write_text(
                "[core]\n\tfsmonitor = sh -c 'exit 99'\n"
            )

            with patch("subprocess.run", side_effect=AssertionError("target Git executed")):
                scope = RepositoryIntake().inspect(target)

            self.assertEqual(scope.repository_commit, commit)
            self.assertIsNone(scope.repository_dirty)
            self.assertRegex(scope.target_snapshot_sha256, r"^[a-f0-9]{64}$")
            self.assertTrue(any("never executes" in warning for warning in scope.warnings))

    def test_subdirectory_does_not_inherit_enclosing_repository_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git_directory = root / ".git"
            target = root / "target"
            git_directory.mkdir()
            target.mkdir()
            (git_directory / "HEAD").write_text("b" * 40 + "\n")
            (target / "Contract.sol").write_text("contract Contract {}\n")

            scope = RepositoryIntake().inspect(target)

            self.assertIsNone(scope.repository_commit)
            self.assertIsNone(scope.repository_dirty)

    def test_scanner_masks_comments_and_emits_hypotheses_only(self) -> None:
        hypotheses = SolidityCandidateScanner().scan_repository(FIXTURE)
        rule_ids = [item.generator for item in hypotheses]
        self.assertEqual(rule_ids.count("deterministic:EVM-AUTH-TX-ORIGIN"), 1)
        self.assertEqual(rule_ids.count("deterministic:EVM-EFFECT-DELEGATECALL"), 1)
        self.assertTrue(all(item.evidence_level.value == "hypothesis" for item in hypotheses))


if __name__ == "__main__":
    unittest.main()
