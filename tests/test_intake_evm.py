import unittest
from pathlib import Path

from nirvana.evm import SolidityCandidateScanner
from nirvana.intake import RepositoryIntake


FIXTURE = Path(__file__).parent / "fixtures" / "evm"


class IntakeAndEvmTests(unittest.TestCase):
    def test_intake_marks_agent_guidance_untrusted(self) -> None:
        scope = RepositoryIntake().inspect(FIXTURE)
        self.assertIn("AGENTS.md", scope.untrusted_instruction_surfaces)
        self.assertIn("foundry", scope.toolchains)
        self.assertIn("evm", scope.frameworks)

    def test_scanner_masks_comments_and_emits_hypotheses_only(self) -> None:
        hypotheses = SolidityCandidateScanner().scan_repository(FIXTURE)
        rule_ids = [item.generator for item in hypotheses]
        self.assertEqual(rule_ids.count("deterministic:EVM-AUTH-TX-ORIGIN"), 1)
        self.assertEqual(rule_ids.count("deterministic:EVM-EFFECT-DELEGATECALL"), 1)
        self.assertTrue(all(item.evidence_level.value == "hypothesis" for item in hypotheses))


if __name__ == "__main__":
    unittest.main()
