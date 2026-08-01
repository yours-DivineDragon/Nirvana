import json
import tempfile
import unittest
from pathlib import Path

from nirvana.adjudication import AdjudicationBoard
from nirvana.board import HypothesisBoard
from nirvana.ledger import EvidenceLedger
from nirvana.models import CodeLocation, EvidenceLevel, Finding, Severity
from nirvana.variants import mine_historical_variants
from nirvana.workflow import audit


FIXTURE = Path(__file__).parent / "fixtures" / "evm"


class AdjudicationVariantTests(unittest.TestCase):
    def test_devil_rejection_is_archived_and_rescue_reopens_the_hypothesis(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            hypothesis_id = result.hypotheses[0].hypothesis_id
            decision = root / "reject.json"
            decision.write_text(
                json.dumps(
                    {
                        "hypothesis_id": hypothesis_id,
                        "critic": "devils_advocate",
                        "decision": "reject",
                        "reasons": ["the suspected authority effect is unreachable"],
                        "assumptions_examined": ["external reachability"],
                        "evidence_ids": [],
                        "next_experiment": "prove the dispatch edge",
                    }
                )
            )
            AdjudicationBoard(result.run_directory).submit_critic_decision(decision)
            rejected = {
                item["hypothesis_id"]: item["status"]
                for item in HypothesisBoard(result.run_directory).list_hypotheses()
            }
            self.assertEqual(rejected[hypothesis_id], "rejected")
            report = json.loads((result.run_directory / "report.json").read_text())
            self.assertEqual(report["rejection_archive"][0]["hypothesis_id"], hypothesis_id)

            rescue = root / "rescue.json"
            rescue.write_text(
                json.dumps(
                    {
                        "hypothesis_id": hypothesis_id,
                        "critic": "rescue",
                        "decision": "rescue",
                        "reasons": ["the reachability assumption was not compiler-confirmed"],
                        "assumptions_examined": ["external reachability"],
                        "evidence_ids": [],
                        "next_experiment": "obtain a compiler call graph",
                    }
                )
            )
            AdjudicationBoard(result.run_directory).submit_critic_decision(rescue)
            statuses = {
                item["hypothesis_id"]: item["status"]
                for item in HypothesisBoard(result.run_directory).list_hypotheses()
            }
            self.assertEqual(statuses[hypothesis_id], "rescued")

    def test_novelty_is_computed_only_for_confirmed_findings_and_variants_are_mined(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = audit(FIXTURE, root / "runs")
            hypothesis = result.hypotheses[0]
            finding = Finding(
                finding_id="F-KNOWN",
                hypothesis_id=hypothesis.hypothesis_id,
                title="Known authority defect",
                severity=Severity.MEDIUM,
                evidence_level=EvidenceLevel.STRUCTURALLY_CONFIRMED,
                security_property="Authority changes require the intended owner",
                root_cause="owner authority upgrade lacks the intended guard",
                locations=[CodeLocation("src/Vault.sol", 11)],
                attacker_prerequisites=["call the entry point"],
                assumptions=[],
                causal_path=["owner", "upgrade"],
                reproducer="structural path",
                impact="authority confusion",
                severity_rationale="material authority effect without demonstrated asset loss",
                reproduction_instructions=["re-run analyzers"],
                remediation="bind the upgrade to owner authority",
                regression_test="add an unauthorized caller negative case",
                supporting_evidence=["E-STRUCT"],
            )
            EvidenceLedger(result.run_directory / "evidence.jsonl").append(
                {"event": "finding_confirmed", "finding": finding.to_dict()}
            )
            corpus = root / "known.json"
            corpus.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0.0",
                        "created_at": "2025-01-01T00:00:00Z",
                        "issues": [
                            {
                                "issue_id": "ISSUE-1",
                                "affected_version": "vulnerable",
                                "code_identity": "src/Vault.sol",
                                "security_property": finding.security_property,
                                "root_cause": finding.root_cause,
                                "root_cause_graph": finding.causal_path,
                                "attacker_prerequisites": finding.attacker_prerequisites,
                                "exploit_sequence": finding.reproduction_instructions,
                                "impact": finding.impact,
                                "fix_strategy": finding.remediation,
                                "historical_lineage": [],
                                "status": "fixed",
                                "provenance": "private reviewed issue corpus",
                                "published_at": "2024-01-01T00:00:00Z",
                            }
                        ],
                    }
                )
            )
            assessment = AdjudicationBoard(result.run_directory).assess_novelty(
                finding.finding_id, corpus
            )
            self.assertEqual(assessment["classification"], "exact_duplicate")
            self.assertEqual(assessment["related_issues"], ["ISSUE-1"])
            self.assertTrue(
                all(
                    assessment["causal_comparisons"][0]["dimensions"][dimension]
                    for dimension in (
                        "security_property",
                        "root_cause",
                        "causal_graph",
                        "attacker_prerequisites",
                        "exploit_sequence",
                        "impact",
                        "fix_strategy",
                        "code_identity",
                    )
                )
            )

            variants = mine_historical_variants(
                result.run_directory, corpus, "2025-01-01T00:00:00Z"
            )
            self.assertTrue(variants)
            self.assertTrue(
                {item.generator for item in variants}
                & {"historical-variant-miner", "retrieval-analogy"}
            )


if __name__ == "__main__":
    unittest.main()
