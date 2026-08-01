import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nirvana.evm import SolcAstCandidateScanner, SolidityCandidateScanner
from nirvana.intake import IntakePolicy, RepositoryIntake


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

    def test_oversized_files_are_stream_hashed_and_keep_snapshot_complete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            artifact = target / "artifact.bin"
            artifact.write_bytes(b"x" * 6_000_001)

            scope = RepositoryIntake(max_file_bytes=1_000_000).inspect(target)

            record = next(item for item in scope.files if item.path == "artifact.bin")
            self.assertEqual(record.kind, "oversized")
            self.assertRegex(record.sha256 or "", r"^[a-f0-9]{64}$")
            self.assertTrue(scope.snapshot_complete)

    def test_intake_policy_exposes_analysis_limit_and_extra_exclusions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "nirvana.toml"
            policy_path.write_text(
                "[intake]\nmax_file_bytes = 12345\n"
                'excluded_directories = ["vendor-generated"]\n'
            )
            policy = IntakePolicy.load(policy_path)

            self.assertEqual(policy.max_file_bytes, 12345)
            self.assertIn("vendor-generated", policy.excluded_directories)
            self.assertIn(".git", policy.excluded_directories)
            self.assertTrue(
                {
                    ".anchor",
                    ".pytest_cache",
                    "artifacts",
                    "broadcast",
                    "cache",
                    "crytic-export",
                }
                <= policy.excluded_directories
            )

    def test_slither_crytic_export_does_not_mutate_the_scoped_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "Contract.sol").write_text("contract Contract {}\n")
            intake = RepositoryIntake()
            before = intake.inspect(target)

            export = target / "crytic-export"
            export.mkdir()
            (export / "compile.json").write_text('{"generated": true}\n')
            after = intake.inspect(target)

            self.assertEqual(
                after.target_snapshot_sha256, before.target_snapshot_sha256
            )
            self.assertNotIn("crytic-export/compile.json", {item.path for item in after.files})

    def test_solc_ast_scanner_emits_contextual_security_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Vault.sol"
            source.write_text("contract Vault { uint totalSupply; function deposit() external {} }\n")
            ast = {
                "sources": {
                    "Vault.sol": {
                        "ast": {
                            "nodeType": "SourceUnit",
                            "nodes": [
                                {
                                    "nodeType": "VariableDeclaration",
                                    "id": 1,
                                    "stateVariable": True,
                                    "src": "17:16:0",
                                },
                                {
                                    "nodeType": "FunctionDefinition",
                                    "name": "deposit",
                                    "kind": "function",
                                    "visibility": "external",
                                    "stateMutability": "nonpayable",
                                    "src": "35:30:0",
                                    "modifiers": [],
                                    "body": {
                                        "nodeType": "Block",
                                        "statements": [
                                            {
                                                "nodeType": "FunctionCall",
                                                "src": "40:4:0",
                                                "expression": {
                                                    "nodeType": "MemberAccess",
                                                    "memberName": "call",
                                                },
                                            },
                                            {
                                                "nodeType": "MemberAccess",
                                                "memberName": "getReserves",
                                                "src": "44:4:0",
                                            },
                                            {
                                                "nodeType": "BinaryOperation",
                                                "operator": "/",
                                                "src": "48:4:0",
                                                "leftExpression": {
                                                    "nodeType": "Identifier",
                                                    "name": "totalSupply",
                                                },
                                            },
                                            {
                                                "nodeType": "Assignment",
                                                "src": "52:4:0",
                                                "leftHandSide": {
                                                    "nodeType": "Identifier",
                                                    "referencedDeclaration": 1,
                                                },
                                            },
                                        ],
                                    },
                                },
                            ],
                        }
                    }
                }
            }
            ast_path = root / "solc-output.json"
            ast_path.write_text(json.dumps(ast))

            hypotheses = SolcAstCandidateScanner().scan_file(ast_path, root)
            generators = {item.generator for item in hypotheses}

            self.assertEqual(
                generators,
                {
                    "solc-ast:EVM-AST-REENTRANCY",
                    "solc-ast:EVM-AST-MISSING-AUTHORITY",
                    "solc-ast:EVM-AST-SPOT-ORACLE",
                    "solc-ast:EVM-AST-SHARE-INFLATION",
                },
            )


if __name__ == "__main__":
    unittest.main()
