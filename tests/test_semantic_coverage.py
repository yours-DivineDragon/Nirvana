import json
import tempfile
import unittest
from pathlib import Path

from nirvana.coverage import CoverageBoard
from nirvana.intake import RepositoryIntake
from nirvana.semantic import SecuritySemanticGraph
from nirvana.workflow import audit


class SemanticCoverageTests(unittest.TestCase):
    def test_solc_ast_adds_typed_declarations_and_reference_edges(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            source_text = (
                "contract Vault {\n"
                "    uint256 balance;\n"
                "    function setBalance(uint256 value) external { balance = value; }\n"
                "}\n"
            )
            (target / "Vault.sol").write_text(source_text)
            variable_offset = source_text.index("uint256 balance")
            function_offset = source_text.index("function setBalance")
            assignment_offset = source_text.index("balance = value")
            ast = root / "solc-output.json"
            ast.write_text(
                json.dumps(
                    {
                        "sources": {
                            "Vault.sol": {
                                "ast": {
                                    "nodeType": "SourceUnit",
                                    "nodes": [
                                        {
                                            "nodeType": "VariableDeclaration",
                                            "id": 1,
                                            "name": "balance",
                                            "stateVariable": True,
                                            "src": f"{variable_offset}:15:0",
                                            "typeDescriptions": {"typeString": "uint256"},
                                        },
                                        {
                                            "nodeType": "FunctionDefinition",
                                            "id": 2,
                                            "name": "setBalance",
                                            "kind": "function",
                                            "visibility": "external",
                                            "stateMutability": "nonpayable",
                                            "src": f"{function_offset}:64:0",
                                            "modifiers": [],
                                            "body": {
                                                "nodeType": "Block",
                                                "statements": [
                                                    {
                                                        "nodeType": "Assignment",
                                                        "src": f"{assignment_offset}:15:0",
                                                        "leftHandSide": {
                                                            "nodeType": "Identifier",
                                                            "referencedDeclaration": 1,
                                                        },
                                                    }
                                                ],
                                            },
                                        },
                                    ],
                                }
                            }
                        }
                    }
                )
            )

            result = audit(target, root / "runs", solc_ast=ast)
            graph = SecuritySemanticGraph.from_dict(
                json.loads((result.run_directory / "semantic-graph.json").read_text())
            )
            support = {item.dialect: item for item in graph.support}
            self.assertEqual(support["evm"].maturity.value, "typed")
            state = next(
                item
                for item in graph.nodes
                if item.kind == "state" and item.label == "balance"
            )
            self.assertEqual(state.properties["type"], "uint256")
            self.assertTrue(
                any(
                    edge.target == state.node_id
                    and edge.kind == "writes"
                    and edge.properties.get("resolution") == "solc-reference"
                    for edge in graph.edges
                )
            )

    def test_polyglot_graph_publishes_truthful_maturity_and_schedule(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            (target / "Vault.sol").write_text(
                "contract Vault { mapping(address=>uint) balance; "
                "function withdraw(uint amount) external { msg.sender.call(\"\"); balance[msg.sender] = 0; } }"
            )
            (target / "module.move").write_text(
                "module app::vault { public entry fun transfer_asset() { assert!(true, 0); } }"
            )
            (target / "api.py").write_text(
                "def withdraw_handler(amount):\n    database.write(amount)\n"
            )
            (target / "Runtime.java").write_text(
                "public class Runtime { public void execute() { deserialize(request); } }"
            )
            (target / "module.wat").write_text("(module (func $entry (export \"entry\")))")

            result = audit(target, root / "runs")
            graph_value = json.loads(
                (result.run_directory / "semantic-graph.json").read_text()
            )
            graph = SecuritySemanticGraph.from_dict(graph_value)
            support = {item.dialect: item.maturity.value for item in graph.support}
            self.assertEqual(support["evm"], "syntax_only")
            self.assertEqual(support["move-sui"], "syntax_only")
            self.assertEqual(support["web-api"], "syntax_only")
            self.assertEqual(support["jvm"], "syntax_only")
            self.assertEqual(support["wasm"], "syntax_only")
            self.assertTrue(any(item.kind == "asset" for item in graph.nodes))
            self.assertTrue(any(item.kind == "trust_boundary" for item in graph.nodes))
            generators = {item.generator for item in result.hypotheses}
            self.assertIn("semantic-graph-query", generators)
            self.assertIn("test-gap-analysis", generators)
            self.assertIn("historical-variant-miner", generators)
            self.assertIn("retrieval-analogy", generators)

            coverage = CoverageBoard(result.run_directory).load()
            self.assertTrue(coverage.flows)
            self.assertEqual(
                len(coverage.tasks), len(coverage.flows) * len(coverage.threat_lenses)
            )
            with self.assertRaisesRegex(ValueError, "negative-analysis"):
                CoverageBoard(result.run_directory).mark(
                    coverage.tasks[0].task_id,
                    "covered",
                    [],
                    ["reviewed"],
                )
            updated = CoverageBoard(result.run_directory).mark(
                coverage.tasks[0].task_id,
                "covered",
                [],
                [
                    "negative-analysis: compiler dispatch and authority paths "
                    "contain no attacker-reachable effect"
                ],
            )
            self.assertGreater(updated.completeness["flow_threat_tasks"], 0)

    def test_intake_records_plans_versions_artifacts_and_submodule_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "foundry.toml").write_text("solc_version = '0.8.27'\n")
            (target / "Vault.sol").write_text("pragma solidity ^0.8.20; contract Vault {}\n")
            (target / "Vault.abi").write_text("[]\n")
            (target / ".gitmodules").write_text(
                '[submodule "lib/example"]\n path = lib/example\n url = https://invalid.example/repo\n'
            )
            (target / "lib" / "example").mkdir(parents=True)
            (target / "lib" / "example" / "Lib.sol").write_text("library Lib {}\n")

            scope = RepositoryIntake().inspect(target)
            self.assertEqual(scope.build_status, "planned")
            self.assertEqual(scope.test_status, "planned")
            self.assertIn(["forge", "build"], scope.build_plan)
            self.assertIn("0.8.27", scope.declared_tool_versions["solc"])
            self.assertTrue(any(item["kind"] == "evm-artifact" for item in scope.discovered_artifacts))
            self.assertRegex(scope.submodules[0]["content_snapshot_sha256"], r"^[a-f0-9]{64}$")


if __name__ == "__main__":
    unittest.main()
