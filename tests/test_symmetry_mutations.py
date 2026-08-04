import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tools.scan_symmetry_ast import main as scan_symmetry_main
from tools.measure_symmetry_mutations import (
    apply_mutation,
    canonical_ast_bytes,
    normalized_ast_document,
    run_measurement,
)


def _identifier(name: str, declaration: int | None = None) -> dict[str, object]:
    value: dict[str, object] = {"nodeType": "Identifier", "name": name}
    if declaration is not None:
        value["referencedDeclaration"] = declaration
    return value


def _assignment(state_id: int, offset: int) -> dict[str, object]:
    return {
        "nodeType": "ExpressionStatement",
        "src": f"{offset}:1:0",
        "expression": {
            "nodeType": "Assignment",
            "src": f"{offset}:1:0",
            "leftHandSide": _identifier("totalAssets", state_id),
            "rightHandSide": {"nodeType": "Literal", "value": "1"},
        },
    }


def _function(
    declaration_id: int,
    name: str,
    statements: list[dict[str, object]],
    *,
    offset: int,
    modifier_src: str | None = None,
) -> dict[str, object]:
    modifiers: list[dict[str, object]] = []
    if modifier_src is not None:
        modifiers.append(
            {
                "nodeType": "ModifierInvocation",
                "src": modifier_src,
                "modifierName": {
                    "nodeType": "IdentifierPath",
                    "name": "nonReentrant",
                },
            }
        )
    return {
        "nodeType": "FunctionDefinition",
        "id": declaration_id,
        "name": name,
        "kind": "function",
        "visibility": "external",
        "stateMutability": "nonpayable",
        "src": f"{offset}:10:0",
        "modifiers": modifiers,
        "body": {"nodeType": "Block", "statements": statements},
    }


def _combined_document() -> dict[str, object]:
    return {
        "sources": {
            "Vault.sol": {
                "AST": {
                    "nodeType": "SourceUnit",
                    "nodes": [
                        {
                            "nodeType": "ContractDefinition",
                            "id": 900,
                            "name": "Vault",
                            "canonicalName": "Vault",
                            "nodes": [
                                {
                                    "nodeType": "VariableDeclaration",
                                    "id": 1,
                                    "name": "totalAssets",
                                    "stateVariable": True,
                                    "src": "1:1:0",
                                },
                                _function(
                                    10,
                                    "deposit",
                                    [_assignment(1, 20)],
                                    offset=10,
                                    modifier_src="11:1:0",
                                ),
                                _function(
                                    11,
                                    "withdraw",
                                    [_assignment(1, 50)],
                                    offset=40,
                                    modifier_src="41:1:0",
                                ),
                            ],
                        }
                    ],
                }
            }
        }
    }


class SymmetryMutationMeasurementTests(unittest.TestCase):
    def test_published_manifest_pins_ten_unique_repository_mutations(self) -> None:
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads(
            root.joinpath(
                "docs", "symmetry-mutation-cases-2026-08.json"
            ).read_text()
        )

        self.assertEqual(manifest["schema_version"], "1.0.0")
        self.assertEqual(len(manifest["cases"]), 10)
        self.assertEqual(
            len({item["case_id"] for item in manifest["cases"]}),
            10,
        )
        self.assertEqual(
            len({item["repository"] for item in manifest["cases"]}),
            10,
        )

    def test_guard_and_write_mutations_are_reached_triggered_and_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            target = workspace / "target"
            target.mkdir()
            target.joinpath("Vault.sol").write_text("contract Vault {}\n" + "\n" * 100)
            combined = _combined_document()
            workspace.joinpath("combined.json").write_text(json.dumps(combined))
            digest = hashlib.sha256(
                canonical_ast_bytes(normalized_ast_document(combined))
            ).hexdigest()
            manifest = {
                "schema_version": "1.0.0",
                "cases": [
                    {
                        "case_id": "guard",
                        "repository": "fixture/vault",
                        "target_root": "target",
                        "combined_json": "combined.json",
                        "expected_ast_sha256": digest,
                        "expected_baseline_symmetry_hypotheses": 0,
                        "mutation": {
                            "kind": "remove_guard",
                            "function_id": 11,
                            "node_src": "41:1:0",
                            "category": "reentrancy",
                        },
                        "pair": {
                            "left_operation_id": 10,
                            "right_operation_id": 11,
                            "expected_generator": "symmetry-analysis:guard-parity",
                        },
                        "observation": {
                            "operation_id": 11,
                            "field": "guards",
                            "value": "reentrancy",
                        },
                    },
                    {
                        "case_id": "write",
                        "repository": "fixture/vault",
                        "target_root": "target",
                        "combined_json": "combined.json",
                        "expected_ast_sha256": digest,
                        "expected_baseline_symmetry_hypotheses": 0,
                        "mutation": {
                            "kind": "remove_write",
                            "function_id": 11,
                            "node_src": "50:1:0",
                            "state": "totalAssets",
                        },
                        "pair": {
                            "left_operation_id": 10,
                            "right_operation_id": 11,
                            "expected_generator": "symmetry-analysis:state-parity",
                        },
                        "observation": {
                            "operation_id": 11,
                            "field": "state_writes",
                            "value": "totalAssets",
                        },
                    },
                ],
            }
            manifest_path = workspace / "manifest.json"
            manifest_path.write_text(json.dumps(manifest))

            result = run_measurement(
                workspace,
                manifest_path,
                workspace / "result.json",
            )

            self.assertEqual(
                result["summary"],
                {
                    "repositories": 2,
                    "baseline_symmetry_hypotheses": 0,
                    "reached": 2,
                    "triggered": 2,
                    "detected": 2,
                    "detection_fraction": "2/2",
                },
            )
            self.assertTrue(all(item["magma"]["detected"] for item in result["cases"]))

    def test_remove_call_deletes_the_enclosing_statement(self) -> None:
        combined = _combined_document()
        contract = combined["sources"]["Vault.sol"]["AST"]["nodes"][0]
        burn = _function(
            20,
            "burn",
            [
                {
                    "nodeType": "ExpressionStatement",
                    "src": "100:5:0",
                    "expression": {
                        "nodeType": "FunctionCall",
                        "src": "100:5:0",
                        "expression": _identifier("_spendAllowance", 30),
                        "arguments": [],
                    },
                }
            ],
            offset=90,
        )
        contract["nodes"].append(burn)

        result = apply_mutation(
            combined,
            {
                "kind": "remove_call",
                "function_id": 20,
                "node_src": "100:5:0",
                "callee_id": 30,
            },
        )

        self.assertEqual(result["removed_node_type"], "ExpressionStatement")
        self.assertEqual(burn["body"]["statements"], [])

    def test_scan_tool_accepts_a_canonical_normalized_ast(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.joinpath("Vault.sol").write_text("contract Vault {}\n" + "\n" * 100)
            normalized = normalized_ast_document(_combined_document())
            input_path = root / "normalized.json"
            output_path = root / "result.json"
            input_path.write_text(json.dumps(normalized))

            with patch(
                "sys.argv",
                [
                    "scan_symmetry_ast.py",
                    str(root),
                    str(input_path),
                    str(output_path),
                ],
            ), redirect_stdout(io.StringIO()):
                scan_symmetry_main()

            result = json.loads(output_path.read_text())
            self.assertEqual(result["symmetry_hypotheses"], [])
            self.assertTrue(output_path.with_suffix(".ast.json").is_file())

    def test_manifest_paths_cannot_escape_the_measurement_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            manifest_path = workspace / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0.0",
                        "cases": [
                            {
                                "case_id": "escape",
                                "repository": "fixture/vault",
                                "target_root": "target",
                                "combined_json": "../combined.json",
                                "expected_ast_sha256": "a" * 64,
                                "mutation": {},
                                "pair": {},
                                "observation": {},
                            }
                        ],
                    }
                )
            )

            with self.assertRaisesRegex(ValueError, "safe relative path"):
                run_measurement(workspace, manifest_path, workspace / "result.json")


if __name__ == "__main__":
    unittest.main()
