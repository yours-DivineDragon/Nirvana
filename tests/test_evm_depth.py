import json
import tempfile
import unittest
from pathlib import Path

from nirvana.evm import SolcAstCandidateScanner


def identifier(name: str, declaration: int | None = None) -> dict[str, object]:
    value: dict[str, object] = {"nodeType": "Identifier", "name": name}
    if declaration is not None:
        value["referencedDeclaration"] = declaration
    return value


def member_call(
    base: dict[str, object], member: str, offset: int
) -> dict[str, object]:
    return {
        "nodeType": "FunctionCall",
        "src": f"{offset}:1:0",
        "arguments": [],
        "expression": {
            "nodeType": "MemberAccess",
            "memberName": member,
            "expression": base,
        },
    }


def assignment(state_id: int, offset: int) -> dict[str, object]:
    return {
        "nodeType": "Assignment",
        "src": f"{offset}:1:0",
        "leftHandSide": identifier("state", state_id),
        "rightHandSide": {"nodeType": "Literal", "value": "1"},
    }


def indexed_assignment(
    state_id: int, index: dict[str, object], offset: int
) -> dict[str, object]:
    return {
        "nodeType": "Assignment",
        "src": f"{offset}:1:0",
        "leftHandSide": {
            "nodeType": "IndexAccess",
            "baseExpression": identifier("position", state_id),
            "indexExpression": index,
        },
        "rightHandSide": {"nodeType": "Literal", "value": "1"},
    }


def guard(condition: dict[str, object], offset: int) -> dict[str, object]:
    return {
        "nodeType": "ExpressionStatement",
        "src": f"{offset}:1:0",
        "expression": {
            "nodeType": "FunctionCall",
            "src": f"{offset}:1:0",
            "expression": identifier("require"),
            "arguments": [condition],
        },
    }


def comparison(
    left: dict[str, object], operator: str, right: dict[str, object]
) -> dict[str, object]:
    return {
        "nodeType": "BinaryOperation",
        "operator": operator,
        "leftExpression": left,
        "rightExpression": right,
    }


def function(
    declaration_id: int,
    name: str,
    statements: list[dict[str, object]],
    *,
    visibility: str = "external",
    modifiers: tuple[str, ...] = (),
    parameters: tuple[tuple[int, str], ...] = (),
    offset: int = 10,
    state_mutability: str = "nonpayable",
) -> dict[str, object]:
    return {
        "nodeType": "FunctionDefinition",
        "id": declaration_id,
        "name": name,
        "kind": "function",
        "visibility": visibility,
        "stateMutability": state_mutability,
        "src": f"{offset}:10:0",
        "modifiers": [
            {
                "nodeType": "ModifierInvocation",
                "modifierName": {"nodeType": "IdentifierPath", "name": item},
            }
            for item in modifiers
        ],
        "parameters": {
            "nodeType": "ParameterList",
            "parameters": [
                {
                    "nodeType": "VariableDeclaration",
                    "id": parameter_id,
                    "name": parameter_name,
                }
                for parameter_id, parameter_name in parameters
            ],
        },
        "body": {"nodeType": "Block", "statements": statements},
    }


def state_variable(declaration_id: int, name: str) -> dict[str, object]:
    return {
        "nodeType": "VariableDeclaration",
        "id": declaration_id,
        "name": name,
        "stateVariable": True,
        "src": "1:1:0",
    }


class SolidityDepthTests(unittest.TestCase):
    def scan(self, contract_nodes: list[dict[str, object]]) -> list:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Vault.sol").write_text("contract Vault {}\n" + ("\n" * 300))
            document = {
                "sources": {
                    "Vault.sol": {
                        "ast": {
                            "nodeType": "SourceUnit",
                            "nodes": [
                                {
                                    "nodeType": "ContractDefinition",
                                    "id": 900,
                                    "name": "Vault",
                                    "canonicalName": "Vault",
                                    "nodes": contract_nodes,
                                }
                            ],
                        }
                    }
                }
            }
            ast_path = root / "solc-output.json"
            ast_path.write_text(json.dumps(document))
            return SolcAstCandidateScanner().scan_file(ast_path, root)

    def test_inverse_paths_flag_omitted_liability_and_guard(self) -> None:
        transfer = member_call(identifier("token"), "transfer", 20)
        transfer_from = member_call(identifier("token"), "transferFrom", 50)
        hypotheses = self.scan(
            [
                state_variable(1, "cash"),
                state_variable(2, "totalDebt"),
                function(
                    10,
                    "borrow",
                    [
                        {"nodeType": "ExpressionStatement", "expression": transfer},
                        assignment(1, 30),
                    ],
                    modifiers=("whenNotPaused",),
                    offset=10,
                ),
                function(
                    11,
                    "repay",
                    [
                        {"nodeType": "ExpressionStatement", "expression": transfer_from},
                        assignment(1, 60),
                        assignment(2, 70),
                    ],
                    offset=40,
                ),
            ]
        )

        generators = {item.generator for item in hypotheses}
        self.assertIn("symmetry-analysis:state-parity", generators)
        self.assertIn("symmetry-analysis:guard-parity", generators)
        parity = next(
            item
            for item in hypotheses
            if item.generator == "symmetry-analysis:state-parity"
        )
        self.assertIn("totalDebt", parity.suspected_violation)
        self.assertEqual(
            {item.symbol for item in parity.candidate_locations}, {"borrow", "repay"}
        )

    def test_internal_call_closure_prevents_a_false_asymmetry(self) -> None:
        borrow_helper = function(
            12,
            "_borrow",
            [
                assignment(1, 100),
                assignment(2, 101),
                {
                    "nodeType": "ExpressionStatement",
                    "expression": member_call(identifier("token"), "transfer", 102),
                },
            ],
            visibility="internal",
            offset=90,
        )
        repay_helper = function(
            13,
            "_repay",
            [
                assignment(1, 120),
                assignment(2, 121),
                {
                    "nodeType": "ExpressionStatement",
                    "expression": member_call(identifier("token"), "transferFrom", 122),
                },
            ],
            visibility="internal",
            offset=110,
        )
        hypotheses = self.scan(
            [
                state_variable(1, "cash"),
                state_variable(2, "totalDebt"),
                function(
                    10,
                    "borrow",
                    [
                        {
                            "nodeType": "ExpressionStatement",
                            "expression": {
                                "nodeType": "FunctionCall",
                                "expression": identifier("_borrow", 12),
                                "arguments": [],
                            },
                        }
                    ],
                    modifiers=("whenNotPaused",),
                    offset=10,
                ),
                function(
                    11,
                    "repay",
                    [
                        {
                            "nodeType": "ExpressionStatement",
                            "expression": {
                                "nodeType": "FunctionCall",
                                "expression": identifier("_repay", 13),
                                "arguments": [],
                            },
                        }
                    ],
                    modifiers=("whenNotPaused",),
                    offset=40,
                ),
                borrow_helper,
                repay_helper,
            ]
        )

        self.assertFalse(
            any(item.generator.startswith("symmetry-analysis:") for item in hypotheses)
        )

    def test_mapping_key_state_read_is_not_treated_as_a_write(self) -> None:
        hypotheses = self.scan(
            [
                state_variable(1, "position"),
                state_variable(2, "feeRecipient"),
                function(
                    10,
                    "depositAssets",
                    [indexed_assignment(1, identifier("account"), 20)],
                    offset=10,
                ),
                function(
                    11,
                    "withdrawAssets",
                    [indexed_assignment(1, identifier("feeRecipient", 2), 50)],
                    offset=40,
                ),
            ]
        )

        self.assertFalse(
            any(item.generator == "symmetry-analysis:state-parity" for item in hypotheses)
        )

    def test_view_call_name_is_not_treated_as_an_asset_effect(self) -> None:
        view_withdraw = member_call(identifier("vault"), "withdraw", 50)
        view_withdraw["expression"]["typeDescriptions"] = {
            "typeIdentifier": "t_function_external_view$__$returns$_t_uint256_$",
            "typeString": "function () view external returns (uint256)",
        }
        hypotheses = self.scan(
            [
                state_variable(1, "cash"),
                function(
                    10,
                    "maxDeposit",
                    [{"nodeType": "Return", "expression": identifier("cash", 1)}],
                    offset=10,
                    state_mutability="view",
                ),
                function(
                    11,
                    "maxWithdraw",
                    [
                        {"nodeType": "ExpressionStatement", "expression": view_withdraw},
                        {"nodeType": "Return", "expression": identifier("cash", 1)},
                    ],
                    offset=40,
                    state_mutability="view",
                ),
            ]
        )

        self.assertFalse(
            any(item.generator == "symmetry-analysis:effect-parity" for item in hypotheses)
        )

    def test_unchecked_and_user_controlled_calls_have_benign_controls(self) -> None:
        unsafe_call = member_call(identifier("target", 20), "call", 20)
        safe_call = member_call(identifier("target", 21), "call", 60)
        captured_call = member_call(identifier("target", 22), "call", 100)
        hypotheses = self.scan(
            [
                state_variable(1, "cash"),
                function(
                    10,
                    "execute",
                    [
                        {"nodeType": "ExpressionStatement", "expression": unsafe_call},
                        assignment(1, 30),
                    ],
                    parameters=((20, "target"),),
                    offset=10,
                ),
                function(
                    11,
                    "safeExecute",
                    [
                        {
                            "nodeType": "VariableDeclarationStatement",
                            "declarations": [
                                {
                                    "nodeType": "VariableDeclaration",
                                    "id": 30,
                                    "name": "ok",
                                }
                            ],
                            "initialValue": safe_call,
                        },
                        guard(identifier("ok", 30), 70),
                        assignment(1, 80),
                    ],
                    modifiers=("onlyOwner",),
                    parameters=((21, "target"),),
                    offset=50,
                ),
                function(
                    12,
                    "capturedButUnchecked",
                    [
                        {
                            "nodeType": "VariableDeclarationStatement",
                            "declarations": [
                                {
                                    "nodeType": "VariableDeclaration",
                                    "id": 31,
                                    "name": "ok",
                                }
                            ],
                            "initialValue": captured_call,
                        },
                        assignment(1, 110),
                    ],
                    modifiers=("onlyOwner",),
                    parameters=((22, "target"),),
                    offset=90,
                ),
            ]
        )

        unchecked = [
            item
            for item in hypotheses
            if item.generator == "solc-ast:EVM-AST-UNCHECKED-LOW-LEVEL-CALL"
        ]
        controlled = [
            item
            for item in hypotheses
            if item.generator == "solc-ast:EVM-AST-USER-CONTROLLED-CALL"
        ]
        self.assertEqual(
            [item.candidate_locations[0].symbol for item in unchecked],
            ["execute", "capturedButUnchecked"],
        )
        self.assertEqual([item.candidate_locations[0].symbol for item in controlled], ["execute"])

    def test_oracle_integrity_requires_positive_fresh_and_complete_round(self) -> None:
        oracle_read = member_call(identifier("feed"), "latestRoundData", 20)
        safe_read = member_call(identifier("feed"), "latestRoundData", 100)
        hypotheses = self.scan(
            [
                function(
                    10,
                    "quote",
                    [{"nodeType": "ExpressionStatement", "expression": oracle_read}],
                    offset=10,
                ),
                function(
                    11,
                    "safeQuote",
                    [
                        {"nodeType": "ExpressionStatement", "expression": safe_read},
                        guard(
                            comparison(
                                identifier("answer"),
                                ">",
                                {"nodeType": "Literal", "value": "0"},
                            ),
                            110,
                        ),
                        guard(
                            comparison(
                                {
                                    "nodeType": "BinaryOperation",
                                    "operator": "-",
                                    "leftExpression": identifier("timestamp"),
                                    "rightExpression": identifier("updatedAt"),
                                },
                                "<=",
                                identifier("maxAge"),
                            ),
                            120,
                        ),
                        guard(
                            comparison(
                                identifier("answeredInRound"),
                                ">=",
                                identifier("roundId"),
                            ),
                            130,
                        ),
                    ],
                    offset=90,
                ),
            ]
        )

        oracle_candidates = [
            item
            for item in hypotheses
            if item.generator == "solc-ast:EVM-AST-ORACLE-INTEGRITY"
        ]
        self.assertEqual(
            [item.candidate_locations[0].symbol for item in oracle_candidates], ["quote"]
        )
        self.assertIn("freshness", oracle_candidates[0].suspected_violation)

    def test_non_reentrant_modifier_is_a_benign_ordering_control(self) -> None:
        hypotheses = self.scan(
            [
                state_variable(1, "cash"),
                function(
                    10,
                    "withdraw",
                    [
                        {
                            "nodeType": "ExpressionStatement",
                            "expression": member_call(identifier("recipient"), "call", 20),
                        },
                        assignment(1, 30),
                    ],
                    modifiers=("nonReentrant",),
                    offset=10,
                ),
            ]
        )

        self.assertNotIn(
            "solc-ast:EVM-AST-REENTRANCY",
            {item.generator for item in hypotheses},
        )


if __name__ == "__main__":
    unittest.main()
