import tempfile
import unittest
from pathlib import Path

from nirvana.models import CodeLocation, EvidenceLevel
from nirvana.symmetry import OperationSummary, SymmetryAnalyzer
from nirvana.workflow import audit


def operation(
    dialect: str,
    name: str,
    *,
    writes: tuple[str, ...],
    reads: tuple[str, ...] = (),
    guards: tuple[str, ...] = (),
    effects: tuple[str, ...] = ("asset-transfer",),
) -> OperationSummary:
    return OperationSummary(
        operation_id=f"{dialect}:vault:{name}",
        dialect=dialect,
        module="vault",
        name=name,
        location=CodeLocation(f"src/vault.{dialect}", 10, 20, name),
        entry_point=True,
        state_reads=frozenset(reads),
        state_writes=frozenset(writes),
        guards=frozenset(guards),
        effects=frozenset(effects),
        frontend=f"{dialect}-test-frontend",
    )


class SymmetryAnalyzerTests(unittest.TestCase):
    def test_same_analyzer_finds_state_and_guard_asymmetry_across_dialects(self) -> None:
        for dialect in ("move-sui", "solana", "web-api"):
            with self.subTest(dialect=dialect):
                hypotheses = SymmetryAnalyzer().analyze(
                    [
                        operation(
                            dialect,
                            "borrow",
                            writes=("cash",),
                            guards=("pause",),
                        ),
                        operation(
                            dialect,
                            "repay",
                            writes=("cash", "totalDebt"),
                        ),
                    ]
                )

                generators = {item.generator for item in hypotheses}
                self.assertEqual(
                    generators,
                    {
                        "symmetry-analysis:state-parity",
                        "symmetry-analysis:guard-parity",
                    },
                )
                self.assertTrue(
                    all(item.evidence_level is EvidenceLevel.HYPOTHESIS for item in hypotheses)
                )
                self.assertTrue(all(len(item.candidate_locations) == 2 for item in hypotheses))

    def test_balanced_inverse_operations_are_a_benign_negative(self) -> None:
        hypotheses = SymmetryAnalyzer().analyze(
            [
                operation(
                    "move-sui",
                    "depositAssets",
                    writes=("balances", "totalAssets"),
                    guards=("pause", "reentrancy"),
                ),
                operation(
                    "move-sui",
                    "withdrawAssets",
                    writes=("balances", "totalAssets"),
                    guards=("pause", "reentrancy"),
                ),
            ]
        )

        self.assertEqual(hypotheses, [])

    def test_unrelated_or_cross_module_operations_are_not_paired(self) -> None:
        borrow = operation("solana", "borrow", writes=("totalDebt",))
        repay = OperationSummary(
            operation_id="solana:other:repay",
            dialect="solana",
            module="other",
            name="repay",
            location=CodeLocation("src/other.rs", 1, 2, "repay"),
            entry_point=True,
            state_writes=frozenset({"cash"}),
            effects=frozenset({"asset-transfer"}),
        )
        settle = operation("solana", "settle", writes=("cash",))

        self.assertEqual(SymmetryAnalyzer().analyze([borrow, repay, settle]), [])

    def test_one_sided_security_effect_is_reported(self) -> None:
        hypotheses = SymmetryAnalyzer().analyze(
            [
                operation("rust-native", "openPosition", writes=("positions",)),
                operation(
                    "rust-native",
                    "closePosition",
                    writes=("positions",),
                    effects=(),
                ),
            ]
        )

        self.assertEqual(
            [item.generator for item in hypotheses],
            ["symmetry-analysis:effect-parity"],
        )

    def test_syntax_only_frontend_runs_symmetry_in_normal_audit_flow(self) -> None:
        for safe in (False, True):
            with self.subTest(safe=safe), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target = root / "target"
                target.mkdir()
                target.joinpath("api.py").write_text(
                    "def deposit_handler():\n"
                    "    require(owner)\n"
                    "    state.balance = 1\n"
                    "    transfer(asset)\n\n"
                    "def withdraw_handler():\n"
                    + ("    require(owner)\n" if safe else "")
                    + "    state.balance = 0\n"
                    "    transfer(asset)\n"
                )

                result = audit(target, root / "runs")
                parity = [
                    item
                    for item in result.hypotheses
                    if item.generator == "symmetry-analysis:guard-parity"
                ]
                self.assertEqual(len(parity), 0 if safe else 1)

    def test_pair_comparison_budget_is_bounded_and_visible(self) -> None:
        analyzer = SymmetryAnalyzer(max_pair_comparisons=1)
        analyzer.analyze(
            [
                operation("solana", "alpha", writes=("cash",)),
                operation("solana", "beta", writes=("cash",)),
                operation("solana", "gamma", writes=("cash",)),
            ]
        )

        self.assertTrue(analyzer.truncated)


if __name__ == "__main__":
    unittest.main()
