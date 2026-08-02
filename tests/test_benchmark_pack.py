import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from nirvana.benchmark_pack import (
    GROUND_TRUTH_COMMITMENT_ALGORITHM,
    TARGET_SNAPSHOT_ALGORITHM,
    benchmark_target_snapshot,
    canonical_ground_truth_document,
    verify_case_pack,
    write_ground_truth_commitment,
)
from nirvana.cli import main
from nirvana.util import sha256_file


class BenchmarkCasePackTests(unittest.TestCase):
    def write_pack(self, root: Path) -> Path:
        attestation = root / "independent-author-attestation.json"
        attestation.write_text(
            json.dumps({"author": "independent-team", "operator_access": False})
        )
        target = root / "cases" / "CASE-1" / "target"
        target.mkdir(parents=True)
        (target / "Fixture.sol").write_text("contract Fixture {}\n")
        reveal = target.parent / "ground-truth.json"
        reveal.write_text(
            json.dumps(
                canonical_ground_truth_document(
                    "CASE-1",
                    True,
                    [{"vulnerability_id": "VULN-1", "severity": "high"}],
                )
            )
        )
        commitment = target.parent / "commitment.json"
        commitment_record = write_ground_truth_commitment(reveal, commitment)
        reveal.unlink()
        sealed = target.parent / "ground-truth.age"
        sealed.write_text("age-encryption.org/v1\nfixture-ciphertext\n")
        pack = {
            "schema_version": "1.2.0",
            "pack_id": "independent-pack-1",
            "cutoff": "2024-12-31T00:00:00Z",
            "created_at": "2025-01-20T00:00:00Z",
            "target_snapshot_algorithm": TARGET_SNAPSHOT_ALGORITHM,
            "ground_truth_commitment_algorithm": GROUND_TRUTH_COMMITMENT_ALGORITHM,
            "author_attestation": {
                "author_id": "independent-team",
                "independent_from_trial_operator": True,
                "custody_model": "separate_human",
                "artifact_path": attestation.relative_to(root).as_posix(),
                "artifact_sha256": sha256_file(attestation),
            },
            "ground_truth_sealing": {
                "method": "age",
                "recipient_fingerprint": "age1fixture-recipient",
            },
            "generator": {
                "name": "fixture-transformer",
                "version": "1.0.0",
                "source_sha256": "1" * 64,
                "randomness": "os-csprng",
            },
            "cases": [
                {
                    "case_id": "CASE-1",
                    "originated_at": "2025-01-15T00:00:00Z",
                    "kloc": 1.0,
                    "target_path": target.relative_to(root).as_posix(),
                    "target_snapshot_sha256": benchmark_target_snapshot(target)[
                        "target_snapshot_sha256"
                    ],
                    "public_commitment_path": commitment.relative_to(root).as_posix(),
                    "public_commitment_artifact_sha256": sha256_file(commitment),
                    "public_commitment_sha256": commitment_record[
                        "public_commitment_sha256"
                    ],
                    "sealed_ground_truth_path": sealed.relative_to(root).as_posix(),
                    "sealed_ground_truth_sha256": sha256_file(sealed),
                }
            ],
        }
        path = root / "case-pack.json"
        path.write_text(json.dumps(pack))
        return path

    def test_case_pack_verifies_hashes_independence_and_target_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_pack(Path(directory))
            report = verify_case_pack(path)
            self.assertTrue(report["valid"])
            self.assertEqual(report["schema_version"], "1.2.0")
            self.assertEqual(report["cases"][0]["kloc"], 1.0)
            self.assertTrue(report["independent"])
            self.assertEqual(report["case_ids"], ["CASE-1"])
            self.assertEqual(report["case_pack_sha256"], sha256_file(path))

    def test_case_pack_hash_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.write_pack(root)
            (root / "cases" / "CASE-1" / "commitment.json").write_text("changed")
            with self.assertRaisesRegex(ValueError, "commitment artifact hash mismatch"):
                verify_case_pack(path)

    def test_case_pack_requires_a_committed_kloc_denominator(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.write_pack(root)
            pack = json.loads(path.read_text())
            del pack["cases"][0]["kloc"]
            path.write_text(json.dumps(pack))
            with self.assertRaisesRegex(ValueError, "kloc"):
                verify_case_pack(path)

    def test_case_pack_commitment_value_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.write_pack(root)
            pack = json.loads(path.read_text())
            pack["cases"][0]["public_commitment_sha256"] = "0" * 64
            path.write_text(json.dumps(pack))
            with self.assertRaisesRegex(ValueError, "commitment value mismatch"):
                verify_case_pack(path)

    def test_case_pack_symlink_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.write_pack(root)
            commitment = root / "cases" / "CASE-1" / "commitment.json"
            destination = root / "real-commitment.json"
            destination.write_text(commitment.read_text())
            commitment.unlink()
            commitment.symlink_to(destination)
            with self.assertRaisesRegex(ValueError, "must not contain symlinks"):
                verify_case_pack(path)

    def test_case_pack_path_traversal_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.write_pack(root)
            pack = json.loads(path.read_text())
            pack["author_attestation"]["artifact_path"] = "../outside.json"
            path.write_text(json.dumps(pack))
            with self.assertRaisesRegex(ValueError, "must stay inside"):
                verify_case_pack(path)

    def test_case_pack_rejects_plaintext_ground_truth(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.write_pack(root)
            sealed = root / "cases" / "CASE-1" / "ground-truth.age"
            sealed.write_text("plaintext ground truth")
            pack = json.loads(path.read_text())
            pack["cases"][0]["sealed_ground_truth_sha256"] = sha256_file(sealed)
            path.write_text(json.dumps(pack))
            with self.assertRaisesRegex(ValueError, "declared age envelope"):
                verify_case_pack(path)

    def test_verify_pack_cli_writes_a_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.write_pack(root)
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = main(["benchmark", "verify-pack", str(path)])
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertIn("verified independent case pack", stdout.getvalue())
            report_path = root / "benchmark-case-pack-report.json"
            self.assertTrue(report_path.is_file())
            self.assertTrue(json.loads(report_path.read_text())["valid"])

    def test_hash_target_cli_uses_the_pack_snapshot_algorithm(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            (target / "Fixture.sol").write_text("contract Fixture {}\n")
            expected = benchmark_target_snapshot(target)
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                result = main(["benchmark", "hash-target", str(target)])
            self.assertEqual(result, 0)
            self.assertEqual(stdout.getvalue().strip(), expected["target_snapshot_sha256"])

    def test_commit_ground_truth_cli_writes_the_public_commitment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reveal = root / "CASE-1-ground-truth.json"
            reveal.write_text(
                json.dumps(
                    canonical_ground_truth_document(
                        "CASE-1",
                        False,
                        [],
                    )
                )
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = main(
                    ["benchmark", "commit-ground-truth", str(reveal)]
                )
            self.assertEqual(result, 0, stderr.getvalue())
            commitment_path = root / "CASE-1-ground-truth.commitment.json"
            commitment = json.loads(commitment_path.read_text())
            self.assertIn(
                f"public commitment: {commitment['public_commitment_sha256']}",
                stdout.getvalue().splitlines(),
            )
            self.assertIn(
                f"commitment artifact: {sha256_file(commitment_path)}",
                stdout.getvalue().splitlines(),
            )

    def test_unrecognized_custody_model_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.write_pack(root)
            pack = json.loads(path.read_text())
            pack["author_attestation"]["custody_model"] = "free-text"
            path.write_text(json.dumps(pack))
            with self.assertRaisesRegex(ValueError, "custody_model"):
                verify_case_pack(path)

    def test_self_authored_case_pack_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.write_pack(root)
            pack = json.loads(path.read_text())
            pack["author_attestation"]["independent_from_trial_operator"] = False
            path.write_text(json.dumps(pack))
            with self.assertRaisesRegex(ValueError, "independent_from_trial_operator"):
                verify_case_pack(path)


if __name__ == "__main__":
    unittest.main()
