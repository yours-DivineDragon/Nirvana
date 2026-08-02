import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from nirvana.benchmark_pack import verify_case_pack
from nirvana.cli import main
from nirvana.util import sha256_file
from nirvana.verification import snapshot_harness


class BenchmarkCasePackTests(unittest.TestCase):
    def write_pack(self, root: Path) -> Path:
        attestation = root / "independent-author-attestation.json"
        attestation.write_text(
            json.dumps({"author": "independent-team", "operator_access": False})
        )
        target = root / "cases" / "CASE-1" / "target"
        target.mkdir(parents=True)
        (target / "Fixture.sol").write_text("contract Fixture {}\n")
        commitment = target.parent / "commitment.json"
        commitment.write_text(json.dumps({"case_id": "CASE-1"}))
        sealed = target.parent / "ground-truth.age"
        sealed.write_text("age-encryption.org/v1\nfixture-ciphertext\n")
        pack = {
            "schema_version": "1.0.0",
            "pack_id": "independent-pack-1",
            "cutoff": "2024-12-31T00:00:00Z",
            "created_at": "2025-01-20T00:00:00Z",
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
                    "target_path": target.relative_to(root).as_posix(),
                    "target_snapshot_sha256": snapshot_harness(target).snapshot_sha256,
                    "public_commitment_path": commitment.relative_to(root).as_posix(),
                    "public_commitment_sha256": sha256_file(commitment),
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
            self.assertTrue(report["independent"])
            self.assertEqual(report["case_ids"], ["CASE-1"])
            self.assertEqual(report["case_pack_sha256"], sha256_file(path))

    def test_case_pack_hash_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.write_pack(root)
            (root / "cases" / "CASE-1" / "commitment.json").write_text("changed")
            with self.assertRaisesRegex(ValueError, "commitment hash mismatch"):
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


if __name__ == "__main__":
    unittest.main()
