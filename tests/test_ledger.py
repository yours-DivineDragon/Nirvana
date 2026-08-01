import json
import tempfile
import unittest
from pathlib import Path

from nirvana.ledger import EvidenceLedger, LedgerIntegrityError


class EvidenceLedgerTests(unittest.TestCase):
    def test_append_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.jsonl"
            ledger = EvidenceLedger(path)
            ledger.append({"event": "one"})
            ledger.append({"event": "two"})
            self.assertEqual(ledger.verify(), 2)

    def test_tampering_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.jsonl"
            ledger = EvidenceLedger(path)
            ledger.append({"event": "one"})
            record = json.loads(path.read_text())
            record["payload"]["event"] = "rewritten"
            path.write_text(json.dumps(record) + "\n")
            with self.assertRaises(LedgerIntegrityError):
                ledger.verify()

    def test_checkpoint_remains_valid_after_later_appends(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.jsonl"
            checkpoint = Path(directory) / "checkpoint.json"
            ledger = EvidenceLedger(path)
            ledger.append({"event": "one"})
            exported = ledger.export_checkpoint(checkpoint)
            ledger.append({"event": "two"})
            self.assertEqual(exported["sequence"], 1)
            self.assertEqual(ledger.verify_checkpoint(checkpoint), 1)


if __name__ == "__main__":
    unittest.main()
