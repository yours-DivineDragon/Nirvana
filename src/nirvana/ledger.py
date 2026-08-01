from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .util import canonical_json, sha256_bytes, utc_now
from .contracts import validate_contract
from .util import atomic_write_json

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None  # type: ignore[assignment]


GENESIS_HASH = "0" * 64


class LedgerIntegrityError(ValueError):
    pass


class EvidenceLedger:
    """Append-only JSONL ledger whose records form a SHA-256 hash chain."""

    def __init__(self, path: Path):
        self.path = path

    @contextmanager
    def _locked_stream(self) -> Iterator[Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a+", encoding="utf-8", newline="\n") as stream:
            if fcntl is not None:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                yield stream
            finally:
                if fcntl is not None:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def append(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.append_many([payload])[0]

    def append_many(self, payloads: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not payloads:
            return []
        with self._locked_stream() as stream:
            stream.seek(0)
            records = [json.loads(line) for line in stream if line.strip()]
            if records:
                self._verify_records(records)
                previous_hash = records[-1]["record_hash"]
                sequence = records[-1]["sequence"] + 1
            else:
                previous_hash = GENESIS_HASH
                sequence = 1
            appended: list[dict[str, Any]] = []
            stream.seek(0, os.SEEK_END)
            for payload in payloads:
                envelope = {
                    "sequence": sequence,
                    "timestamp": utc_now(),
                    "previous_hash": previous_hash,
                    "payload": payload,
                }
                envelope["record_hash"] = sha256_bytes(canonical_json(envelope).encode("utf-8"))
                stream.write(canonical_json(envelope) + "\n")
                appended.append(envelope)
                previous_hash = envelope["record_hash"]
                sequence += 1
            stream.flush()
            os.fsync(stream.fileno())
            return appended

    def records(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as stream:
            return [json.loads(line) for line in stream if line.strip()]

    def verify(self) -> int:
        records = self.records()
        self._verify_records(records)
        return len(records)

    def export_checkpoint(self, output: Path) -> dict[str, Any]:
        records = self.records()
        self._verify_records(records)
        if not records:
            raise ValueError("cannot checkpoint an empty evidence ledger")
        prefix = "".join(canonical_json(record) + "\n" for record in records).encode("utf-8")
        checkpoint = {
            "schema_version": "1.0.0",
            "created_at": utc_now(),
            "ledger_path": str(self.path.resolve(strict=True)),
            "sequence": records[-1]["sequence"],
            "record_hash": records[-1]["record_hash"],
            "prefix_sha256": sha256_bytes(prefix),
            "external_anchor": None,
        }
        validate_contract(checkpoint, "ledger-checkpoint.schema.json")
        atomic_write_json(output.resolve(), checkpoint)
        return checkpoint

    def verify_checkpoint(self, checkpoint_path: Path) -> int:
        value = json.loads(checkpoint_path.resolve(strict=True).read_text(encoding="utf-8"))
        validate_contract(value, "ledger-checkpoint.schema.json")
        records = self.records()
        self._verify_records(records)
        sequence = int(value["sequence"])
        if len(records) < sequence:
            raise LedgerIntegrityError("ledger is shorter than its checkpoint")
        anchored = records[:sequence]
        if anchored[-1]["record_hash"] != value["record_hash"]:
            raise LedgerIntegrityError("checkpoint record hash does not match the ledger")
        prefix = "".join(canonical_json(record) + "\n" for record in anchored).encode("utf-8")
        if sha256_bytes(prefix) != value["prefix_sha256"]:
            raise LedgerIntegrityError("checkpoint prefix hash does not match the ledger")
        return sequence

    @staticmethod
    def _verify_records(records: list[dict[str, Any]]) -> None:
        previous_hash = GENESIS_HASH
        for expected_sequence, record in enumerate(records, start=1):
            required = {"sequence", "timestamp", "previous_hash", "payload", "record_hash"}
            missing = required - record.keys()
            if missing:
                raise LedgerIntegrityError(f"record {expected_sequence} lacks {sorted(missing)}")
            if record["sequence"] != expected_sequence:
                raise LedgerIntegrityError(f"record {expected_sequence} has an invalid sequence")
            if record["previous_hash"] != previous_hash:
                raise LedgerIntegrityError(f"record {expected_sequence} breaks the hash chain")
            unsigned = {key: value for key, value in record.items() if key != "record_hash"}
            calculated_hash = sha256_bytes(canonical_json(unsigned).encode("utf-8"))
            if record["record_hash"] != calculated_hash:
                raise LedgerIntegrityError(f"record {expected_sequence} was modified")
            previous_hash = record["record_hash"]
