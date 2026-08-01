from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .ledger import EvidenceLedger
from .models import EVIDENCE_RANK, EvidenceLevel, EvidenceRecord, Finding, Hypothesis
from .util import sha256_file


class HypothesisBoard:
    """Typed operations backed by the append-only evidence ledger."""

    def __init__(self, run_directory: Path):
        self.run_directory = run_directory.resolve(strict=True)
        self.ledger = EvidenceLedger(self.run_directory / "evidence.jsonl")
        self.ledger.verify()

    def import_hypothesis(self, path: Path) -> Hypothesis:
        value = self._read_json(path)
        hypothesis = Hypothesis.from_dict(value)
        if hypothesis.hypothesis_id in self._ids_for_event("hypothesis_proposed", "hypothesis_id"):
            raise ValueError(f"hypothesis already exists: {hypothesis.hypothesis_id}")
        self.ledger.append(
            {
                "event": "hypothesis_proposed",
                "hypothesis": hypothesis.to_dict(),
                "import": self._provenance(path),
            }
        )
        self._refresh_report()
        return hypothesis

    def import_evidence(self, path: Path) -> EvidenceRecord:
        value = self._read_json(path)
        evidence = EvidenceRecord.from_dict(value)
        if evidence.hypothesis_id is not None:
            known_hypotheses = self._ids_for_event("hypothesis_proposed", "hypothesis_id")
            if evidence.hypothesis_id not in known_hypotheses:
                raise ValueError(f"unknown hypothesis: {evidence.hypothesis_id}")
        if evidence.artifact_path is not None:
            artifact = Path(evidence.artifact_path).resolve(strict=True)
            if sha256_file(artifact) != evidence.artifact_sha256:
                raise ValueError("evidence artifact hash does not match the recorded digest")
        if evidence.evidence_id in self._ids_for_event("evidence_recorded", "evidence_id"):
            raise ValueError(f"evidence already exists: {evidence.evidence_id}")
        self.ledger.append(
            {
                "event": "evidence_recorded",
                "evidence": evidence.to_dict(),
                "import": self._provenance(path),
            }
        )
        self._refresh_report()
        return evidence

    def confirm_finding(self, path: Path) -> Finding:
        value = self._read_json(path)
        finding = Finding.from_dict(value)
        known_hypotheses = self._ids_for_event("hypothesis_proposed", "hypothesis_id")
        if finding.hypothesis_id not in known_hypotheses:
            raise ValueError(f"unknown hypothesis: {finding.hypothesis_id}")
        supporting_levels = [
            record["payload"]["evidence"]["level"]
            for record in self.ledger.records()
            if record["payload"].get("event") == "evidence_recorded"
            and record["payload"]["evidence"].get("hypothesis_id") == finding.hypothesis_id
        ]
        if not supporting_levels:
            raise ValueError("finding has no recorded evidence")
        if max(EVIDENCE_RANK[EvidenceLevel(level)] for level in supporting_levels) < EVIDENCE_RANK[
            finding.evidence_level
        ]:
            raise ValueError("finding evidence level exceeds its recorded supporting evidence")
        if finding.finding_id in self._ids_for_event("finding_confirmed", "finding_id"):
            raise ValueError(f"finding already exists: {finding.finding_id}")
        self.ledger.append(
            {
                "event": "finding_confirmed",
                "finding": finding.to_dict(),
                "import": self._provenance(path),
            }
        )
        self._refresh_report()
        return finding

    def list_hypotheses(self) -> list[dict[str, Any]]:
        return [
            record["payload"]["hypothesis"]
            for record in self.ledger.records()
            if record["payload"].get("event") == "hypothesis_proposed"
        ]

    def _ids_for_event(self, event: str, key: str) -> set[str]:
        container = {
            "hypothesis_proposed": "hypothesis",
            "evidence_recorded": "evidence",
            "finding_confirmed": "finding",
        }[event]
        return {
            str(record["payload"][container][key])
            for record in self.ledger.records()
            if record["payload"].get("event") == event
        }

    @staticmethod
    def _read_json(path: Path) -> dict[str, Any]:
        resolved = path.resolve(strict=True)
        if resolved.stat().st_size > 1_000_000:
            raise ValueError("import JSON exceeds the 1 MB safety limit")
        value = json.loads(resolved.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("import file must contain one JSON object")
        return value

    @staticmethod
    def _provenance(path: Path) -> dict[str, str]:
        resolved = path.resolve(strict=True)
        return {"path": str(resolved), "sha256": sha256_file(resolved)}

    def _refresh_report(self) -> None:
        from .workflow import refresh_report

        refresh_report(self.run_directory)
