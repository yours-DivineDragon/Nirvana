from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .intake import RepositoryIntake, ScopeManifest, validate_scope_against_ledger
from .ledger import EvidenceLedger
from .models import EVIDENCE_RANK, EvidenceLevel, EvidenceRecord, Finding, Hypothesis
from .policy import CommandRunner, ExecutionMode
from .util import atomic_write_json, sha256_file
from .verification import (
    ExecutionRequest,
    execution_receipt,
    load_receipt,
    policy_sha256,
    request_from_receipt,
    resolve_execution_cwd,
    result_is_accepted,
    result_signature,
)


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
        if EVIDENCE_RANK[evidence.level] >= EVIDENCE_RANK[EvidenceLevel.EXECUTABLE]:
            raise ValueError(
                "executable and stronger evidence must be minted by nirvana evidence run"
            )
        if evidence.hypothesis_id is not None:
            self._require_known_hypothesis(evidence.hypothesis_id)
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

    def execute_evidence(self, path: Path, runner: CommandRunner) -> EvidenceRecord:
        request = ExecutionRequest.from_dict(self._read_json(path))
        self._require_known_hypothesis(request.hypothesis_id)
        self._require_new_evidence_id(request.evidence_id)
        if runner.mode is ExecutionMode.HOST:
            raise ValueError(
                "host execution cannot mint executable evidence; use a digest-pinned Docker policy"
            )
        scope = self._load_scope()
        target_root = Path(scope.target_root).resolve(strict=True)
        self._require_target_snapshot(scope, target_root)
        cwd = resolve_execution_cwd(target_root, request.cwd)
        result = runner.run(request.command, cwd, request.stdin.encode("utf-8"))
        target_unchanged = self._target_snapshot_matches(scope, target_root)
        receipt = execution_receipt(
            request,
            runner,
            result,
            target_root,
            scope.target_snapshot_sha256,
        )
        if not result_is_accepted(result, request.expected_return_codes) or not target_unchanged:
            attempt = 1 + sum(
                record["payload"].get("event") == "execution_rejected"
                and record["payload"].get("evidence_id") == request.evidence_id
                for record in self.ledger.records()
            )
            artifact, digest = self._write_receipt(
                request.evidence_id, f"rejected-{attempt}.json", receipt
            )
            reason = self._execution_rejection_reason(
                result.blocked_reason,
                result.timed_out,
                result.return_code,
                request.expected_return_codes,
                target_unchanged,
            )
            self.ledger.append(
                {
                    "event": "execution_rejected",
                    "evidence_id": request.evidence_id,
                    "reason": reason,
                    "artifact_path": str(artifact),
                    "artifact_sha256": digest,
                    "request_import": self._provenance(path),
                }
            )
            self._refresh_report()
            raise ValueError(reason)

        artifact, digest = self._write_receipt(request.evidence_id, "execution.json", receipt)
        signature = result_signature(result)
        evidence = EvidenceRecord(
            evidence_id=request.evidence_id,
            hypothesis_id=request.hypothesis_id,
            level=EvidenceLevel.EXECUTABLE,
            kind=request.kind,
            summary=request.summary,
            source="nirvana:command-runner",
            artifact_path=str(artifact),
            artifact_sha256=digest,
            command=list(request.command),
            tool_version=request.tool_version,
            assumptions=list(request.assumptions),
            metadata={
                "runner_minted": True,
                "execution_mode": runner.mode.value,
                "policy_sha256": policy_sha256(runner),
                "target_snapshot_sha256": scope.target_snapshot_sha256,
                "cwd": request.cwd,
                "expected_return_codes": list(request.expected_return_codes),
                **signature,
            },
        )
        self.ledger.append(
            {
                "event": "evidence_recorded",
                "evidence": evidence.to_dict(),
                "minted_by": "nirvana:command-runner",
                "request_import": self._provenance(path),
            }
        )
        self._refresh_report()
        return evidence

    def verify_evidence(self, evidence_id: str, runner: CommandRunner) -> EvidenceRecord:
        evidence = self._evidence_by_id(evidence_id)
        if EVIDENCE_RANK[evidence.level] < EVIDENCE_RANK[EvidenceLevel.EXECUTABLE]:
            raise ValueError("only executable and stronger evidence can be replay-verified")
        if evidence.metadata.get("runner_minted") is not True:
            raise ValueError("executable evidence was not minted by the Nirvana runner")
        if evidence.artifact_path is None or evidence.artifact_sha256 is None:
            raise ValueError("runner-minted evidence lacks its execution receipt")
        artifact = Path(evidence.artifact_path).resolve(strict=True)
        if sha256_file(artifact) != evidence.artifact_sha256:
            raise ValueError("execution receipt hash does not match the ledger")
        receipt = load_receipt(artifact)
        request = request_from_receipt(receipt)
        if request.evidence_id != evidence.evidence_id or request.command != evidence.command:
            raise ValueError("execution receipt does not match the evidence record")
        if receipt.get("evidence_id") != evidence.evidence_id:
            raise ValueError("execution receipt has the wrong evidence identifier")

        scope = self._load_scope()
        target_root = Path(scope.target_root).resolve(strict=True)
        target = receipt.get("target", {})
        recorded_runner = receipt.get("runner", {})
        if target.get("root") != str(target_root):
            raise ValueError("execution receipt targets a different repository")
        if target.get("snapshot_sha256") != scope.target_snapshot_sha256:
            raise ValueError("execution receipt targets a different repository snapshot")
        if recorded_runner.get("mode") != runner.mode.value:
            raise ValueError("replay execution mode differs from the original execution")
        if recorded_runner.get("policy_sha256") != policy_sha256(runner):
            raise ValueError("replay policy differs from the original execution")
        self._require_target_snapshot(scope, target_root)

        cwd = resolve_execution_cwd(target_root, request.cwd)
        result = runner.run(request.command, cwd, request.stdin.encode("utf-8"))
        target_unchanged = self._target_snapshot_matches(scope, target_root)
        replay_number = 1 + sum(
            record["payload"].get("event") in {"evidence_verified", "evidence_replay_failed"}
            and record["payload"].get("evidence_id") == evidence.evidence_id
            for record in self.ledger.records()
        )
        replay = execution_receipt(
            request,
            runner,
            result,
            target_root,
            scope.target_snapshot_sha256,
            replay_of=evidence.artifact_sha256,
        )
        replay_artifact, replay_digest = self._write_receipt(
            evidence.evidence_id, f"replay-{replay_number}.json", replay
        )
        original_signature = {
            key: receipt.get("result", {}).get(key)
            for key in result_signature(result)
        }
        current_signature = result_signature(result)
        verified = (
            result_is_accepted(result, request.expected_return_codes)
            and target_unchanged
            and current_signature == original_signature
        )
        event = {
            "event": "evidence_verified" if verified else "evidence_replay_failed",
            "evidence_id": evidence.evidence_id,
            "original_artifact_sha256": evidence.artifact_sha256,
            "replay_artifact_path": str(replay_artifact),
            "replay_artifact_sha256": replay_digest,
            "result": current_signature,
        }
        payloads = [event]
        if verified and EVIDENCE_RANK[scope.evidence_ceiling] < EVIDENCE_RANK[EvidenceLevel.EXECUTABLE]:
            previous = scope.evidence_ceiling
            scope.evidence_ceiling = EvidenceLevel.EXECUTABLE
            atomic_write_json(self.run_directory / "scope.json", scope)
            payloads.append(
                {
                    "event": "evidence_ceiling_raised",
                    "previous": previous.value,
                    "current": scope.evidence_ceiling.value,
                    "basis": evidence.evidence_id,
                }
            )
        self.ledger.append_many(payloads)
        self._refresh_report()
        if not verified:
            raise ValueError("replay result does not match the original executable evidence")
        return evidence

    def confirm_finding(self, path: Path) -> Finding:
        value = self._read_json(path)
        finding = Finding.from_dict(value)
        scope = self._load_scope()
        if EVIDENCE_RANK[finding.evidence_level] > EVIDENCE_RANK[scope.evidence_ceiling]:
            raise ValueError(
                "finding evidence level exceeds the run evidence ceiling "
                f"({scope.evidence_ceiling.value})"
            )
        known_hypotheses = self._ids_for_event("hypothesis_proposed", "hypothesis_id")
        if finding.hypothesis_id not in known_hypotheses:
            raise ValueError(f"unknown hypothesis: {finding.hypothesis_id}")
        verified_evidence = {
            record["payload"]["evidence_id"]
            for record in self.ledger.records()
            if record["payload"].get("event") == "evidence_verified"
        }
        supporting_levels = [
            record["payload"]["evidence"]["level"]
            for record in self.ledger.records()
            if record["payload"].get("event") == "evidence_recorded"
            and record["payload"]["evidence"].get("hypothesis_id") == finding.hypothesis_id
            and (
                EVIDENCE_RANK[EvidenceLevel(record["payload"]["evidence"]["level"])]
                < EVIDENCE_RANK[EvidenceLevel.EXECUTABLE]
                or record["payload"]["evidence"]["evidence_id"] in verified_evidence
            )
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

    def _require_known_hypothesis(self, hypothesis_id: str) -> None:
        known = self._ids_for_event("hypothesis_proposed", "hypothesis_id")
        if hypothesis_id not in known:
            raise ValueError(f"unknown hypothesis: {hypothesis_id}")

    def _require_new_evidence_id(self, evidence_id: str) -> None:
        if evidence_id in self._ids_for_event("evidence_recorded", "evidence_id"):
            raise ValueError(f"evidence already exists: {evidence_id}")

    def _evidence_by_id(self, evidence_id: str) -> EvidenceRecord:
        matches = [
            EvidenceRecord.from_dict(record["payload"]["evidence"])
            for record in self.ledger.records()
            if record["payload"].get("event") == "evidence_recorded"
            and record["payload"]["evidence"].get("evidence_id") == evidence_id
        ]
        if not matches:
            raise ValueError(f"unknown evidence: {evidence_id}")
        if len(matches) != 1:
            raise ValueError(f"duplicate evidence records exist: {evidence_id}")
        return matches[0]

    def _load_scope(self) -> ScopeManifest:
        value = self._read_json(self.run_directory / "scope.json")
        scope = ScopeManifest.from_dict(value)
        return validate_scope_against_ledger(scope, self.ledger.records())

    @staticmethod
    def _target_snapshot_matches(scope: ScopeManifest, target_root: Path) -> bool:
        current = RepositoryIntake().inspect(target_root)
        return current.target_snapshot_sha256 == scope.target_snapshot_sha256

    def _require_target_snapshot(self, scope: ScopeManifest, target_root: Path) -> None:
        if not scope.snapshot_complete:
            raise ValueError(
                "audited target snapshot is incomplete; hash or exclude every scoped file first"
            )
        if not self._target_snapshot_matches(scope, target_root):
            raise ValueError("audited target no longer matches the captured scope snapshot")

    def _write_receipt(
        self, evidence_id: str, filename: str, receipt: dict[str, Any]
    ) -> tuple[Path, str]:
        directory = self.run_directory / "artifacts" / evidence_id
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / filename
        if path.exists():
            raise ValueError(f"execution receipt already exists: {path}")
        atomic_write_json(path, receipt)
        return path.resolve(strict=True), sha256_file(path)

    @staticmethod
    def _execution_rejection_reason(
        blocked_reason: str | None,
        timed_out: bool,
        return_code: int | None,
        expected_return_codes: list[int],
        target_unchanged: bool,
    ) -> str:
        if blocked_reason is not None:
            return f"execution was blocked: {blocked_reason}"
        if timed_out:
            return "execution timed out"
        if not target_unchanged:
            return "execution changed the audited target snapshot"
        return (
            f"execution returned {return_code}; expected one of "
            f"{sorted(expected_return_codes)}"
        )

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
