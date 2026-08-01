from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .intake import MAX_SCOPE_BYTES, RepositoryIntake, ScopeManifest, validate_scope_against_ledger
from .ledger import EvidenceLedger
from .models import EVIDENCE_RANK, EvidenceLevel, EvidenceRecord, Finding, Hypothesis
from .policy import CommandRunner, ExecutionMode
from .util import atomic_write_json, sha256_file
from .verification import (
    ExecutionRequest,
    ReplayMode,
    evaluate_assertions,
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
            evidence.artifact_path = str(artifact)
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
        hypothesis = self._hypothesis_by_id(request.hypothesis_id)
        self._validate_request_claim(request, hypothesis)
        self._require_new_evidence_id(request.evidence_id)
        if (
            runner.mode is ExecutionMode.HOST
            and request.evidence_level is EvidenceLevel.EXECUTABLE
        ):
            raise ValueError(
                "host execution cannot mint executable evidence; use a digest-pinned Docker policy"
            )
        scope = self._load_scope()
        target_root = Path(scope.target_root).resolve(strict=True)
        self._require_target_snapshot(scope, target_root)
        cwd = resolve_execution_cwd(target_root, request.cwd)
        result = runner.run(request.command, cwd, request.stdin.encode("utf-8"))
        assertion_results = evaluate_assertions(request, result)
        target_unchanged = self._target_snapshot_matches(scope, target_root)
        receipt = execution_receipt(
            request,
            runner,
            result,
            assertion_results,
            target_root,
            scope.target_snapshot_sha256,
        )
        if (
            not result_is_accepted(
                result, request.expected_return_codes, assertion_results
            )
            or not target_unchanged
        ):
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
                assertion_results,
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
            level=request.evidence_level,
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
                "adapter": request.adapter,
                "claim": request.claim,
                "replay_mode": request.replay_mode.value,
                "expected_return_codes": list(request.expected_return_codes),
                "assertions": assertion_results,
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
        if EVIDENCE_RANK[evidence.level] < EVIDENCE_RANK[EvidenceLevel.STRUCTURALLY_CONFIRMED]:
            raise ValueError("only runner-minted structural and stronger evidence can be replay-verified")
        if evidence.metadata.get("runner_minted") is not True:
            raise ValueError("evidence was not minted by the Nirvana runner")
        if evidence.artifact_path is None or evidence.artifact_sha256 is None:
            raise ValueError("runner-minted evidence lacks its execution receipt")
        artifact = Path(evidence.artifact_path).resolve(strict=True)
        if sha256_file(artifact) != evidence.artifact_sha256:
            raise ValueError("execution receipt hash does not match the ledger")
        receipt = load_receipt(artifact)
        request = request_from_receipt(receipt)
        if request.evidence_id != evidence.evidence_id or request.command != evidence.command:
            raise ValueError("execution receipt does not match the evidence record")
        if request.evidence_level is not evidence.level:
            raise ValueError("execution receipt has the wrong evidence level")
        hypothesis = self._hypothesis_by_id(request.hypothesis_id)
        self._validate_request_claim(request, hypothesis)
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
        assertion_results = evaluate_assertions(request, result)
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
            assertion_results,
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
        signature_matches = (
            request.replay_mode is ReplayMode.ASSERTIONS
            or current_signature == original_signature
        )
        verified = (
            result_is_accepted(
                result, request.expected_return_codes, assertion_results
            )
            and target_unchanged
            and signature_matches
        )
        event = {
            "event": "evidence_verified" if verified else "evidence_replay_failed",
            "evidence_id": evidence.evidence_id,
            "original_artifact_sha256": evidence.artifact_sha256,
            "replay_artifact_path": str(replay_artifact),
            "replay_artifact_sha256": replay_digest,
            "result": current_signature,
            "assertions": assertion_results,
            "replay_mode": request.replay_mode.value,
        }
        payloads = [event]
        next_ceiling: EvidenceLevel | None = None
        ceiling_basis: str | list[str] = evidence.evidence_id
        if verified and evidence.level is EvidenceLevel.EXECUTABLE:
            next_ceiling = EvidenceLevel.EXECUTABLE
        elif verified and evidence.level is EvidenceLevel.STRUCTURALLY_CONFIRMED:
            corroboration = self._structural_corroboration_basis(
                evidence.hypothesis_id or "", evidence.evidence_id
            )
            if corroboration:
                next_ceiling = EvidenceLevel.STRUCTURALLY_CONFIRMED
                ceiling_basis = corroboration
                payloads.append(
                    {
                        "event": "structural_corroboration_verified",
                        "hypothesis_id": evidence.hypothesis_id,
                        "evidence_ids": corroboration,
                        "mode": "replay-corroboration",
                    }
                )
        if (
            next_ceiling is not None
            and EVIDENCE_RANK[scope.evidence_ceiling] < EVIDENCE_RANK[next_ceiling]
        ):
            previous = scope.evidence_ceiling
            scope.evidence_ceiling = next_ceiling
            payloads.append(
                {
                    "event": "evidence_ceiling_raised",
                    "previous": previous.value,
                    "current": scope.evidence_ceiling.value,
                    "basis": ceiling_basis,
                }
            )
        self.ledger.append_many(payloads)
        # The ledger is authoritative. Persist its new projection only after the
        # durable append; a stale lower manifest can be repaired on the next load.
        if next_ceiling is not None:
            atomic_write_json(self.run_directory / "scope.json", scope)
        self._refresh_report()
        if not verified:
            raise ValueError("replay did not satisfy the recorded verification contract")
        return evidence

    def corroborate_evidence(
        self, hypothesis_id: str, evidence_ids: list[str]
    ) -> list[EvidenceRecord]:
        hypothesis = self._hypothesis_by_id(hypothesis_id)
        if len(evidence_ids) < 2 or len(set(evidence_ids)) != len(evidence_ids):
            raise ValueError("structural corroboration requires at least two unique evidence ids")
        evidence = [self._evidence_by_id(item) for item in evidence_ids]
        scope = self._load_scope()
        expected_claim = {
            "security_property": hypothesis.security_property,
            "suspected_violation": hypothesis.suspected_violation,
        }
        allowed_adapters = {"solc-ast", "slither", "semgrep"}
        adapters: set[str] = set()
        for item in evidence:
            if item.hypothesis_id != hypothesis_id:
                raise ValueError("structural evidence belongs to a different hypothesis")
            if item.level is not EvidenceLevel.STRUCTURALLY_CONFIRMED:
                raise ValueError("corroboration accepts structural evidence only")
            adapter = str(item.metadata.get("adapter", ""))
            if adapter not in allowed_adapters:
                raise ValueError(f"unsupported structural analyzer provenance: {adapter!r}")
            if item.source != f"deterministic:{adapter}":
                raise ValueError("structural evidence source does not match its analyzer")
            if not item.tool_version:
                raise ValueError("structural evidence requires an analyzer version")
            if item.metadata.get("target_snapshot_sha256") != scope.target_snapshot_sha256:
                raise ValueError("structural evidence targets a different repository snapshot")
            if item.metadata.get("claim") != expected_claim:
                raise ValueError("structural evidence proves a different claim")
            if item.artifact_path is None or item.artifact_sha256 is None:
                raise ValueError("structural evidence lacks its hashed analyzer artifact")
            artifact = Path(item.artifact_path).resolve(strict=True)
            if sha256_file(artifact) != item.artifact_sha256:
                raise ValueError("structural analyzer artifact hash does not match")
            adapters.add(adapter)
        if len(adapters) < 2:
            raise ValueError("structural corroboration requires independent analyzer adapters")

        ids = sorted(evidence_ids)
        payloads: list[dict[str, Any]] = [
            {
                "event": "structural_corroboration_verified",
                "hypothesis_id": hypothesis_id,
                "evidence_ids": ids,
                "adapters": sorted(adapters),
                "mode": "artifact-corroboration",
            }
        ]
        if EVIDENCE_RANK[scope.evidence_ceiling] < EVIDENCE_RANK[
            EvidenceLevel.STRUCTURALLY_CONFIRMED
        ]:
            previous = scope.evidence_ceiling
            scope.evidence_ceiling = EvidenceLevel.STRUCTURALLY_CONFIRMED
            payloads.append(
                {
                    "event": "evidence_ceiling_raised",
                    "previous": previous.value,
                    "current": scope.evidence_ceiling.value,
                    "basis": ids,
                }
            )
        self.ledger.append_many(payloads)
        atomic_write_json(self.run_directory / "scope.json", scope)
        self._refresh_report()
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
        hypothesis = self._hypothesis_by_id(finding.hypothesis_id)
        if finding.security_property != hypothesis.security_property:
            raise ValueError("finding security property does not match its hypothesis")
        verified_evidence = self._currently_verified_evidence_ids()
        corroborated_evidence = {
            str(evidence_id)
            for record in self.ledger.records()
            if record["payload"].get("event") == "structural_corroboration_verified"
            and record["payload"].get("mode") == "artifact-corroboration"
            for evidence_id in record["payload"].get("evidence_ids", [])
        }
        accepted_evidence = verified_evidence | corroborated_evidence
        if not set(finding.supporting_evidence) <= accepted_evidence:
            missing = sorted(set(finding.supporting_evidence) - accepted_evidence)
            raise ValueError(
                "every supporting evidence id must be replay-verified or structurally corroborated: "
                f"{missing}"
            )
        evidence_by_id = {
            record["payload"]["evidence"]["evidence_id"]: EvidenceRecord.from_dict(
                record["payload"]["evidence"]
            )
            for record in self.ledger.records()
            if record["payload"].get("event") == "evidence_recorded"
        }
        unknown = sorted(set(finding.supporting_evidence) - evidence_by_id.keys())
        if unknown:
            raise ValueError(f"finding references unknown evidence: {unknown}")
        supporting = [evidence_by_id[item] for item in finding.supporting_evidence]
        for item in supporting:
            if item.artifact_path is None or item.artifact_sha256 is None:
                raise ValueError("finding supporting evidence lacks a hashed artifact")
            artifact = Path(item.artifact_path).resolve(strict=True)
            if sha256_file(artifact) != item.artifact_sha256:
                raise ValueError("finding supporting evidence artifact hash does not match")
        if any(item.hypothesis_id != finding.hypothesis_id for item in supporting):
            raise ValueError("finding supporting evidence belongs to a different hypothesis")
        if any(
            item.metadata.get("claim")
            != {
                "security_property": hypothesis.security_property,
                "suspected_violation": hypothesis.suspected_violation,
            }
            for item in supporting
        ):
            raise ValueError("finding supporting evidence proves a different claim")
        if max(EVIDENCE_RANK[item.level] for item in supporting) < EVIDENCE_RANK[
            finding.evidence_level
        ]:
            raise ValueError("finding evidence level exceeds its recorded supporting evidence")
        if finding.evidence_level is EvidenceLevel.STRUCTURALLY_CONFIRMED:
            adapters = {str(item.metadata.get("adapter")) for item in supporting}
            if len(adapters) < 2:
                raise ValueError("structural findings require two independent verified adapters")
        if finding.reproducer_evidence_id is not None:
            reproducer = evidence_by_id[finding.reproducer_evidence_id]
            if EVIDENCE_RANK[reproducer.level] < EVIDENCE_RANK[EvidenceLevel.EXECUTABLE]:
                raise ValueError("finding reproducer evidence is not executable")
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

    def _hypothesis_by_id(self, hypothesis_id: str) -> Hypothesis:
        matches = [
            Hypothesis.from_dict(record["payload"]["hypothesis"])
            for record in self.ledger.records()
            if record["payload"].get("event") == "hypothesis_proposed"
            and record["payload"]["hypothesis"].get("hypothesis_id") == hypothesis_id
        ]
        if not matches:
            raise ValueError(f"unknown hypothesis: {hypothesis_id}")
        if len(matches) != 1:
            raise ValueError(f"duplicate hypotheses exist: {hypothesis_id}")
        return matches[0]

    @staticmethod
    def _validate_request_claim(request: ExecutionRequest, hypothesis: Hypothesis) -> None:
        if (
            request.claim.security_property != hypothesis.security_property
            or request.claim.suspected_violation != hypothesis.suspected_violation
        ):
            raise ValueError("execution claim does not match its hypothesis")

    def _structural_corroboration_basis(
        self, hypothesis_id: str, current_evidence_id: str
    ) -> list[str]:
        verified = self._currently_verified_evidence_ids()
        verified.add(current_evidence_id)
        by_adapter: dict[str, str] = {}
        for record in self.ledger.records():
            payload = record["payload"]
            if payload.get("event") != "evidence_recorded":
                continue
            evidence = EvidenceRecord.from_dict(payload["evidence"])
            if (
                evidence.evidence_id not in verified
                or evidence.hypothesis_id != hypothesis_id
                or evidence.level is not EvidenceLevel.STRUCTURALLY_CONFIRMED
                or evidence.metadata.get("runner_minted") is not True
            ):
                continue
            adapter = str(evidence.metadata.get("adapter", ""))
            if adapter:
                by_adapter.setdefault(adapter, evidence.evidence_id)
        if len(by_adapter) < 2:
            return []
        return sorted(by_adapter.values())

    def _currently_verified_evidence_ids(self) -> set[str]:
        latest: dict[str, str] = {}
        for record in self.ledger.records():
            payload = record["payload"]
            event = payload.get("event")
            if event in {"evidence_verified", "evidence_replay_failed"}:
                latest[str(payload["evidence_id"])] = str(event)
        return {
            evidence_id
            for evidence_id, event in latest.items()
            if event == "evidence_verified"
        }

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
        value = self._read_json(
            self.run_directory / "scope.json",
            max_bytes=MAX_SCOPE_BYTES,
            description="scope manifest",
        )
        scope = ScopeManifest.from_dict(value)
        recorded_ceiling = scope.evidence_ceiling
        validated = validate_scope_against_ledger(scope, self.ledger.records())
        if validated.evidence_ceiling is not recorded_ceiling:
            atomic_write_json(self.run_directory / "scope.json", validated)
        return validated

    @staticmethod
    def _target_snapshot_matches(scope: ScopeManifest, target_root: Path) -> bool:
        current = RepositoryIntake(
            max_file_bytes=scope.max_analysis_file_bytes,
            ignored_directories=set(scope.excluded_directories),
        ).inspect(target_root)
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
        assertion_results: list[dict[str, Any]],
    ) -> str:
        if blocked_reason is not None:
            return f"execution was blocked: {blocked_reason}"
        if timed_out:
            return "execution timed out"
        if not target_unchanged:
            return "execution changed the audited target snapshot"
        if return_code not in expected_return_codes:
            return (
                f"execution returned {return_code}; expected exactly "
                f"{expected_return_codes[0]}"
            )
        failed = [
            str(item.get("assertion_id"))
            for item in assertion_results
            if item.get("passed") is not True
        ]
        if failed:
            return f"execution assertions failed: {', '.join(failed)}"
        return (
            "execution did not satisfy the verification contract"
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
    def _read_json(
        path: Path,
        max_bytes: int = 1_000_000,
        description: str = "import JSON",
    ) -> dict[str, Any]:
        resolved = path.resolve(strict=True)
        if resolved.stat().st_size > max_bytes:
            raise ValueError(
                f"{description} exceeds its {max_bytes // (1024 * 1024)} MB safety limit"
            )
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
