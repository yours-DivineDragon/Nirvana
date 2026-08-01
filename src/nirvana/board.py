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
    HarnessSnapshot,
    MAX_CONTROL_CHANGED_FILES,
    NegativeControlExecution,
    ReplayMode,
    evaluate_assertions,
    execution_receipt,
    load_receipt,
    negative_control_is_accepted,
    policy_sha256,
    request_from_receipt,
    resolve_execution_cwd,
    result_is_accepted,
    result_signature,
    snapshot_harness,
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
        if EVIDENCE_RANK[evidence.level] >= EVIDENCE_RANK[
            EvidenceLevel.STRUCTURALLY_CONFIRMED
        ]:
            raise ValueError(
                "structural and stronger evidence must be minted by nirvana evidence run"
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
        control = self._prepare_negative_control(
            request, hypothesis, scope, target_root
        )
        harness_root, harness_snapshot = self._prepare_harness(
            request, target_root, control[0] if control is not None else None
        )
        cwd = resolve_execution_cwd(target_root, request.cwd)
        result = self._run_request(runner, request, cwd, harness_root)
        assertion_results = evaluate_assertions(request, result)
        invariant_results = evaluate_assertions(
            request, result, request.control_invariants
        )
        target_unchanged = self._target_snapshot_matches(scope, target_root)
        negative_control: NegativeControlExecution | None = None
        control_accepted = True
        control_unchanged = True
        if control is not None:
            control_root, control_scope, changed_files = control
            control_cwd = resolve_execution_cwd(control_root, request.cwd)
            control_result = self._run_request(
                runner, request, control_cwd, harness_root
            )
            control_assertions = evaluate_assertions(request, control_result)
            control_invariants = evaluate_assertions(
                request, control_result, request.control_invariants
            )
            control_unchanged = self._target_snapshot_matches(
                control_scope, control_root
            )
            control_accepted = negative_control_is_accepted(
                control_result,
                request.negative_control.expected_return_codes,
                control_assertions,
                control_invariants,
            )
            negative_control = NegativeControlExecution(
                target_root=str(control_root),
                snapshot_sha256=control_scope.target_snapshot_sha256,
                changed_files=changed_files,
                expected_return_codes=list(
                    request.negative_control.expected_return_codes
                ),
                result=control_result,
                assertion_results=control_assertions,
                invariant_results=control_invariants,
            )
        harness_unchanged = self._harness_snapshot_matches(
            harness_root, harness_snapshot
        )
        receipt = execution_receipt(
            request,
            runner,
            result,
            assertion_results,
            invariant_results,
            target_root,
            scope.target_snapshot_sha256,
            harness_snapshot=harness_snapshot,
            negative_control=negative_control,
        )
        if (
            not result_is_accepted(
                result,
                request.expected_return_codes,
                assertion_results,
                invariant_results,
            )
            or not target_unchanged
            or not harness_unchanged
            or not control_unchanged
            or not control_accepted
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
                invariant_results,
                harness_unchanged=harness_unchanged,
                control_unchanged=control_unchanged,
                control_accepted=control_accepted,
                control_invariant_results=(
                    negative_control.invariant_results
                    if negative_control is not None
                    else []
                ),
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
                "control_invariants": invariant_results,
                "harness_snapshot_sha256": (
                    harness_snapshot.snapshot_sha256
                    if harness_snapshot is not None
                    else None
                ),
                "negative_control_verified": negative_control is not None,
                "negative_control_snapshot_sha256": (
                    negative_control.snapshot_sha256
                    if negative_control is not None
                    else None
                ),
                "negative_control_changed_files": (
                    [item["path"] for item in negative_control.changed_files]
                    if negative_control is not None
                    else []
                ),
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
        control = self._prepare_negative_control(
            request, hypothesis, scope, target_root
        )
        harness_root, harness_snapshot = self._prepare_harness(
            request, target_root, control[0] if control is not None else None
        )
        expected_harness = (
            harness_snapshot.to_dict() if harness_snapshot is not None else None
        )
        if receipt.get("harness") != expected_harness:
            raise ValueError("execution receipt binds a different auditor harness")
        self._validate_control_receipt_binding(receipt, request, control)

        cwd = resolve_execution_cwd(target_root, request.cwd)
        result = self._run_request(runner, request, cwd, harness_root)
        assertion_results = evaluate_assertions(request, result)
        invariant_results = evaluate_assertions(
            request, result, request.control_invariants
        )
        target_unchanged = self._target_snapshot_matches(scope, target_root)
        negative_control: NegativeControlExecution | None = None
        control_accepted = True
        control_unchanged = True
        if control is not None:
            control_root, control_scope, changed_files = control
            control_cwd = resolve_execution_cwd(control_root, request.cwd)
            control_result = self._run_request(
                runner, request, control_cwd, harness_root
            )
            control_assertions = evaluate_assertions(request, control_result)
            control_invariants = evaluate_assertions(
                request, control_result, request.control_invariants
            )
            control_unchanged = self._target_snapshot_matches(
                control_scope, control_root
            )
            control_accepted = negative_control_is_accepted(
                control_result,
                request.negative_control.expected_return_codes,
                control_assertions,
                control_invariants,
            )
            negative_control = NegativeControlExecution(
                target_root=str(control_root),
                snapshot_sha256=control_scope.target_snapshot_sha256,
                changed_files=changed_files,
                expected_return_codes=list(
                    request.negative_control.expected_return_codes
                ),
                result=control_result,
                assertion_results=control_assertions,
                invariant_results=control_invariants,
            )
        harness_unchanged = self._harness_snapshot_matches(
            harness_root, harness_snapshot
        )
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
            invariant_results,
            target_root,
            scope.target_snapshot_sha256,
            replay_of=evidence.artifact_sha256,
            harness_snapshot=harness_snapshot,
            negative_control=negative_control,
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
        control_signature_matches = True
        control_decision_matches = True
        target_invariant_decision_matches = True
        control_invariant_decision_matches = True
        if request.control_invariants:
            original_invariants = receipt.get("result", {}).get(
                "control_invariants", []
            )
            original_invariant_decision = [
                (item.get("assertion_id"), item.get("passed"))
                for item in original_invariants
            ]
            replay_invariant_decision = [
                (item.get("assertion_id"), item.get("passed"))
                for item in invariant_results
            ]
            target_invariant_decision_matches = (
                replay_invariant_decision == original_invariant_decision
            )
        if negative_control is not None:
            original_control = receipt.get("negative_control") or {}
            original_assertions = original_control.get("result", {}).get(
                "assertions", []
            )
            original_decision = [
                (item.get("assertion_id"), item.get("passed"))
                for item in original_assertions
            ]
            replay_decision = [
                (item.get("assertion_id"), item.get("passed"))
                for item in negative_control.assertion_results
            ]
            control_decision_matches = replay_decision == original_decision
            original_control_invariants = original_control.get("result", {}).get(
                "control_invariants", []
            )
            original_control_invariant_decision = [
                (item.get("assertion_id"), item.get("passed"))
                for item in original_control_invariants
            ]
            replay_control_invariant_decision = [
                (item.get("assertion_id"), item.get("passed"))
                for item in negative_control.invariant_results
            ]
            control_invariant_decision_matches = (
                replay_control_invariant_decision
                == original_control_invariant_decision
            )
        if negative_control is not None and request.replay_mode is ReplayMode.STRICT:
            original_control = receipt.get("negative_control") or {}
            original_control_signature = {
                key: original_control.get("result", {}).get(key)
                for key in result_signature(negative_control.result)
            }
            control_signature_matches = (
                result_signature(negative_control.result)
                == original_control_signature
            )
        verified = (
            result_is_accepted(
                result,
                request.expected_return_codes,
                assertion_results,
                invariant_results,
            )
            and target_unchanged
            and signature_matches
            and harness_unchanged
            and control_unchanged
            and control_accepted
            and control_decision_matches
            and target_invariant_decision_matches
            and control_invariant_decision_matches
            and control_signature_matches
        )
        event = {
            "event": "evidence_verified" if verified else "evidence_replay_failed",
            "evidence_id": evidence.evidence_id,
            "original_artifact_sha256": evidence.artifact_sha256,
            "replay_artifact_path": str(replay_artifact),
            "replay_artifact_sha256": replay_digest,
            "result": current_signature,
            "assertions": assertion_results,
            "control_invariants": invariant_results,
            "control_invariant_decision_matches": (
                target_invariant_decision_matches
            ),
            "replay_mode": request.replay_mode.value,
            "harness_snapshot_sha256": (
                harness_snapshot.snapshot_sha256
                if harness_snapshot is not None
                else None
            ),
            "negative_control": (
                {
                    "snapshot_sha256": negative_control.snapshot_sha256,
                    "result": result_signature(negative_control.result),
                    "assertions": negative_control.assertion_results,
                    "control_invariants": negative_control.invariant_results,
                    "accepted": control_accepted,
                    "decision_matches": control_decision_matches,
                    "invariant_decision_matches": (
                        control_invariant_decision_matches
                    ),
                }
                if negative_control is not None
                else None
            ),
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

    def confirm_finding(self, path: Path) -> Finding:
        value = self._read_json(path)
        finding = Finding.from_dict(value)
        scope = self._load_scope()
        target_root = Path(scope.target_root).resolve(strict=True)
        self._require_target_snapshot(scope, target_root)
        if EVIDENCE_RANK[finding.evidence_level] > EVIDENCE_RANK[scope.evidence_ceiling]:
            raise ValueError(
                "finding evidence level exceeds the run evidence ceiling "
                f"({scope.evidence_ceiling.value})"
            )
        hypothesis = self._hypothesis_by_id(finding.hypothesis_id)
        if finding.security_property != hypothesis.security_property:
            raise ValueError("finding security property does not match its hypothesis")
        verified_evidence = self._currently_verified_evidence_ids()
        if not set(finding.supporting_evidence) <= verified_evidence:
            missing = sorted(set(finding.supporting_evidence) - verified_evidence)
            raise ValueError(
                "every supporting evidence id must be runner-minted and replay-verified: "
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
            self._require_auxiliary_inputs_current(item, scope, target_root)
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
            structural_adapters = {"solc-ast", "slither", "semgrep"}
            structural_support = [
                item
                for item in supporting
                if item.level is EvidenceLevel.STRUCTURALLY_CONFIRMED
                and item.metadata.get("runner_minted") is True
                and item.metadata.get("adapter") in structural_adapters
            ]
            adapters = {str(item.metadata.get("adapter")) for item in structural_support}
            if len(adapters) < 2:
                raise ValueError(
                    "structural findings require two independent runner-verified structural adapters"
                )
        if finding.reproducer_evidence_id is not None:
            reproducer = evidence_by_id[finding.reproducer_evidence_id]
            if EVIDENCE_RANK[reproducer.level] < EVIDENCE_RANK[EvidenceLevel.EXECUTABLE]:
                raise ValueError("finding reproducer evidence is not executable")
            if reproducer.metadata.get("negative_control_verified") is not True:
                raise ValueError(
                    "finding reproducer lacks a runner-verified negative control"
                )
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
        structural_adapters = {"solc-ast", "slither", "semgrep"}
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
            if adapter in structural_adapters:
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

    def _prepare_harness(
        self,
        request: ExecutionRequest,
        target_root: Path,
        control_root: Path | None,
    ) -> tuple[Path | None, HarnessSnapshot | None]:
        if request.harness is None:
            return None, None
        root = Path(request.harness.path).resolve(strict=True)
        if self._paths_overlap(root, target_root) or (
            control_root is not None and self._paths_overlap(root, control_root)
        ):
            raise ValueError(
                "auditor harness must be outside the audited and negative-control targets"
            )
        return root, snapshot_harness(root)

    def _require_auxiliary_inputs_current(
        self,
        evidence: EvidenceRecord,
        scope: ScopeManifest,
        target_root: Path,
    ) -> None:
        if evidence.metadata.get("runner_minted") is not True:
            raise ValueError("finding supporting evidence was not runner-minted")
        artifact = Path(evidence.artifact_path or "").resolve(strict=True)
        receipt = load_receipt(artifact)
        request = request_from_receipt(receipt)
        hypothesis = self._hypothesis_by_id(request.hypothesis_id)
        control = self._prepare_negative_control(
            request, hypothesis, scope, target_root
        )
        _, harness_snapshot = self._prepare_harness(
            request, target_root, control[0] if control is not None else None
        )
        expected_harness = (
            harness_snapshot.to_dict() if harness_snapshot is not None else None
        )
        if receipt.get("harness") != expected_harness:
            raise ValueError("finding evidence auditor harness no longer matches its receipt")
        self._validate_control_receipt_binding(receipt, request, control)

    def _prepare_negative_control(
        self,
        request: ExecutionRequest,
        hypothesis: Hypothesis,
        scope: ScopeManifest,
        target_root: Path,
    ) -> tuple[Path, ScopeManifest, list[dict[str, str | None]]] | None:
        if request.negative_control is None:
            return None
        control_root = Path(request.negative_control.target_root).resolve(strict=True)
        if self._paths_overlap(control_root, target_root):
            raise ValueError(
                "negative control target must be separate from the audited target"
            )
        control_scope = RepositoryIntake(
            max_file_bytes=scope.max_analysis_file_bytes,
            ignored_directories=set(scope.excluded_directories),
        ).inspect(control_root)
        if not control_scope.snapshot_complete:
            raise ValueError("negative control target snapshot is incomplete")
        target_files = {item.path: item for item in scope.files}
        control_files = {item.path: item for item in control_scope.files}
        changed_files: list[dict[str, str | None]] = []
        for relative in sorted(target_files.keys() | control_files.keys()):
            target_item = target_files.get(relative)
            control_item = control_files.get(relative)
            target_signature = (
                (target_item.kind, target_item.size, target_item.sha256)
                if target_item is not None
                else None
            )
            control_signature = (
                (control_item.kind, control_item.size, control_item.sha256)
                if control_item is not None
                else None
            )
            if target_signature != control_signature:
                if len(changed_files) >= MAX_CONTROL_CHANGED_FILES:
                    raise ValueError(
                        "negative control target delta exceeds the 64-file safety limit"
                    )
                changed_files.append(
                    {
                        "path": relative,
                        "target_sha256": (
                            target_item.sha256 if target_item is not None else None
                        ),
                        "control_sha256": (
                            control_item.sha256 if control_item is not None else None
                        ),
                    }
                )
        actual_paths = [item["path"] for item in changed_files]
        if actual_paths != sorted(request.negative_control.changed_files):
            raise ValueError(
                "negative control changed_files do not exactly match its target delta; "
                f"expected {sorted(request.negative_control.changed_files)}, "
                f"observed {actual_paths}"
            )
        candidate_paths = {
            Path(location.path).as_posix()
            for location in hypothesis.candidate_locations
        }
        if not set(actual_paths) & candidate_paths:
            raise ValueError(
                "negative control must change at least one hypothesis candidate location; "
                f"candidates {sorted(candidate_paths)}, observed {actual_paths}"
            )
        return control_root, control_scope, changed_files

    @staticmethod
    def _validate_control_receipt_binding(
        receipt: dict[str, Any],
        request: ExecutionRequest,
        control: tuple[Path, ScopeManifest, list[dict[str, str | None]]] | None,
    ) -> None:
        recorded = receipt.get("negative_control")
        if control is None:
            if recorded is not None:
                raise ValueError("execution receipt has an unexpected negative control")
            return
        control_root, control_scope, changed_files = control
        expected = {
            "target": {
                "root": str(control_root),
                "snapshot_sha256": control_scope.target_snapshot_sha256,
            },
            "changed_files": changed_files,
            "expected_return_codes": list(
                request.negative_control.expected_return_codes
            ),
        }
        if not isinstance(recorded, dict):
            raise ValueError("execution receipt lacks its negative control")
        observed = {
            "target": recorded.get("target"),
            "changed_files": recorded.get("changed_files"),
            "expected_return_codes": recorded.get("expected_return_codes"),
        }
        if observed != expected:
            raise ValueError("execution receipt binds a different negative control")

    @staticmethod
    def _run_request(
        runner: CommandRunner,
        request: ExecutionRequest,
        cwd: Path,
        harness_root: Path | None,
    ):
        if harness_root is None:
            return runner.run(request.command, cwd, request.stdin.encode("utf-8"))
        return runner.run(
            request.command,
            cwd,
            request.stdin.encode("utf-8"),
            harness_root,
        )

    @staticmethod
    def _harness_snapshot_matches(
        harness_root: Path | None, harness_snapshot: HarnessSnapshot | None
    ) -> bool:
        if harness_root is None or harness_snapshot is None:
            return harness_root is None and harness_snapshot is None
        try:
            return (
                snapshot_harness(harness_root).snapshot_sha256
                == harness_snapshot.snapshot_sha256
            )
        except (OSError, ValueError):
            return False

    @staticmethod
    def _paths_overlap(first: Path, second: Path) -> bool:
        return first == second or first in second.parents or second in first.parents

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
        invariant_results: list[dict[str, Any]],
        *,
        harness_unchanged: bool = True,
        control_unchanged: bool = True,
        control_accepted: bool = True,
        control_invariant_results: list[dict[str, Any]] | None = None,
    ) -> str:
        if blocked_reason is not None:
            return f"execution was blocked: {blocked_reason}"
        if timed_out:
            return "execution timed out"
        if not target_unchanged:
            return "execution changed the audited target snapshot"
        if not harness_unchanged:
            return "execution changed the auditor harness snapshot"
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
        failed_invariants = [
            str(item.get("assertion_id"))
            for item in invariant_results
            if item.get("passed") is not True
        ]
        if failed_invariants:
            return (
                "execution control invariants failed: "
                f"{', '.join(failed_invariants)}"
            )
        if not control_unchanged:
            return "execution changed the negative control target snapshot"
        failed_control_invariants = [
            str(item.get("assertion_id"))
            for item in (control_invariant_results or [])
            if item.get("passed") is not True
        ]
        if failed_control_invariants:
            return (
                "negative control health invariants failed: "
                f"{', '.join(failed_control_invariants)}"
            )
        if not control_accepted:
            return (
                "negative control did not produce the declared opposite verifier decision"
            )
        return "execution did not satisfy the verification contract"

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
