from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .contracts import validate_contract
from .ledger import EvidenceLedger
from .models import CodeLocation, EvidenceLevel, EvidenceRecord, Hypothesis, MismatchClass
from .util import atomic_write_json, canonical_json, sha256_bytes, sha256_file, utc_now


MAX_DIFFERENTIAL_ARTIFACT_BYTES = 256 * 1024 * 1024


def load_differential_report(path: Path) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    if resolved.stat().st_size > MAX_DIFFERENTIAL_ARTIFACT_BYTES:
        raise ValueError("differential report exceeds the 256 MB import limit")
    value = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("differential report must be one JSON object")
    validate_contract(value, "differential-report.schema.json")
    return value


def attach_report(run_directory: Path, report_path: Path) -> list[Hypothesis]:
    run_root = run_directory.resolve(strict=True)
    ledger = EvidenceLedger(run_root / "evidence.jsonl")
    records = ledger.records()
    ledger.verify()
    report = load_differential_report(report_path)
    _require_valid_report(report)
    source = report_path.resolve(strict=True)
    digest = sha256_file(source)
    existing_attachment = next(
        (
            record["payload"]
            for record in records
            if record["payload"].get("event") == "differential_report_attached"
            and record["payload"].get("source_sha256") == digest
        ),
        None,
    )
    if existing_attachment is not None:
        attached_path = Path(str(existing_attachment["artifact_path"])).resolve(
            strict=True
        )
        attached_digest = str(existing_attachment["artifact_sha256"])
        if sha256_file(attached_path) != attached_digest:
            raise ValueError("previously attached differential report no longer matches the ledger")
        return _attached_hypotheses(records, report, attached_digest)
    attached_path = run_root / "differential" / f"report-{digest[:16]}.json"
    atomic_write_json(attached_path, report)
    attached_digest = sha256_file(attached_path)
    hypotheses: list[Hypothesis] = []
    payloads: list[dict[str, Any]] = [
        {
            "event": "differential_report_attached",
            "artifact_path": str(attached_path),
            "artifact_sha256": attached_digest,
            "source_path": str(source),
            "source_sha256": digest,
            "spec_sha256": report["spec_sha256"],
            "manifest_sha256": report["manifest_sha256"],
            "case_count": report["case_count"],
            "mismatch_count": len(report["mismatches"]),
            "valid": True,
        }
    ]
    existing_ids = {
        str(record["payload"]["hypothesis"]["hypothesis_id"])
        for record in records
        if record["payload"].get("event") == "hypothesis_proposed"
    }
    for mismatch in report["mismatches"]:
        identity = _differential_identity(attached_digest, mismatch)
        hypothesis_id = f"H-DIFF-{identity[:16]}"
        if hypothesis_id in existing_ids:
            continue
        hypothesis = Hypothesis(
            hypothesis_id=hypothesis_id,
            security_property=(
                "Independent implementations of the pinned specification must agree on observable behaviour"
            ),
            suspected_violation=(
                f"Differential case {mismatch['case_id']} produced distinct normalized outcomes"
            ),
            affected_assets=["specification-defined protocol behaviour"],
            required_attacker_capabilities=["supply the divergent input or reach an equivalent state"],
            assumptions=[
                "the comparator and normalizer are correct",
                "the implementations are sufficiently independent",
                "a disagreement is a hypothesis until classified and impact-validated",
            ],
            candidate_locations=[
                CodeLocation(path=f"differential/{attached_path.name}", line_start=1)
            ],
            verification_plan=[
                "rule out harness and normalization defects",
                "minimize the divergent seed",
                "classify the mismatch against the pinned prose and tests",
                "construct an impact verifier with a healthy negative control",
            ],
            threat_lens="differential-consistency",
            generator="differential-analysis",
            graph_slice=[
                f"spec:{report['spec_sha256']}",
                f"case:{mismatch['case_id']}",
                *[f"implementation:{item['implementation']}" for item in mismatch["outcomes"]],
            ],
            unresolved_assumptions=[
                "harness correctness",
                "specification intent",
                "security impact",
            ],
            proposed_next_experiment="minimize and classify the mismatch",
        )
        evidence = EvidenceRecord(
            evidence_id=f"E-DIFF-{identity[:16]}",
            hypothesis_id=hypothesis_id,
            level=EvidenceLevel.LOCALISED,
            kind="differential-disagreement",
            summary=f"Pinned implementations diverged on case {mismatch['case_id']}",
            source="nirvana:differential-harness",
            artifact_path=str(attached_path),
            artifact_sha256=attached_digest,
            metadata={
                "case_id": mismatch["case_id"],
                "input_sha256": mismatch["input_sha256"],
                "classification": mismatch["classification"],
                "spec_sha256": report["spec_sha256"],
                "manifest_sha256": report["manifest_sha256"],
                "not_proof": True,
            },
        )
        hypotheses.append(hypothesis)
        payloads.extend(
            [
                {
                    "event": "hypothesis_proposed",
                    "hypothesis": hypothesis.to_dict(),
                    "source": "differential-report",
                },
                {
                    "event": "evidence_recorded",
                    "evidence": evidence.to_dict(),
                    "source": "differential-report",
                },
            ]
        )
    ledger.append_many(payloads)
    from .workflow import refresh_report

    refresh_report(run_root)
    return hypotheses


def classify_mismatch(
    report_path: Path,
    case_id: str,
    classification: MismatchClass,
    rationale: list[str],
    output: Path,
    run_directory: Path | None = None,
) -> dict[str, Any]:
    if classification is MismatchClass.UNCLASSIFIED:
        raise ValueError("triage classification must resolve the unclassified state")
    if not rationale or any(not item.strip() for item in rationale):
        raise ValueError("mismatch classification requires a non-empty rationale")
    report = load_differential_report(report_path)
    _require_valid_report(report)
    matches = [item for item in report["mismatches"] if str(item["case_id"]) == case_id]
    if len(matches) != 1:
        raise ValueError(f"differential mismatch is not uniquely available: {case_id}")
    triage = {
        "schema_version": "1.0.0",
        "created_at": utc_now(),
        "report_sha256": sha256_file(report_path.resolve(strict=True)),
        "case_id": case_id,
        "classification": classification.value,
        "rationale": list(rationale),
        "reviewed_outcomes": list(matches[0]["outcomes"]),
    }
    validate_contract(triage, "differential-triage.schema.json")
    output_path = output.resolve()
    atomic_write_json(output_path, triage)
    if run_directory is not None:
        _append_artifact_event(
            run_directory,
            "differential_mismatch_classified",
            output_path,
            {"case_id": case_id, "classification": classification.value},
        )
    return triage


def write_feedback_package(
    triage_path: Path,
    minimization_path: Path,
    spec_amendment: str,
    regression_test: str,
    output: Path,
    run_directory: Path | None = None,
) -> dict[str, Any]:
    triage = _validated_json(triage_path, "differential-triage.schema.json")
    minimized = _validated_json(
        minimization_path, "differential-minimization.schema.json"
    )
    if triage["case_id"] != minimized["case_id"]:
        raise ValueError("triage and minimization refer to different cases")
    if not spec_amendment.strip() or not regression_test.strip():
        raise ValueError("feedback requires both a spec amendment and a regression-test description")
    package = {
        "schema_version": "1.0.0",
        "created_at": utc_now(),
        "case_id": triage["case_id"],
        "classification": triage["classification"],
        "triage_sha256": sha256_file(triage_path.resolve(strict=True)),
        "minimization_sha256": sha256_file(minimization_path.resolve(strict=True)),
        "spec_amendment": spec_amendment,
        "regression_test": regression_test,
        "corpus_case": {
            "id": f"regression-{triage['case_id']}",
            "input": minimized["minimized_input"],
        },
        "application_status": "proposal; human review required before changing the spec or corpus",
    }
    validate_contract(package, "differential-feedback.schema.json")
    output_path = output.resolve()
    atomic_write_json(output_path, package)
    if run_directory is not None:
        _append_artifact_event(
            run_directory,
            "differential_feedback_created",
            output_path,
            {"case_id": triage["case_id"]},
        )
    return package


def prepare_disclosure_packet(
    report_path: Path,
    triage_path: Path,
    minimization_path: Path,
    agent_context_path: Path,
    impact_statement: str,
    output: Path,
    run_directory: Path | None = None,
) -> dict[str, Any]:
    report = load_differential_report(report_path)
    _require_valid_report(report)
    triage = _validated_json(triage_path, "differential-triage.schema.json")
    minimized = _validated_json(
        minimization_path, "differential-minimization.schema.json"
    )
    context = json.loads(agent_context_path.resolve(strict=True).read_text(encoding="utf-8"))
    if not isinstance(context, dict):
        raise ValueError("agent context must be one JSON object")
    validate_contract(context, "disclosure-agent-context.schema.json")
    if triage["case_id"] != minimized["case_id"] or not impact_statement.strip():
        raise ValueError("disclosure inputs disagree or impact statement is empty")
    mismatch = next(
        (item for item in report["mismatches"] if item["case_id"] == triage["case_id"]),
        None,
    )
    if mismatch is None:
        raise ValueError("triaged case is absent from the differential report")
    packet = {
        "schema_version": "1.0.0",
        "created_at": utc_now(),
        "spec_revision": {
            "path": report["spec_path"],
            "sha256": report["spec_sha256"],
            "manifest_sha256": report["manifest_sha256"],
        },
        "minimized_seed": minimized["minimized_input"],
        "normalized_outputs": [
            {
                "implementation": item["implementation"],
                "normalized_output": item["normalized_output"],
                "return_code": item["return_code"],
            }
            for item in mismatch["outcomes"]
        ],
        "classification": triage["classification"],
        "impact_statement": impact_statement,
        "agent_configuration": {
            **context,
            "implementations": report["implementations"],
            "runner": report["runner"],
        },
        "prompt_injection_assessment": {
            "untrusted_content_in_scope": context["untrusted_content_in_scope"],
            "indicators": context["prompt_injection_indicators"],
            "pipeline_network_allowed": report["runner"]["network_allowed"],
            "host_execution_allowed": report["runner"]["host_execution_allowed"],
        },
        "recommended_order": [
            "spec authors",
            "implementation maintainers",
            "integrators and downstream client teams",
            "public advisory after coordinated mitigation",
        ],
        "handling": {
            "visibility": "private",
            "automatic_delivery": False,
            "human_approval_required": True,
            "warning": "Do not publish exploit-capable details before mitigations or disablement steps exist.",
        },
    }
    validate_contract(packet, "disclosure-packet.schema.json")
    output_path = output.resolve()
    atomic_write_json(output_path, packet)
    if run_directory is not None:
        _append_artifact_event(
            run_directory,
            "disclosure_packet_prepared",
            output_path,
            {"case_id": triage["case_id"], "automatic_delivery": False},
        )
    return packet


def _validated_json(path: Path, schema: str) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    value = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{schema} artifact must be one JSON object")
    validate_contract(value, schema)
    return value


def _require_valid_report(report: dict[str, Any]) -> None:
    if report["valid"] is True:
        return
    reasons = "; ".join(str(item) for item in report["invalid_reasons"])
    raise ValueError(
        "differential report is invalid and cannot enter the hypothesis, triage, "
        f"or disclosure pipeline: {reasons}"
    )


def _attached_hypotheses(
    records: list[dict[str, Any]], report: dict[str, Any], attached_digest: str
) -> list[Hypothesis]:
    expected_ids = {
        f"H-DIFF-{_differential_identity(attached_digest, mismatch)[:16]}"
        for mismatch in report["mismatches"]
    }
    existing = {
        str(record["payload"]["hypothesis"]["hypothesis_id"]): Hypothesis.from_dict(
            record["payload"]["hypothesis"]
        )
        for record in records
        if record["payload"].get("event") == "hypothesis_proposed"
        and str(record["payload"]["hypothesis"].get("hypothesis_id"))
        in expected_ids
    }
    missing = expected_ids - existing.keys()
    if missing:
        raise ValueError(
            "differential attachment ledger is incomplete for hypotheses: "
            f"{sorted(missing)}"
        )
    return [existing[item] for item in sorted(expected_ids)]


def _differential_identity(
    attached_digest: str, mismatch: dict[str, Any]
) -> str:
    return sha256_bytes(
        canonical_json(
            {
                "report": attached_digest,
                "case_id": mismatch["case_id"],
                "input": mismatch["input_sha256"],
            }
        ).encode()
    )


def _append_artifact_event(
    run_directory: Path,
    event: str,
    artifact: Path,
    metadata: dict[str, Any],
) -> None:
    run_root = run_directory.resolve(strict=True)
    ledger = EvidenceLedger(run_root / "evidence.jsonl")
    ledger.verify()
    ledger.append(
        {
            "event": event,
            "artifact_path": str(artifact),
            "artifact_sha256": sha256_file(artifact),
            **metadata,
        }
    )
    from .workflow import refresh_report

    refresh_report(run_root)
