from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .contracts import validate_contract
from .ledger import EvidenceLedger
from .models import Finding, HypothesisStatus, NoveltyClass
from .semantic import semantic_fingerprint
from .util import canonical_json, sha256_bytes, sha256_file, utc_now


class AdjudicationBoard:
    def __init__(self, run_directory: Path):
        self.run_directory = run_directory.resolve(strict=True)
        self.ledger = EvidenceLedger(self.run_directory / "evidence.jsonl")
        self.ledger.verify()

    def submit_critic_decision(self, path: Path) -> dict[str, Any]:
        resolved = path.resolve(strict=True)
        value = json.loads(resolved.read_text(encoding="utf-8"))
        validate_contract(value, "critic-decision.schema.json")
        hypothesis_id = str(value["hypothesis_id"])
        records = self.ledger.records()
        if hypothesis_id not in _hypothesis_ids(records):
            raise ValueError(f"unknown hypothesis: {hypothesis_id}")
        critic = str(value["critic"])
        decision = str(value["decision"])
        if critic == "devils_advocate" and decision not in {"sustain", "reject"}:
            raise ValueError("Devil's Advocate decisions must sustain or reject")
        if critic == "rescue" and decision not in {"uphold_rejection", "rescue"}:
            raise ValueError("Rescue Critic decisions must uphold_rejection or rescue")
        current = current_hypothesis_status(records, hypothesis_id)
        if critic == "rescue" and current is not HypothesisStatus.REJECTED:
            raise ValueError("Rescue Critic may review only a rejected hypothesis")
        if critic == "devils_advocate" and current is HypothesisStatus.VERIFIED:
            raise ValueError("a verified hypothesis cannot be rejected without invalidating its evidence")
        evidence_ids = [str(item) for item in value["evidence_ids"]]
        known_evidence = _evidence_ids(records)
        unknown = sorted(set(evidence_ids) - known_evidence)
        if unknown:
            raise ValueError(f"critic decision references unknown evidence: {unknown}")
        if decision in {"reject", "rescue"} and not value["assumptions_examined"]:
            raise ValueError("rejection and rescue decisions must identify examined assumptions")
        if decision == "rescue" and not evidence_ids and not value.get("next_experiment"):
            raise ValueError("rescue requires new evidence or a concrete next experiment")
        next_status = {
            "sustain": HypothesisStatus.AWAITING_VERIFICATION,
            "reject": HypothesisStatus.REJECTED,
            "uphold_rejection": HypothesisStatus.REJECTED,
            "rescue": HypothesisStatus.RESCUED,
        }[decision]
        payload = {
            "event": "critic_decision",
            "hypothesis_id": hypothesis_id,
            "critic": critic,
            "decision": decision,
            "status": next_status.value,
            "reasons": list(value["reasons"]),
            "assumptions_examined": list(value["assumptions_examined"]),
            "evidence_ids": evidence_ids,
            "next_experiment": value.get("next_experiment"),
            "decision_artifact": {
                "path": str(resolved),
                "sha256": sha256_file(resolved),
            },
        }
        self.ledger.append(payload)
        from .workflow import refresh_report

        refresh_report(self.run_directory)
        return payload

    def assess_novelty(self, finding_id: str, corpus_path: Path) -> dict[str, Any]:
        records = self.ledger.records()
        finding_values = [
            record["payload"]["finding"]
            for record in records
            if record["payload"].get("event") == "finding_confirmed"
            and record["payload"]["finding"].get("finding_id") == finding_id
        ]
        if len(finding_values) != 1:
            raise ValueError(f"novelty assessment requires one confirmed finding: {finding_id}")
        finding = Finding.from_dict(finding_values[0])
        resolved = corpus_path.resolve(strict=True)
        corpus = json.loads(resolved.read_text(encoding="utf-8"))
        validate_contract(corpus, "known-issue-corpus.schema.json")
        classification, related, rationale, comparisons = _compare_known_issues(
            finding, corpus["issues"]
        )
        payload = {
            "event": "novelty_assessed",
            "finding_id": finding_id,
            "classification": classification.value,
            "related_issues": related,
            "rationale": rationale,
            "causal_comparisons": comparisons,
            "corpus_path": str(resolved),
            "corpus_sha256": sha256_file(resolved),
            "assessed_at": utc_now(),
        }
        self.ledger.append(payload)
        from .workflow import refresh_report

        refresh_report(self.run_directory)
        return payload


def current_hypothesis_status(
    records: list[dict[str, Any]], hypothesis_id: str
) -> HypothesisStatus:
    proposed = [
        record["payload"]["hypothesis"]
        for record in records
        if record["payload"].get("event") == "hypothesis_proposed"
        and record["payload"]["hypothesis"].get("hypothesis_id") == hypothesis_id
    ]
    if not proposed:
        raise ValueError(f"unknown hypothesis: {hypothesis_id}")
    status = HypothesisStatus(proposed[-1].get("status", HypothesisStatus.PROPOSED.value))
    evidence_to_hypothesis = {
        str(record["payload"]["evidence"]["evidence_id"]): record["payload"]["evidence"].get("hypothesis_id")
        for record in records
        if record["payload"].get("event") == "evidence_recorded"
    }
    verified: set[str] = set()
    for record in records:
        payload = record["payload"]
        if payload.get("event") == "critic_decision" and payload.get("hypothesis_id") == hypothesis_id:
            status = HypothesisStatus(payload["status"])
        elif payload.get("event") in {"evidence_verified", "evidence_replay_failed"}:
            evidence_id = str(payload.get("evidence_id"))
            if evidence_to_hypothesis.get(evidence_id) != hypothesis_id:
                continue
            if payload["event"] == "evidence_verified":
                verified.add(evidence_id)
            else:
                verified.discard(evidence_id)
            if verified:
                status = HypothesisStatus.VERIFIED
            elif status is HypothesisStatus.VERIFIED:
                status = HypothesisStatus.AWAITING_VERIFICATION
    return status


def latest_novelty_assessments(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    assessments: dict[str, dict[str, Any]] = {}
    for record in records:
        payload = record["payload"]
        if payload.get("event") == "novelty_assessed":
            assessments[str(payload["finding_id"])] = payload
    return assessments


def rejected_archive(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for hypothesis_id in sorted(_hypothesis_ids(records)):
        if current_hypothesis_status(records, hypothesis_id) is not HypothesisStatus.REJECTED:
            continue
        decisions = [
            record["payload"]
            for record in records
            if record["payload"].get("event") == "critic_decision"
            and record["payload"].get("hypothesis_id") == hypothesis_id
        ]
        result.append(
            {
                "hypothesis_id": hypothesis_id,
                "reasons": [reason for decision in decisions for reason in decision.get("reasons", [])],
                "last_decision": decisions[-1]["decision"] if decisions else "unknown",
            }
        )
    return result


def _compare_known_issues(
    finding: Finding, issues: list[dict[str, Any]]
) -> tuple[NoveltyClass, list[str], str, list[dict[str, Any]]]:
    if not issues:
        return (
            NoveltyClass.UNCERTAIN,
            [],
            "the supplied known-issue corpus is empty",
            [],
        )
    finding_root = _words(finding.root_cause)
    finding_property = _words(finding.security_property)
    finding_locations = {item.path for item in finding.locations}
    finding_graph = _sequence(finding.causal_path)
    finding_prerequisites = _set(finding.attacker_prerequisites)
    finding_sequence = _sequence(finding.reproduction_instructions)
    finding_impact = _words(finding.impact)
    finding_fix = _words(finding.remediation)
    comparisons: list[dict[str, Any]] = []
    for issue in issues:
        dimensions = {
            "security_property": _words(str(issue["security_property"]))
            == finding_property,
            "root_cause": _words(str(issue["root_cause"])) == finding_root,
            "causal_graph": _sequence(issue["root_cause_graph"]) == finding_graph,
            "attacker_prerequisites": _set(issue["attacker_prerequisites"])
            == finding_prerequisites,
            "exploit_sequence": _sequence(issue["exploit_sequence"])
            == finding_sequence,
            "impact": _words(str(issue["impact"])) == finding_impact,
            "fix_strategy": _words(str(issue["fix_strategy"])) == finding_fix,
            "code_identity": str(issue["code_identity"]) in finding_locations,
            "historical_lineage": bool(
                set(map(str, issue["historical_lineage"]))
                & set(finding.related_issues)
            ),
        }
        comparisons.append(
            {
                "issue_id": str(issue["issue_id"]),
                "status": str(issue["status"]),
                "dimensions": dimensions,
                "matched_dimension_count": sum(dimensions.values()),
                "provenance": str(issue["provenance"]),
                "published_at": str(issue["published_at"]),
            }
        )
    exact = [
        (issue, comparison)
        for issue, comparison in zip(issues, comparisons, strict=True)
        if all(
            comparison["dimensions"][dimension]
            for dimension in (
                "security_property",
                "root_cause",
                "causal_graph",
                "attacker_prerequisites",
                "exploit_sequence",
                "impact",
                "fix_strategy",
                "code_identity",
            )
        )
    ]
    variants = [
        (issue, comparison)
        for issue, comparison in zip(issues, comparisons, strict=True)
        if comparison["dimensions"]["security_property"]
        and comparison["dimensions"]["root_cause"]
        and not any(issue is exact_issue for exact_issue, _ in exact)
    ]
    instances = [
        (issue, comparison)
        for issue, comparison in zip(issues, comparisons, strict=True)
        if comparison["dimensions"]["security_property"]
        and not comparison["dimensions"]["root_cause"]
    ]
    if exact:
        unfixed = [item for item in exact if item[0]["status"] == "unfixed"]
        selected = unfixed or exact
        classification = NoveltyClass.KNOWN_UNFIXED if unfixed else NoveltyClass.EXACT_DUPLICATE
        return (
            classification,
            [str(item[0]["issue_id"]) for item in selected],
            "same code identity, invariant, root cause, causal graph, prerequisites, exploit sequence, impact, and fix strategy",
            comparisons,
        )
    if variants:
        return (
            NoveltyClass.VARIANT,
            [str(item[0]["issue_id"]) for item in variants],
            "same root cause and invariant with one or more distinct causal, prerequisite, sequence, impact, fix, or code dimensions",
            comparisons,
        )
    if instances:
        return (
            NoveltyClass.NEW_INSTANCE,
            [str(item[0]["issue_id"]) for item in instances],
            "known security property with a distinct root cause",
            comparisons,
        )
    return (
        NoveltyClass.NOVEL_MECHANISM,
        [],
        "no matching invariant or causal mechanism exists in the supplied provenance-bearing corpus",
        comparisons,
    )


def _words(value: str) -> str:
    import re

    return " ".join(re.findall(r"[a-z0-9]+", value.lower()))


def _sequence(values: list[Any]) -> list[str]:
    return [_words(str(value)) for value in values]


def _set(values: list[Any]) -> list[str]:
    return sorted({_words(str(value)) for value in values})


def _hypothesis_ids(records: list[dict[str, Any]]) -> set[str]:
    return {
        str(record["payload"]["hypothesis"]["hypothesis_id"])
        for record in records
        if record["payload"].get("event") == "hypothesis_proposed"
    }


def _evidence_ids(records: list[dict[str, Any]]) -> set[str]:
    return {
        str(record["payload"]["evidence"]["evidence_id"])
        for record in records
        if record["payload"].get("event") == "evidence_recorded"
    }
