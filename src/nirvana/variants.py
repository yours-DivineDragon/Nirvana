from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .contracts import validate_contract
from .ledger import EvidenceLedger
from .intake import ScopeManifest, validate_scope_against_ledger
from .models import Hypothesis
from .semantic import SecuritySemanticGraph, graph_hypotheses
from .util import sha256_file


_STOP_WORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "in",
    "is", "it", "of", "on", "or", "that", "the", "this", "to", "with", "must",
}


def mine_historical_variants(
    run_directory: Path,
    corpus_path: Path,
    cutoff: str | None = None,
) -> list[Hypothesis]:
    run_root = run_directory.resolve(strict=True)
    ledger = EvidenceLedger(run_root / "evidence.jsonl")
    records = ledger.records()
    ledger.verify()
    corpus_file = corpus_path.resolve(strict=True)
    corpus = json.loads(corpus_file.read_text(encoding="utf-8"))
    validate_contract(corpus, "known-issue-corpus.schema.json")
    cutoff_date = _date(cutoff) if cutoff is not None else None
    issues = [
        item
        for item in corpus["issues"]
        if cutoff_date is None or _date(item["published_at"]) <= cutoff_date
    ]
    graph = SecuritySemanticGraph.from_dict(
        json.loads((run_root / "semantic-graph.json").read_text(encoding="utf-8"))
    )
    graph_record = next(
        (
            record["payload"]
            for record in records
            if record["payload"].get("event") == "semantic_graph_created"
        ),
        None,
    )
    if graph_record is None or sha256_file(run_root / "semantic-graph.json") != graph_record["artifact_sha256"]:
        raise ValueError("semantic graph does not match the run ledger")
    existing = [
        Hypothesis.from_dict(record["payload"]["hypothesis"])
        for record in records
        if record["payload"].get("event") == "hypothesis_proposed"
    ]
    templates = [_issue_template(item) for item in issues]
    scope = validate_scope_against_ledger(
        ScopeManifest.from_dict(
            json.loads((run_root / "scope.json").read_text(encoding="utf-8"))
        ),
        records,
    )
    if graph.target_snapshot_sha256 != scope.target_snapshot_sha256:
        raise ValueError("historical variant graph targets a different repository snapshot")
    generated = graph_hypotheses(
        graph,
        Path(scope.target_root),
        existing,
        templates,
    )
    existing_ids = {item.hypothesis_id for item in existing}
    new = [item for item in generated if item.hypothesis_id not in existing_ids]
    payloads: list[dict[str, Any]] = [
        {
            "event": "historical_variant_corpus_mined",
            "corpus_path": str(corpus_file),
            "corpus_sha256": sha256_file(corpus_file),
            "cutoff": cutoff,
            "eligible_issue_count": len(issues),
            "hypothesis_count": len(new),
            "retrieval_is_evidence": False,
        }
    ]
    payloads.extend(
        {
            "event": "hypothesis_proposed",
            "hypothesis": hypothesis.to_dict(),
            "source": "historical-variant-corpus",
        }
        for hypothesis in new
    )
    ledger.append_many(payloads)
    from .workflow import refresh_report

    refresh_report(run_root)
    return new


def _issue_template(issue: dict[str, Any]) -> dict[str, Any]:
    words = re.findall(
        r"[a-z][a-z0-9_-]{3,}",
        " ".join(
            [
                issue["security_property"],
                issue["root_cause"],
                *issue["root_cause_graph"],
                issue["impact"],
            ]
        ).lower(),
    )
    keywords = sorted({word for word in words if word not in _STOP_WORDS})[:24]
    return {
        "id": issue["issue_id"],
        "keywords": keywords,
        "threat_lens": "historical-variant",
        "security_property": issue["security_property"],
        "attacker_capabilities": issue["attacker_prerequisites"],
        "provenance": f"{issue['provenance']} (published {issue['published_at']})",
        "retrieval": True,
    }


def _date(value: str) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
