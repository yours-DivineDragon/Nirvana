from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .contracts import validate_contract
from .ledger import EvidenceLedger
from .models import Hypothesis
from .semantic import SecuritySemanticGraph, SemanticEdge, SemanticNode
from .util import atomic_write_json, jsonable, sha256_bytes, sha256_file, utc_now


THREAT_LENSES = (
    "access-control",
    "accounting",
    "sequencing",
    "oracle-and-external-input",
    "callback-and-reentrancy",
    "griefing-and-liveness",
    "privilege-and-upgrade",
    "cryptography-and-randomness",
    "configuration-and-deployment",
)


@dataclass(slots=True)
class BusinessFlow:
    flow_id: str
    name: str
    entry_points: list[str]
    assets: list[str]
    authorities: list[str]
    state_transitions: list[str]
    trust_boundaries: list[str]
    upgrades: list[str]
    risk: float


@dataclass(slots=True)
class CoverageTask:
    task_id: str
    flow_id: str
    threat_lens: str
    risk: float
    status: str
    graph_slice: list[str]
    candidate_hypotheses: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CoverageManifest:
    schema_version: str
    created_at: str
    graph_sha256: str
    flows: list[BusinessFlow]
    threat_lenses: list[str]
    tasks: list[CoverageTask]
    tracked: dict[str, list[str]]
    completeness: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        value = jsonable(self)
        validate_contract(value, "coverage.schema.json")
        return value

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "CoverageManifest":
        validate_contract(value, "coverage.schema.json")
        return cls(
            schema_version=str(value["schema_version"]),
            created_at=str(value["created_at"]),
            graph_sha256=str(value["graph_sha256"]),
            flows=[BusinessFlow(**item) for item in value["flows"]],
            threat_lenses=[str(item) for item in value["threat_lenses"]],
            tasks=[CoverageTask(**item) for item in value["tasks"]],
            tracked={str(key): [str(item) for item in items] for key, items in value["tracked"].items()},
            completeness={str(key): float(item) for key, item in value["completeness"].items()},
        )


def build_coverage_schedule(
    graph: SecuritySemanticGraph,
    hypotheses: Iterable[Hypothesis],
) -> CoverageManifest:
    node_by_id = {node.node_id: node for node in graph.nodes}
    outgoing: dict[str, list[SemanticEdge]] = {}
    for edge in graph.edges:
        outgoing.setdefault(edge.source, []).append(edge)

    flow_roots = [
        node for node in graph.nodes if node.kind == "entry_point"
    ] or [
        node
        for node in graph.nodes
        if node.kind == "symbol"
        and any(
            node_by_id.get(edge.target) is not None
            and node_by_id[edge.target].kind in {"effect", "asset", "upgrade"}
            for edge in outgoing.get(node.node_id, [])
        )
    ]
    flows: list[BusinessFlow] = []
    for root in flow_roots[:250]:
        reachable = _bounded_reachable(root.node_id, outgoing, 3, 128)
        related = [node_by_id[item] for item in reachable if item in node_by_id]
        grouped = {
            kind: sorted({item.node_id for item in related if item.kind == kind})
            for kind in ("asset", "authority", "state", "trust_boundary", "upgrade", "effect")
        }
        risk = 1.0
        risk += 2.0 * bool(grouped["asset"])
        risk += 1.5 * bool(grouped["authority"])
        risk += 1.5 * bool(grouped["trust_boundary"])
        risk += 2.0 * bool(grouped["upgrade"])
        risk += 0.5 * len(grouped["effect"])
        flow_id = f"FLOW-{sha256_bytes(root.node_id.encode())[:16]}"
        flows.append(
            BusinessFlow(
                flow_id=flow_id,
                name=root.label,
                entry_points=[root.node_id],
                assets=grouped["asset"],
                authorities=grouped["authority"],
                state_transitions=sorted(set(grouped["state"] + grouped["effect"])),
                trust_boundaries=grouped["trust_boundary"],
                upgrades=grouped["upgrade"],
                risk=risk,
            )
        )
    if not flows:
        modules = [node for node in graph.nodes if node.kind == "module"]
        for module in modules[:100]:
            flows.append(
                BusinessFlow(
                    flow_id=f"FLOW-{sha256_bytes(module.node_id.encode())[:16]}",
                    name=f"module review: {module.label}",
                    entry_points=[module.node_id],
                    assets=[],
                    authorities=[],
                    state_transitions=[],
                    trust_boundaries=[],
                    upgrades=[],
                    risk=1.0,
                )
            )

    hypotheses_list = list(hypotheses)
    tasks: list[CoverageTask] = []
    for flow in sorted(flows, key=lambda item: (-item.risk, item.flow_id)):
        graph_slice = sorted(
            set(
                flow.entry_points
                + flow.assets
                + flow.authorities
                + flow.state_transitions
                + flow.trust_boundaries
                + flow.upgrades
            )
        )
        for lens in THREAT_LENSES:
            related_hypotheses = sorted(
                item.hypothesis_id
                for item in hypotheses_list
                if item.threat_lens == lens
                or bool(set(item.graph_slice) & set(graph_slice))
            )
            task_identity = f"{flow.flow_id}\0{lens}".encode()
            task_id = f"C-{sha256_bytes(task_identity)[:18]}"
            tasks.append(
                CoverageTask(
                    task_id=task_id,
                    flow_id=flow.flow_id,
                    threat_lens=lens,
                    risk=flow.risk + _lens_risk(lens, flow),
                    status="scheduled",
                    graph_slice=graph_slice,
                    candidate_hypotheses=related_hypotheses,
                    notes=(
                        ["candidate generated; verification still required"]
                        if related_hypotheses
                        else ["coverage gap: no candidate or negative analysis recorded"]
                    ),
                )
            )
    tasks.sort(key=lambda item: (-item.risk, item.task_id))
    tracked = {
        "functions_and_modules": sorted(node.node_id for node in graph.nodes if node.kind in {"module", "symbol", "entry_point"}),
        "assets": sorted(node.node_id for node in graph.nodes if node.kind == "asset"),
        "authority_paths": sorted(node.node_id for node in graph.nodes if node.kind == "authority"),
        "state_transitions": sorted(node.node_id for node in graph.nodes if node.kind in {"state", "effect"}),
        "trust_boundaries": sorted(node.node_id for node in graph.nodes if node.kind == "trust_boundary"),
        "privileged_actions": sorted(node.node_id for node in graph.nodes if node.kind == "upgrade"),
        "invariants": sorted(node.node_id for node in graph.nodes if node.kind == "invariant"),
        "dynamic_states_reached": [],
        "hypotheses_tested": [],
    }
    return CoverageManifest(
        schema_version="1.0.0",
        created_at=utc_now(),
        graph_sha256=graph.sha256(),
        flows=flows,
        threat_lenses=list(THREAT_LENSES),
        tasks=tasks,
        tracked=tracked,
        completeness=_completeness(tasks, tracked),
    )


class CoverageBoard:
    """Ledger-backed coverage updates; ``coverage.json`` is only a projection."""

    def __init__(self, run_directory: Path):
        self.run_directory = run_directory.resolve(strict=True)
        self.ledger = EvidenceLedger(self.run_directory / "evidence.jsonl")
        self.ledger.verify()

    def load(self) -> CoverageManifest:
        captured = [
            record["payload"]
            for record in self.ledger.records()
            if record["payload"].get("event") == "coverage_schedule_created"
        ]
        if len(captured) != 1:
            raise ValueError("ledger must bind exactly one coverage schedule")
        initial_path = Path(str(captured[0]["artifact_path"])).resolve(strict=True)
        if initial_path != (self.run_directory / "coverage-initial.json").resolve(strict=True):
            raise ValueError("coverage schedule artifact escapes the run directory")
        if sha256_file(initial_path) != captured[0].get("coverage_sha256"):
            raise ValueError("initial coverage schedule does not match the ledger")
        initial = CoverageManifest.from_dict(
            json.loads(initial_path.read_text(encoding="utf-8"))
        )
        if initial.graph_sha256 != captured[0].get("graph_sha256"):
            raise ValueError("coverage schedule targets a different semantic graph")
        return self._reconstruct(initial)

    def mark(
        self,
        task_id: str,
        status: str,
        evidence_ids: list[str],
        notes: list[str],
        reached_nodes: list[str] | None = None,
    ) -> CoverageManifest:
        if status not in {"in_progress", "covered", "blocked"}:
            raise ValueError("coverage status must be in_progress, covered, or blocked")
        manifest = self.load()
        known = {item.task_id for item in manifest.tasks}
        if task_id not in known:
            raise ValueError(f"unknown coverage task: {task_id}")
        if status == "covered" and not evidence_ids and not notes:
            raise ValueError("covered tasks require evidence ids or a deterministic negative-analysis note")
        if status == "covered" and not evidence_ids and not any(
            note.startswith("negative-analysis:") and len(note) > len("negative-analysis:") + 20
            for note in notes
        ):
            raise ValueError(
                "coverage without verified evidence requires a concrete "
                "negative-analysis: note"
            )
        verified = _currently_verified_evidence(self.ledger.records())
        unknown_evidence = sorted(set(evidence_ids) - verified)
        if unknown_evidence:
            raise ValueError(f"coverage evidence must be replay-verified: {unknown_evidence}")
        known_nodes = {
            node
            for values in manifest.tracked.values()
            for node in values
        } | {node for task in manifest.tasks for node in task.graph_slice}
        unknown_nodes = sorted(set(reached_nodes or []) - known_nodes)
        if unknown_nodes:
            raise ValueError(f"coverage update references unknown graph nodes: {unknown_nodes}")
        event = {
            "event": "coverage_updated",
            "task_id": task_id,
            "status": status,
            "evidence_ids": sorted(set(evidence_ids)),
            "notes": list(notes),
            "reached_nodes": sorted(set(reached_nodes or [])),
        }
        self.ledger.append(event)
        updated = self.load()
        atomic_write_json(self.run_directory / "coverage.json", updated)
        return updated

    def _reconstruct(self, initial: CoverageManifest) -> CoverageManifest:
        tasks = {item.task_id: item for item in initial.tasks}
        for record in self.ledger.records():
            payload = record["payload"]
            if payload.get("event") != "coverage_updated":
                continue
            task = tasks.get(str(payload.get("task_id")))
            if task is None:
                raise ValueError("coverage ledger references an unknown task")
            task.status = str(payload["status"])
            task.evidence_ids = [str(item) for item in payload.get("evidence_ids", [])]
            task.notes = [str(item) for item in payload.get("notes", [])]
            initial.tracked["dynamic_states_reached"] = sorted(
                set(initial.tracked.get("dynamic_states_reached", []))
                | {str(item) for item in payload.get("reached_nodes", [])}
            )
        records = self.ledger.records()
        evidence_hypotheses = {
            str(record["payload"]["evidence"]["evidence_id"]): record["payload"]["evidence"].get("hypothesis_id")
            for record in records
            if record["payload"].get("event") == "evidence_recorded"
        }
        tested = sorted(
            {
                str(evidence_hypotheses[evidence_id])
                for evidence_id in _currently_verified_evidence(records)
                if evidence_hypotheses.get(evidence_id) is not None
            }
        )
        initial.tracked["hypotheses_tested"] = tested
        initial.completeness = _completeness(initial.tasks, initial.tracked)
        return initial


def _bounded_reachable(
    start: str,
    outgoing: dict[str, list[SemanticEdge]],
    depth: int,
    limit: int,
) -> list[str]:
    seen = {start}
    frontier = {start}
    for _ in range(depth):
        following = {
            edge.target
            for node in frontier
            for edge in outgoing.get(node, [])
            if edge.target not in seen
        }
        seen.update(following)
        frontier = following
        if not frontier or len(seen) >= limit:
            break
    return sorted(seen)[:limit]


def _lens_risk(lens: str, flow: BusinessFlow) -> float:
    if lens == "access-control" and flow.authorities:
        return 2.0
    if lens == "accounting" and flow.assets:
        return 2.0
    if lens == "callback-and-reentrancy" and flow.trust_boundaries:
        return 2.0
    if lens == "privilege-and-upgrade" and flow.upgrades:
        return 2.5
    return 0.0


def _completeness(
    tasks: list[CoverageTask], tracked: dict[str, list[str]]
) -> dict[str, float]:
    total = len(tasks)
    covered = sum(item.status == "covered" for item in tasks)
    return {
        "flow_threat_tasks": covered / total if total else 0.0,
        "assets": _node_coverage(tasks, tracked.get("assets", [])),
        "authority_paths": _node_coverage(tasks, tracked.get("authority_paths", [])),
        "state_transitions": _node_coverage(tasks, tracked.get("state_transitions", [])),
        "trust_boundaries": _node_coverage(tasks, tracked.get("trust_boundaries", [])),
        "dynamic_states": 1.0 if tracked.get("dynamic_states_reached") else 0.0,
    }


def _node_coverage(tasks: list[CoverageTask], nodes: list[str]) -> float:
    if not nodes:
        return 1.0
    covered_nodes = {
        node
        for task in tasks
        if task.status == "covered"
        for node in task.graph_slice
    }
    return len(set(nodes) & covered_nodes) / len(set(nodes))


def _currently_verified_evidence(records: list[dict[str, Any]]) -> set[str]:
    latest: dict[str, str] = {}
    for record in records:
        payload = record["payload"]
        if payload.get("event") in {"evidence_verified", "evidence_replay_failed"}:
            latest[str(payload["evidence_id"])] = str(payload["event"])
    return {item for item, event in latest.items() if event == "evidence_verified"}
