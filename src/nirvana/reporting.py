from __future__ import annotations

from typing import Any

from .intake import ScopeManifest
from .models import Finding, Hypothesis


def render_audit_report(
    scope: ScopeManifest,
    hypotheses: list[Hypothesis],
    findings: list[Finding],
    run_id: str,
    graph_summary: dict[str, Any] | None = None,
    coverage: dict[str, Any] | None = None,
    baseline: dict[str, Any] | None = None,
    novelty_assessments: dict[str, dict[str, Any]] | None = None,
    rejection_archive: list[dict[str, Any]] | None = None,
    deduplicated_findings: list[str] | None = None,
    cost_accounting: dict[str, Any] | None = None,
) -> str:
    confirmed_hypotheses = {finding.hypothesis_id for finding in findings}
    queued_hypotheses = [
        hypothesis
        for hypothesis in hypotheses
        if hypothesis.hypothesis_id not in confirmed_hypotheses
        and hypothesis.status.value != "rejected"
    ]
    lines = [
        "# Nirvana audit run",
        "",
        f"- Run: `{run_id}`",
        f"- Target: `{scope.target_root}`",
        f"- Commit: `{scope.repository_commit or 'not-a-git-commit'}`",
        f"- Target snapshot: `{scope.target_snapshot_sha256}`",
        f"- Snapshot complete: `{str(scope.snapshot_complete).lower()}`",
        f"- Dirty state: `{'unknown' if scope.repository_dirty is None else str(scope.repository_dirty).lower()}`",
        f"- Build: `{baseline.get('build_status', scope.build_status) if baseline else scope.build_status}`",
        f"- Tests: `{baseline.get('test_status', scope.test_status) if baseline else scope.test_status}`",
        f"- Evidence ceiling: `{scope.evidence_ceiling.value}`",
        f"- Confirmed findings: **{len(findings)}**",
        f"- Unconfirmed hypotheses: **{len(queued_hypotheses)}**",
        "",
        "> Confirmed findings require structural corroboration; high and critical findings require executable evidence.",
        "",
        "## Scope",
        "",
        f"Inventoried {len(scope.files)} files. Detected toolchains: "
        + (", ".join(scope.toolchains) if scope.toolchains else "none"),
        "",
    ]
    lines.extend(
        [
            "### Intake signals",
            "",
            f"- Dependency manifests: **{len(scope.dependency_manifests)}**",
            f"- Declared compiler/runtime constraints: **{sum(len(item) for item in scope.declared_tool_versions.values())}**",
            f"- Declared submodules with content snapshots: **{len(scope.submodules)}**",
            f"- Existing ABI/IDL/bytecode/deployment artefacts: **{len(scope.discovered_artifacts)}**",
            f"- Privileged-identity leads: **{len(scope.privileged_identities)}**",
            f"- Upgrade-path leads: **{len(scope.upgrade_mechanisms)}**",
            f"- External-dependency leads: **{len(scope.external_dependencies)}**",
            f"- Local source/deployed-bytecode attestations: **{len(scope.deployment_matches)}**",
            "",
        ]
    )
    if scope.untrusted_instruction_surfaces:
        lines.extend(
            [
                "### Untrusted repository guidance",
                "",
                "The following files were recorded as target data, not agent authority:",
                "",
                *[f"- `{path}`" for path in scope.untrusted_instruction_surfaces],
                "",
            ]
        )
    if graph_summary is not None:
        lines.extend(
            [
                "## Security Semantic Graph",
                "",
                f"- Nodes: **{graph_summary['node_count']}**",
                f"- Edges: **{graph_summary['edge_count']}**",
                f"- Artifact: `{graph_summary['artifact_sha256']}`",
                "- Published dialect maturity:",
                *[
                    f"  - `{item['dialect']}`: `{item['maturity']}` — "
                    + "; ".join(item.get("limitations", []))
                    for item in graph_summary.get("support", [])
                ],
                *[f"- Warning: {item}" for item in graph_summary.get("warnings", [])],
                "",
            ]
        )
    if coverage is not None:
        completeness = coverage.get("completeness", {})
        lines.extend(
            [
                "## Coverage schedule",
                "",
                f"- Business flows: **{len(coverage.get('flows', []))}**",
                f"- Flow × threat tasks: **{len(coverage.get('tasks', []))}**",
                f"- Covered tasks: **{sum(item.get('status') == 'covered' for item in coverage.get('tasks', []))}**",
                f"- Task completeness: **{float(completeness.get('flow_threat_tasks', 0.0)):.1%}**",
                "",
                "Uncovered tasks remain explicit gaps; candidate generation does not count as coverage.",
                "",
            ]
        )
    if cost_accounting is not None:
        lines.extend(
            [
                "## Cost accounting",
                "",
                f"- Verification execution: **{cost_accounting.get('verification_execution_ms', 0)} ms**",
                f"- Model cost units recorded: **{cost_accounting.get('model_cost_units', 0)}**",
                f"- Model-cost coverage complete: `{str(cost_accounting.get('model_cost_complete', False)).lower()}`",
                "",
            ]
        )
    lines.extend(["## Confirmed findings", ""])
    if not findings:
        lines.extend(["No finding has crossed the confirmation gate.", ""])
    for finding in findings:
        lines.extend(
            [
                f"### {finding.finding_id}: {finding.title}",
                "",
                f"- Severity: `{finding.severity.value}`",
                f"- Evidence: `{finding.evidence_level.value}`",
                f"- Hypothesis: `{finding.hypothesis_id}`",
                f"- Root cause: {finding.root_cause}",
                f"- Impact: {finding.impact}",
                f"- Severity rationale: {finding.severity_rationale}",
                f"- Reproducer: `{finding.reproducer}`",
                f"- Supporting evidence: `{', '.join(finding.supporting_evidence)}`",
                f"- Novelty: `{(novelty_assessments or {}).get(finding.finding_id, {}).get('classification', 'unassessed')}`",
                "",
            ]
        )
    if deduplicated_findings:
        lines.extend(
            [
                "### Deduplicated validated findings",
                "",
                *[f"- `{finding_id}` — exact root-cause duplicate" for finding_id in deduplicated_findings],
                "",
            ]
        )
    lines.extend(["## Analyst queue", ""])
    if not queued_hypotheses:
        lines.extend(["No unconfirmed hypotheses remain.", ""])
    for hypothesis in queued_hypotheses:
        location = hypothesis.candidate_locations[0]
        lines.extend(
            [
                f"### {hypothesis.hypothesis_id}: {hypothesis.threat_lens}",
                "",
                f"- Status: `{hypothesis.status.value}`",
                f"- Evidence: `{hypothesis.evidence_level.value}`",
                f"- Generator: `{hypothesis.generator}`",
                f"- Location: `{location.path}:{location.line_start}`",
                f"- Property: {hypothesis.security_property}",
                f"- Suspicion: {hypothesis.suspected_violation}",
                "- Next verification:",
                *[f"  - {step}" for step in hypothesis.verification_plan],
                "",
            ]
        )
    lines.extend(["## Rejection and rescue archive", ""])
    if not rejection_archive:
        lines.extend(["No hypothesis is currently rejected.", ""])
    else:
        for item in rejection_archive:
            lines.extend(
                [
                    f"### {item['hypothesis_id']}",
                    "",
                    f"- Last decision: `{item['last_decision']}`",
                    *[f"- Reason: {reason}" for reason in item.get("reasons", [])],
                    "",
                ]
            )
    lines.extend(
        [
            "## Limitations",
            "",
            "This foundation run performs reproducible intake and recall-oriented candidate generation. "
            "It does not claim exploitability, severity, novelty, or protocol correctness without independent evidence.",
            "",
        ]
    )
    return "\n".join(lines)
