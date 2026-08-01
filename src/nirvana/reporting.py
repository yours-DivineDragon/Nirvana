from __future__ import annotations

from .intake import ScopeManifest
from .models import Finding, Hypothesis


def render_audit_report(
    scope: ScopeManifest,
    hypotheses: list[Hypothesis],
    findings: list[Finding],
    run_id: str,
) -> str:
    confirmed_hypotheses = {finding.hypothesis_id for finding in findings}
    queued_hypotheses = [
        hypothesis for hypothesis in hypotheses if hypothesis.hypothesis_id not in confirmed_hypotheses
    ]
    lines = [
        "# Nirvana audit run",
        "",
        f"- Run: `{run_id}`",
        f"- Target: `{scope.target_root}`",
        f"- Commit: `{scope.repository_commit or 'not-a-git-commit'}`",
        f"- Build: `{scope.build_status}`",
        f"- Evidence ceiling: `{scope.evidence_ceiling.value}`",
        f"- Confirmed findings: **{len(findings)}**",
        f"- Unconfirmed hypotheses: **{len(queued_hypotheses)}**",
        "",
        "> No candidate below the executable evidence gate is presented as a confirmed vulnerability.",
        "",
        "## Scope",
        "",
        f"Inventoried {len(scope.files)} files. Detected toolchains: "
        + (", ".join(scope.toolchains) if scope.toolchains else "none"),
        "",
    ]
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
                f"- Reproducer: `{finding.reproducer}`",
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
