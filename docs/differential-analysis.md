# Differential specification analysis

Differential analysis is an ambiguity and divergence detector, not a correctness proof.

## Required independence

Produce implementations in isolated workspaces. Prevent them from reading one another. Diversify model session, prompt, language, libraries, and toolchain when possible. Nirvana does not call any model API; the human starts separate Codex, Claude Code, or Kimi Code sessions and supplies the same pinned specification.

## Harness workflow

1. Pin the specification revision and canonical tests.
2. Define one deterministic input/output protocol for every implementation.
3. Normalize only documented benign differences.
4. Prove the comparator with agreement and intentional-divergence fixtures.
5. Run canonical, boundary, malformed, historical, metamorphic, and fuzz-generated cases.
6. Minimize every stable divergent seed.
7. Preserve inputs, normalized outputs, full output hashes, bounded raw transcript prefixes, implementation source-set hashes, commands, languages, producer/model/prompt provenance, tool versions, and runner policy.
8. Classify only after ruling out harness defects.
9. Produce a reviewed prose-and-test feedback package.
10. Attach the mismatch to an audit run when it may represent a security property violation.

## Mismatch classes

| Class | Meaning |
|---|---|
| Harness bug | Execution, normalization, or comparison is wrong |
| Implementation bug | At least one implementation violates explicit intended behavior |
| Specification ambiguity | More than one interpretation is reasonable |
| Clear but unsafe specification | Implementations agree with an unambiguous but insecure design |

Agreement raises confidence but never establishes correctness. The final class requires design review, adversarial invariants, or formalization rather than more differential voting.

Classification is durable rather than an in-place edit of the original report:

```bash
nirvana spec classify differential-report.json <case-id> spec_ambiguity \
  --rationale "both readings are compatible with the pinned prose" \
  --output triage.json --run-directory <run-directory>
```

The manifest's `[analysis]` table controls deterministic repeated runs and seeded JSON mutations. `repetitions` is at least two so the report can flag per-implementation flakes. `fuzz_cases` extends, but never replaces, the canonical JSONL corpus. Every generated case has a stable ID derived from its canonical input and `fuzz_seed`. Reports record both requested and generated fuzz counts and emit a warning when the finite mutation space cannot satisfy the requested budget.

## Minimize and feed back

The minimizer reruns all implementations after every deterministic JSON reduction. It refuses non-divergent and flaky inputs rather than manufacturing a smaller-looking artifact.

```bash
nirvana spec minimize manifest.toml <case-id> --policy nirvana.toml \
  --execution-mode docker --output minimized.json
nirvana spec feedback triage.json minimized.json \
  --spec-amendment "state the boundary behavior explicitly" \
  --regression-test "add the minimized input to the canonical corpus" \
  --output feedback.json --run-directory <run-directory>
```

The feedback artifact is a proposal. Nirvana never changes the specification or conformance corpus without human review.

## Audit-pipeline integration

`nirvana spec compare ... --run-directory <run>` or `nirvana spec attach` copies the report into the audit run, hashes it into the ledger, and emits one `H-DIFF-*` hypothesis plus localised evidence per mismatch. The hypothesis explicitly retains comparator correctness, implementation independence, specification intent, and security impact as unresolved assumptions. A differential report cannot raise the evidence ceiling.

If review establishes a security-relevant implementation bug, ambiguity, or clear-but-unsafe specification, prepare a private packet:

```bash
nirvana disclose prepare differential-report.json triage.json minimized.json \
  agent-context.json --impact "security consequence and affected users" \
  --output private-disclosure-packet.json --run-directory <run-directory>
```

The packet preserves the pinned spec, minimized seed, normalized outputs, classification and impact, agent/tool configuration, prompt-injection assessment, and recommended coordination order. `automatic_delivery` is always false.

## Execution boundary

The CLI accepts commands only as arrays and uses `shell=False`. Opaque shell command strings and target-context Git are blocked. Execution is denied by default. Untrusted generated implementations should run in a pinned, read-only Docker sandbox with network disabled, no secrets, dropped capabilities, bounded memory/processes, and disposable writable tool storage. Host execution is for locally authored reviewed fixtures only; because Nirvana cannot isolate host networking, it requires `allow_host_execution = true` and the separate `accept_host_network_risk = true`. This acknowledgement does not require or enable `allow_network` in Docker.
