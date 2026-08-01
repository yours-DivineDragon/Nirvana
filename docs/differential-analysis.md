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
6. Minimize every divergent seed.
7. Preserve inputs, normalized outputs, implementation source-set hashes, commands, languages, producer/model/prompt provenance, tool versions, and transcripts.
8. Classify only after ruling out harness defects.

## Mismatch classes

| Class | Meaning |
|---|---|
| Harness bug | Execution, normalization, or comparison is wrong |
| Implementation bug | At least one implementation violates explicit intended behavior |
| Specification ambiguity | More than one interpretation is reasonable |
| Clear but unsafe specification | Implementations agree with an unambiguous but insecure design |

Agreement raises confidence but never establishes correctness. The final class requires design review, adversarial invariants, or formalization rather than more differential voting.

The manifest's `[analysis]` table controls deterministic repeated runs and seeded JSON mutations. `repetitions` is at least two so the report can flag per-implementation flakes. `fuzz_cases` extends, but never replaces, the canonical JSONL corpus. Every generated case has a stable ID derived from its canonical input and `fuzz_seed`.

## Execution boundary

The CLI accepts commands only as arrays and uses `shell=False`. Opaque shell command strings and target-context Git are blocked. Execution is denied by default. Untrusted generated implementations should run in a pinned, read-only Docker sandbox with network disabled, no secrets, dropped capabilities, bounded memory/processes, and disposable writable tool storage. Host execution is for reviewed fixtures only; because Nirvana cannot isolate host networking, it requires explicit host execution and network acceptance in addition to the mode selection.
