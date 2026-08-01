# Differential specification workflow

## Prepare independent interpretations

1. Pin one specification revision and canonical conformance suite.
2. Create each implementation in a separate session and workspace.
3. Prevent implementations from reading one another.
4. Record producer, model and prompt hash when agent-generated, language, source-set hash, command, libraries, tool version, and commit. Diversity reduces but does not eliminate correlated error.
5. Do not call model APIs from Nirvana; start Codex, Claude Code, or Kimi Code directly.

## Build the comparator

Each implementation reads one JSON value from stdin and emits one JSON value to stdout. Put each case in JSONL as `{"id":"...","input":...}`. Configure implementations as command arrays in TOML.

Prove normalization separately. Normalize only behavior the specification declares irrelevant. Preserve reverts/errors, return codes, and exact raw-output hashes.

Set at least two repeated runs per implementation so flakes are not mistaken for semantic divergence. Use a fixed `fuzz_seed` and bounded `fuzz_cases` for deterministic JSON mutation; preserve the canonical corpus separately.

The report is valid only when every scheduled execution runs to completion and produces normalizable output. Blocked, timed-out, or unnormalizable executions invalidate agreement and mismatch counts. Import gates re-derive the schedule and validity from cross-field execution facts and reject a self-declared `valid` value that conflicts with them. A non-zero return with a valid normalized output remains part of the observable contract and may itself be the divergence. Preserve invalid reports for diagnosis, but do not attach, classify, or disclose them.

## Generate cases

- Canonical examples and exact error cases
- Zero, one, maximum, minimum, and off-by-one thresholds
- Rounding, precision, overflow, coercion, and canonicalization boundaries
- Malformed, reordered, duplicated, truncated, and unknown fields
- Historical incident and regression seeds
- Metamorphic properties such as encode/decode, normalize/replay, and signer/verifier agreement
- Coverage-guided or property-based mutations when a safe sandbox exists

## Classify divergences

Use exactly one provisional class:

- `harness_bug`
- `implementation_bug`
- `spec_ambiguity`
- `clear_but_unsafe_spec`

Keep `unclassified` until the comparator, environment, and input are reproduced. Minimize the seed and add a regression test. Patch prose and tests together for ambiguity. Agreement cannot rule out a clear but unsafe design.
