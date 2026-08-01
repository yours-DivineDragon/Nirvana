# Evidence promotion

## Ladder

1. `hypothesis`: a pattern or semantic suspicion only.
2. `localised`: exact code and a plausible causal explanation.
3. `structurally_confirmed`: a static path, state transition, or independent deterministic corroboration.
4. `executable`: a compilable failing test, crash, invariant counterexample, or transaction sequence.
5. `exploit_demonstrated`: reproducible asset loss, authority gain, consensus failure, or equivalent effect.
6. `formally_established`: a machine-checked proof or exhaustive bounded counterexample under explicit assumptions.

## Promotion rules

- Promote only when the new artifact itself satisfies the next definition.
- A second model opinion is not independent deterministic corroboration.
- A retrieved historical finding supplies a hypothesis and validation ideas, never proof for this target.
- Code reachability without the trigger is not a detected vulnerability.
- A crash without security impact is not automatically a security finding.
- Fork evidence proves behavior at one pinned state and configuration, not every deployment.
- Economic evidence states liquidity, capital, ordering, oracle, fee, and governance assumptions.
- Store contradicting evidence and rejection reasons alongside supporting evidence.
- Imported evidence records are capped at `localised`. Nirvana must run and replay every structural or executable adapter before it can affect a reporting ceiling.
- Structural confirmation requires two distinct runner-minted and replay-verified solc-AST, Slither, or Semgrep receipts bound to the same snapshot and claim. This tier cannot support high or critical severity.
- A process exit alone is never proof. The request must declare bounded fixed-string or JSON predicates for the specific verifier decision. Unbounded regular-expression assertions are not supported.
- Executable evidence requires a separate patched-target negative control with an exact declared file delta. Nirvana runs the same command and predicates against both targets; a PoC that passes against both is rejected.
- Auditor-owned harnesses remain outside the target, contain no symlinks, are mounted read-only, and are hash-bound into mint and replay receipts.
- Every finding lists its supporting evidence IDs. Executable findings bind a negative-control-verified reproducer ID, and evidence from another hypothesis or claim is rejected.

## Finding gate

Before confirmation, require target commit/configuration, violated property, root cause, locations, prerequisites, assumptions, causal path, minimal reproducer, observable impact, independent reproduction steps, severity rationale, duplicate/variant assessment, remediation, and regression test.
