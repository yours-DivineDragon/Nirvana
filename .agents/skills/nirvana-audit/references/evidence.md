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
- Imported evidence records cannot claim `executable` or stronger. Nirvana must run the reviewed adapter command, capture the bounded output, checked assertions, claim, and target snapshot in a hashed receipt, and replay that receipt under the same policy before it can support confirmation.
- Two imported structural analyzer artifacts may be explicitly corroborated only when their adapters, versions, artifact hashes, target snapshot, and hypothesis claim are independently bound. This tier cannot support high or critical severity.
- A process exit alone is never proof. The request must declare checked predicates for the specific verifier decision. Assertion replay may ignore irrelevant output noise; strict replay additionally compares raw hashes.
- Every finding lists its supporting evidence IDs. Executable findings bind a replay-verified reproducer ID, and evidence from another hypothesis or claim is rejected.

## Finding gate

Before confirmation, require target commit/configuration, violated property, root cause, locations, prerequisites, assumptions, causal path, minimal reproducer, observable impact, independent reproduction steps, severity rationale, duplicate/variant assessment, remediation, and regression test.
