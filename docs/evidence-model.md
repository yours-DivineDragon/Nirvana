# Evidence model

Nirvana separates suspicion from proof.

| Level | Required basis | Treatment |
|---|---|---|
| Hypothesis | Pattern or semantic suspicion | Internal analyst queue only |
| Localised | Exact code and plausible causal explanation | Lead requiring confirmation |
| Structurally confirmed | Static path, state transition, or independent corroboration | Potential finding under review |
| Executable | Compilable failing test, crash, invariant counterexample, or transaction sequence | Reportable after impact review |
| Exploit demonstrated | Reproducible loss, authority gain, consensus failure, or equivalent | High-confidence finding |
| Formally established | Machine-checked proof or exhaustive bounded counterexample | Highest assurance within assumptions |

High and critical findings normally require `executable` evidence or stronger. A cryptographic or design exception must be independently established and document why safe reproduction is impossible.

## Evidence ledger

Each JSONL record contains a sequence number, timestamp, previous-record hash, typed payload, and its own SHA-256 hash. Appends verify the complete existing chain before writing. This detects rewriting, deletion, insertion, and reordering within the retained ledger.

The ledger is tamper-evident, not magically immutable: an attacker who can replace the entire ledger and every external checkpoint can create a new chain. Production deployments must periodically anchor ledger heads in an independent trusted store.

## Finding contract

A confirmed finding includes the exact target identity, violated property, root cause, code locations, attacker prerequisites, assumptions, causal path, minimal reproducer, impact, independent reproduction steps, severity rationale, related issues, remediation, and regression test.

Novelty is evaluated only after validation and by root cause, invariant, prerequisites, exploit sequence, impact, fix, code identity, and historical lineage—not textual similarity.
