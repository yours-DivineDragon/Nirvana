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

## Executable provenance

Executable evidence cannot be imported as a self-declared JSON record. `nirvana evidence run` executes a reviewed request through `CommandRunner` in a digest-pinned Docker sandbox and writes a hashed receipt containing the target snapshot, exact argv, working directory, bounded stdin/stdout/stderr, return code, execution mode, and policy fingerprint. Host execution may support reviewed local experiments, but it cannot mint executable evidence. The evidence source is assigned by Nirvana rather than by the request.

Every request binds to the hypothesis security property and suspected violation. It names a supported adapter and checked stdout/stderr predicates (`contains`, `regex`, or `json_pointer_equals`) plus exactly one expected return code. The receipt stores each predicate decision and the raw output hashes. A command whose argv does not match its adapter is rejected.

`nirvana evidence verify` replays that receipt against the same target snapshot and policy. In the default assertion mode, the declared predicates and return code must pass again even when benign timing, seed, gas, or temporary-path text changes. Strict mode additionally requires the original output hashes. Only a successful executable replay raises the run ceiling to `executable`.

Two distinct solc-AST, Slither, or Semgrep artifacts may raise the intermediate ceiling with `nirvana evidence corroborate`. Each imported record must bind its artifact hash, analyzer/version, target snapshot, and exact hypothesis claim. This tier can support medium-and-lower findings under review; it can never satisfy the high/critical executable gate.

The captured scope is also ledger-backed. Direct edits to `scope.json`, including its ceiling, are rejected when they do not correspond to recorded ceiling transitions. Executable verification is refused when any scoped file lacks a complete content hash.

Findings list the exact `supporting_evidence` identifiers. Executable findings also name one `reproducer_evidence_id`. Every identifier must belong to the same hypothesis and claim, and executable support must be replay-verified. This prevents an unrelated successful command from unlocking another claim. The checked predicates establish a declared verifier decision, but the analyst must still validate reachability, attacker prerequisites, severity, and impact.

Ceiling transitions are appended to the ledger before the derived `scope.json` projection is replaced. If the process stops between those operations, the next load repairs a stale lower projection from the ledger. A manifest that claims a higher unledgered ceiling is rejected.

## Evidence ledger

Each JSONL record contains a sequence number, timestamp, previous-record hash, typed payload, and its own SHA-256 hash. Appends verify the complete existing chain before writing. This detects rewriting, deletion, insertion, and reordering within the retained ledger.

The ledger is tamper-evident, not magically immutable: an attacker who can replace the entire ledger and every external checkpoint can create a new chain. Production deployments must periodically anchor ledger heads in an independent trusted store.

## Finding contract

A confirmed finding includes the exact target identity, violated property, root cause, code locations, attacker prerequisites, assumptions, causal path, minimal reproducer, impact, independent reproduction steps, severity rationale, related issues, remediation, and regression test.

Novelty is evaluated only after validation and by root cause, invariant, prerequisites, exploit sequence, impact, fix, code identity, and historical lineage—not textual similarity.
