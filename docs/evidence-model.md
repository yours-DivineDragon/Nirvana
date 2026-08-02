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

High and critical findings normally require `executable` evidence or stronger. `exploit_demonstrated` is reserved for a machine-checked asset loss, authority gain, consensus failure, or equivalent security effect. `formally_established` requires an explicit machine-checked property, assumptions, and completeness scope. A cryptographic or design exception must be independently established and document why safe reproduction is impossible.

## Executable provenance

Executable evidence cannot be imported as a self-declared JSON record. `nirvana evidence run` executes a reviewed request through `CommandRunner` in a digest-pinned Docker sandbox and writes a hashed receipt containing the target snapshot, exact argv, working directory, bounded stdin/stdout/stderr, return code, execution mode, and policy fingerprint. Host execution may support reviewed local experiments, but it cannot mint executable evidence. The evidence source is assigned by Nirvana rather than by the request.

Every request binds to the hypothesis security property and suspected violation. It names a supported adapter and checked stdout/stderr predicates (`contains` or `json_pointer_equals`) plus exactly one expected return code. A JSON predicate accepts either a stream containing exactly one JSON document or exactly one line prefixed `NIRVANA_RESULT_JSON=` amid normal runner output; duplicate marker lines are rejected. This lets pytest, Forge, and symbolic summaries coexist with a harness-owned structured decision. Regular-expression predicates are deliberately unsupported because target-controlled output can trigger unbounded backtracking. The receipt stores each predicate decision and the raw output hashes. A command whose argv does not match its adapter, or names a path instead of a sandbox-resolved tool, is rejected.

Executable requests include a patched-target negative control. Its file delta must exactly match the request and touch at least one path in the hypothesis's `candidate_locations`. Nirvana runs the same adapter, argv, stdin, exploit predicates, and `control_invariants` against both targets. The original target must satisfy every exploit predicate and health invariant; the patched target must return the declared control code, retain every health invariant, and fail at least one exploit predicate. Both decision vectors are captured and replayed. A trivial PoC that passes against both targets, or a control that merely breaks compilation, collection, startup, or the verifier harness, cannot raise the ceiling.

Non-zero outcomes are adapter-classified rather than trusted from the request, and the versioned adapter contract ID is recorded in the receipt and rechecked on replay. Pytest uses `0`/`1`; Forge uses `0`/`1` and requires a completed failing-suite summary for `1`; Cargo uses `0`/`101`, requires `--message-format=json`, and accepts `101` only when Cargo reports a successful build followed by failed tests; native `node --test` uses `0`/`1` with TAP output, while ambiguous non-zero npm/pnpm/yarn wrapper results are refused; Echidna uses `0`/`1` with `--format=json`; Medusa uses its dedicated `0`/`7` success/test-failure codes; and Halmos uses `0`/`1` with a completed symbolic-test summary. Other exit states are infrastructure outcomes, not evidence.

Every executable request should include a baseline test unrelated to the PoC and assert its exact success marker in `control_invariants` on both targets. Also assert compilation and test discovery when those signals are separate. A marker such as `collected 1 item`, `Suite result:`, or “the verifier started” is insufficient by itself: a crashing PoC can emit it before failing. Prefer a named baseline test plus a stable completed-suite count or structured summary.

Auditor-owned PoCs may live outside both targets. A symlink-free harness is stream-hashed, mounted read-only at `/harness`, and bound into the original and replay receipts. Target, control, and harness snapshots are rechecked before finding confirmation.

`nirvana evidence verify` replays the receipt against the same targets, harness, and policy. In the default assertion mode, the declared decisions must repeat even when benign timing, seed, gas, or temporary-path text changes. Strict mode additionally requires the original output hashes. A successful replay raises the ceiling to the receipt's exact level.

For `exploit_demonstrated`, the request's `impact` object names the effect category, affected asset, description, and the structured JSON assertion IDs that establish it. Fixed-string output cannot carry this tier. For `formally_established`, the Halmos adapter requires a `formal` object containing the property, explicit assumptions, completeness scope, and structured proof assertion IDs. A bounded counterexample is formally established only inside that stated scope; the label does not imply an unbounded theorem.

Imported records are capped at `localised`. Two distinct solc-AST, Slither, or Semgrep executions may raise the intermediate ceiling only after Nirvana mints and replay-verifies both receipts against the same target and claim. This tier can support medium-and-lower findings under review; it can never satisfy the high/critical executable gate.

The captured scope is also ledger-backed. Direct edits to `scope.json`, including its ceiling, are rejected when they do not correspond to recorded ceiling transitions. Executable verification is refused when any scoped file lacks a complete content hash.

Findings list the exact `supporting_evidence` identifiers. Executable and stronger findings also name a `reproducer_evidence_id` and a `regression_evidence_id`; both must be replay-verified and negative-control-backed. Every identifier must belong to the same hypothesis and claim. The finding's causal path must reference nodes in the ledger-bound SSG, intersect the hypothesis graph slice, and follow directed SSG edges between consecutive graph nodes. This prevents an unrelated command, regression, or disconnected narrative path from unlocking another claim. The checked predicates establish a declared verifier decision, but the analyst must still validate reachability, attacker prerequisites, severity, and impact.

Ceiling transitions are appended to the ledger before the derived `scope.json` projection is replaced. If the process stops between those operations, the next load repairs a stale lower projection from the ledger. A manifest that claims a higher unledgered ceiling is rejected.

## Evidence ledger

Each JSONL record contains a sequence number, timestamp, previous-record hash, typed payload, and its own SHA-256 hash. Appends verify the complete existing chain before writing. This detects rewriting, deletion, insertion, and reordering within the retained ledger.

The ledger is tamper-evident, not magically immutable: an attacker who can replace the entire ledger and every external checkpoint can create a new chain. `nirvana ledger checkpoint` exports a signed-data-ready prefix head, and `verify-checkpoint` proves that prefix even after later appends. Production deployments must periodically publish those checkpoints to an independent trusted store; Nirvana deliberately does not choose or contact that store.

Blind benchmark runs add a typed `benchmark_trial_sealed` boundary before reveal. The seal is derived from the full confirmed-finding set and binds trial, case, run, seed, severity, evidence tier, reproduction/regression state, novelty classification and corpus hash, exact-duplicate/novel decisions, ledger-derived time-to-finding, and the canonical six-dimension coverage projection reconstructed from the initial schedule and coverage events. `nirvana benchmark seal-trial` appends it only after the run is complete and every supporting evidence record is replay-verified, then exports the checkpoint named by the benchmark manifest. Evaluation rechecks the seal, the checkpoint prefix, the current ledger's later replay status, coverage schedule and events, and a one-to-one manifest finding set. The seal does not replace independent publication of the checkpoint hash.

## Finding contract

A confirmed finding includes the exact target identity, violated property, root cause, code locations, attacker prerequisites, assumptions, causal path, minimal reproducer, impact, independent reproduction steps, severity rationale, related issues, remediation, and regression test.

Novelty is evaluated only after validation and by root cause, invariant, prerequisites, exploit sequence, impact, fix, code identity, and historical lineage—not textual similarity. Every confirmed finding also creates a candidate learning bundle. A separate review can promote the candidate only after positive and benign-negative regressions, cross-project generalization, a performance/noise budget, human review, and provenance/license review; promotion records a decision and never edits production detector source.
