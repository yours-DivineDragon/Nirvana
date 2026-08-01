# Architecture

The two founding research PDFs are authoritative. This document translates their shared conclusions into an evolving engineering boundary; it is not a substitute for their research, comparisons, or caveats.

## Product thesis

Nirvana is a universal orchestration and representation layer with specialized runtime adapters. It is not a universal prompt. Language-independent concepts such as assets, authority, effects, state, trust, history, and evidence remain common; EVM, Solana, Move, native, JVM, WASM, consensus, and Web/API semantics remain dialect-specific.

The canonical workflow is:

**Ingest -> build -> model -> scope -> hypothesize -> localize -> execute -> disprove -> rescue -> deduplicate -> report -> learn.**

## Architectural layers

| Layer | Contract | Foundation status |
|---|---|---|
| Intake and reproducibility | Pin identity, inventory inputs, detect toolchains, record exclusions | Non-executing identity, scalable manifest, configurable exclusions, and complete stream-hashed snapshot implemented |
| Polyglot frontend | Generic parser through domain-complete runtime dialect | EVM lexical fallback plus supplied solc standard-JSON AST context |
| Security Semantic Graph | Typed syntax, control, data, type, effect, authority, asset, state, trust, history, evidence layers | Schema boundary planned |
| Coverage scheduler | Business-flow x threat-lens work queue | Agent workflow specified |
| Candidate ensemble | Deterministic, graph, logic, attacker, spec, variant, differential, test-gap generators | Contextual EVM candidates; provenance-bound differential fuzz/flake foundation |
| Hypothesis board | Typed shared state rather than agent chat | Ledger-backed imports implemented |
| Verification router | Cheapest suitable static, dynamic, symbolic, formal, differential verifier | Adapter-bound assertions, runner-verified structural corroboration, health-checked candidate-bound negative controls, harness overlays, and strict/semantic replay implemented |
| Evidence ledger | Immutable provenance and artifacts | Hash-chained JSONL implemented |
| Adversarial validation | Devil's Advocate, Rescue Critic, deduplication and novelty | Workflow specified |
| Output and learning | Confirmed report, analyst queue, rejection archive, detector distillation | Initial report and gates implemented |

## Stable boundaries

The serialized contracts in `schemas/` are intended to remain independent of the implementation language and coding-agent host. Python currently implements them because it is available and testable in the development environment. A Rust core may later own graph ingestion, scheduling, and high-throughput analysis behind the same versioned contracts.

No component may infer confidence from model self-assessment. Evidence rank comes from reproducible artifacts and independent verification.

## Support maturity

Every runtime adapter publishes one of five levels:

1. `syntax_only`
2. `typed`
3. `data_flow_capable`
4. `executable`
5. `domain_complete`

Parsing alone never implies security understanding.

## Implementation order

1. Foundation: ledger, schemas, sandbox policy, scheduler boundary, reports.
2. EVM vertical slice: compiler AST, call/data/effect graph, Slither, Foundry, Echidna/Medusa, Halmos, fork reproduction.
3. Semantic intelligence: assets, authority, business flows, inferred specifications, paired critics.
4. Solana and Sui: account/CPI and object/capability dialects with executable tests.
5. Native and distributed systems.
6. Controlled detector distillation, continuous operation, disclosure, and cost governance.
