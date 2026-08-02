# Architecture

The two founding research PDFs are authoritative. This document maps their common design to executable boundaries; it does not replace their research or imply that every dialect has equal semantic depth.

## Product thesis

Nirvana is a universal orchestration and representation layer with specialized runtime adapters. It is not a universal prompt. Assets, authority, effects, state, trust, history, coverage, and evidence share common contracts; EVM, Solana, Move/Sui, native, JVM, WASM, DLT, and Web/API semantics remain dialect-specific.

The canonical loop is:

**ingest → baseline → model → schedule → hypothesize → localize → execute → disprove → rescue → deduplicate → report → learn → evaluate**

Every mutable conclusion is an append-only ledger event. JSON artifacts are projections or immutable, hash-bound inputs.

## Architectural layers

| Layer | Executable contract | Version 0.4 status |
|---|---|---|
| Intake and reproducibility | Pin identity, files, dependencies, submodules, tools, exclusions, artifacts, authority/upgrades/dependencies, build/test plans, deployment attestations | Implemented; execution remains an explicit reviewed Docker step |
| Polyglot frontend | Publish a maturity level and limitations for every detected dialect | Generic bounded syntax frontend for all named families; supplied EVM AST raises EVM to `typed` |
| Security Semantic Graph | Typed nodes/edges for syntax, call, state, asset, authority, effects, invariants, upgrades, dependencies, and trust | Versioned, hash-bound SSG implemented; syntax-derived edges remain explicitly unsound until corroborated |
| Coverage scheduler | Risk-prioritized business-flow × threat-lens work queue and tracked completeness | Ledger-backed schedule and coverage updates implemented |
| Candidate ensemble | Deterministic, AST, graph, attacker, spec-inference, variant, differential, test-gap, and retrieval generators | Implemented as hypothesis generators; none self-promote to evidence |
| Hypothesis board | Typed state, assumptions, graph slices, costs, supporting and contradicting evidence | Ledger-backed board implemented |
| Verification router | Cheapest suitable structural, dynamic, fuzz, symbolic, exploit, or formal evaluator | Adapter-bound execution, negative controls, assertions, health invariants, replay, harness overlays, and all six levels implemented |
| Evidence ledger | Immutable provenance, receipts, artifacts, and independently anchorable heads | Hash-chained JSONL plus prefix checkpoints implemented; external storage remains an operator responsibility |
| Adversarial validation | Devil's Advocate, Rescue Critic, rejection archive, causal deduplication, novelty | Typed ledger workflows implemented |
| Differential loop | Compare, repeat, fuzz, classify, minimize, feed back, attach, disclose | Implemented; mismatch attachments are `localised` leads only |
| Output and learning | Confirmed report, analyst queue, rejection archive, learning bundle, detector promotion gates | Implemented; detector source is never changed automatically |
| Evaluation | Temporal split, independent encrypted case packs, canonical ground-truth reveal commitments, committed finding attribution, sealed ledger-bound trials, hidden variants, Magma signals, eleven metrics, and sample-qualified release gates | Dependency-free evaluator implemented; claims still require real blind benchmark data beyond the shipped templates |

## Security Semantic Graph

The SSG is language-neutral at the storage layer and dialect-specific at ingestion. Nodes represent modules, symbols/entry points, state, assets, authority, effects, trust boundaries, invariants, upgrades, and external dependencies. Edges represent containment, calls, reads/writes/transfers, guards, authority, upgrades, trust crossings, dependencies, constraints, and reachability.

Stable node IDs bind hypotheses, coverage updates, causal finding paths, variant templates, and learning candidates. A lexical edge is labelled syntax-only; it does not become a sound call/data-flow edge because it is stored in a graph. Compiler or runtime evidence must establish stronger semantics.

## State and trust boundaries

```text
target bytes ──hash──> scope ──ledger──> graph ──hash──> coverage schedule
                               │                     │
                               ├──> hypotheses <─────┘
                               │        │
                               │        ├── critics / variants / differential leads
                               │        └── runner-minted evidence + replay
                               │                         │
                               └─────────────────────────┴──> confirmed finding
                                                             │
                                                             ├── novelty/dedup
                                                             └── learning bundle
```

Target content, retrieved corpora, compiler artifacts, generated implementations, and tool output are untrusted. Their hashes and provenance are facts; their instructions and self-asserted conclusions are not authority.

## Support maturity

Every detected dialect publishes exactly one level:

1. `syntax_only`
2. `typed`
3. `data_flow_capable`
4. `executable`
5. `domain_complete`

The support record lists frontends, available runtime adapters, modeled concepts, and limitations. Maturity is not inferred from file extensions alone, and runtime evidence is still established per run. Version 0.4's generic frontend is `syntax_only`; a supplied, hash-bound solc AST raises EVM to `typed`. No bundled dialect currently claims `domain_complete`.

## Stable boundaries

Serialized contracts in `schemas/` remain independent of implementation language and coding-agent host. Python implements the current core because it is dependency-free and testable. A future Rust core can replace graph ingestion, scheduling, and high-throughput analysis without changing the contracts.

No component may infer confidence from model self-assessment, majority voting, retrieval similarity, or a process exit alone. Evidence rank comes from a runner-minted artifact, adapter decision contract, target/control behavior, and successful replay. Benchmark claims come from contamination-controlled manifests, not README assertions.
