# Nirvana

Nirvana is a local, evidence-gated security research system for authorized bug-bounty and audit work. It runs with **Codex**, **Claude Code**, or **Kimi Code** through one shared Agent Skill. It does not call model APIs, require provider API keys, or route prompts through hosted model SDKs.

> Models propose semantic hypotheses. Deterministic analysis locates and constrains them. Tests, fuzzers, symbolic engines, or formal tools prove or reject them.

## Current status

Version `0.4.8` implements the complete orchestration skeleton described by the two founding PDFs:

- hostile-repository intake with commit, dependency, submodule, artifact, toolchain, privilege, upgrade, external-dependency, and snapshot provenance;
- opt-in, digest-pinned Docker build/test baselines with hash-bound generated ABI, IDL, bytecode, and build artifacts;
- a versioned Security Semantic Graph (SSG) for modules, entry points, state, assets, authority, effects, invariants, upgrades, dependencies, and trust boundaries;
- an explicit support-maturity record per detected dialect, from `syntax_only` through `domain_complete`;
- a ledger-backed business-flow × threat-lens coverage scheduler;
- deterministic, AST, graph-query, attacker-sequence, specification-inference, historical-variant, test-gap, retrieval-analogy, and differential candidate generators;
- typed hypotheses, Devil's Advocate and Rescue Critic decisions, rejection archives, causal deduplication, and post-validation novelty assessment;
- all six evidence levels: `hypothesis`, `localised`, `structurally_confirmed`, `executable`, `exploit_demonstrated`, and `formally_established`;
- assertion-checked execution receipts, replay, patched-target negative controls, health invariants, and hash-bound auditor harness overlays;
- finding-to-evidence, regression, causal-graph, severity-rationale, and impact bindings;
- differential classification, deterministic seed minimization, spec/test feedback packages, audit-run integration, and private disclosure packets;
- contamination-controlled temporal benchmark evaluation, Magma-style reached/triggered/detected accounting, the eleven source metrics, and explicit release gates;
- regression learning bundles and gated detector-distillation reviews that never modify production rules automatically;
- hash-chained evidence ledgers with exportable prefix checkpoints and pre-reveal benchmark trial seals.

This is still an evolving research system. The generic frontend supplies broad **syntax-level** coverage; it does not pretend that Solana, Move/Sui, native, JVM, WASM, DLT, or Web/API targets are domain-complete. Even the EVM compiler frontend currently publishes `typed`, not complete interprocedural data flow. The generated support record and `nirvana doctor` output are the authority for what a particular run can claim.

## Install locally

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
nirvana doctor
```

The package has no runtime dependencies outside Python 3.11+.

## Create a reproducible run

Run Nirvana from this trusted repository rather than changing into an untrusted target:

```bash
nirvana audit /absolute/path/to/authorized-target \
  --output ./nirvana-runs --policy ./nirvana.toml
```

The run directory contains:

- `scope.json` — pinned target identity, inventory, dependency/toolchain signals, exclusions, and evidence ceiling;
- `semantic-graph.json` — the hash-bound SSG and truthful dialect maturity;
- `coverage-initial.json` — immutable initial flow × threat schedule;
- `coverage.json` — ledger-derived current coverage projection;
- `hypotheses.jsonl` — recall-oriented candidates, never confirmed findings;
- `evidence.jsonl` — the hash-chained event ledger;
- `report.json` and `report.md` — current conclusions, support limits, costs, coverage, rejections, and findings.

Verify ledger integrity and create an independently anchorable prefix checkpoint:

```bash
nirvana ledger verify ./nirvana-runs/<run-id>/evidence.jsonl
nirvana ledger checkpoint ./nirvana-runs/<run-id>/evidence.jsonl \
  --output ledger-checkpoint.json
nirvana ledger verify-checkpoint ./nirvana-runs/<run-id>/evidence.jsonl \
  ledger-checkpoint.json
```

Intake never launches Git from the target, so repository-local hooks and `core.fsmonitor` cannot execute. Dirty state remains unknown unless a future isolated adapter proves it. Every scoped regular file is stream-hashed, including files above the content-analysis limit.

For compiler-context EVM candidates, generate solc standard-JSON output in an isolated environment and pass the existing artifact. The AST is analysis context, not evidence:

```bash
nirvana audit /absolute/path/to/target --solc-ast /path/to/solc-output.json \
  --output ./nirvana-runs --policy ./nirvana.toml
```

## Run the build and test baseline

Intake records safe, argv-native build and test plans but never executes target content automatically. Copy only detected commands into a reviewed `baseline-request.json`; successful exit code `0` is mandatory. Run the baseline in a digest-pinned Docker policy:

```bash
nirvana baseline run <run-directory> baseline-request.json \
  --policy nirvana.toml --execution-mode docker
```

The target stays read-only. Outputs are redirected to an auditor-owned overlay, bounded, stream-hashed, marked non-executable, and referenced by a ledger-bound receipt. Build and test status becomes `passed` or `failed` only after this step.

Captured deployed bytecode must be obtained separately through an authorized process. Nirvana performs an offline comparison and never queries a chain itself:

```bash
nirvana deployment verify <run-directory> deployment-attestation.json
```

## Work the semantic coverage board

`nirvana audit` derives business flows from graph entry points and creates every applicable flow × threat-lens task. Candidate generation is not counted as coverage.

```bash
nirvana coverage list <run-directory>
nirvana coverage mark <run-directory> <task-id> --status in_progress \
  --note "reviewing the authority transition"
nirvana coverage mark <run-directory> <task-id> --status covered \
  --evidence <verified-evidence-id> --reached-node <graph-node-id>
```

A covered task needs replay-verified evidence or a concrete `negative-analysis:` note describing the deterministic basis. The report tracks assets, authority paths, state/effects, trust boundaries, dynamic states, and hypotheses tested.

## Adversarial review, variants, and novelty

Critic decisions are typed ledger events, not chat conclusions:

```bash
nirvana hypothesis critique <run-directory> critic-decision.json
nirvana variant mine <run-directory> known-issues.json --cutoff 2025-01-01T00:00:00Z
nirvana finding novelty <run-directory> <finding-id> known-issues.json
```

The Devil's Advocate may sustain or reject a hypothesis. A separate Rescue Critic may uphold or revive a rejection only with cited evidence or a concrete next experiment. Historical mining produces hypotheses and records corpus provenance; retrieval never counts as evidence. Novelty is assigned only after confirmation by comparing the invariant, root cause, causal graph, prerequisites, exploit sequence, impact, code identity, fix, and lineage.

## Mint evidence

Imported analyst material is capped at `localised`. Stronger evidence is created by execution and successful replay:

```bash
nirvana evidence run <run-directory> execution-request.json \
  --policy nirvana.toml --execution-mode docker
nirvana evidence verify <run-directory> <evidence-id> \
  --policy nirvana.toml --execution-mode docker
```

Structural confirmation requires two distinct replay-verified solc-AST, Slither, or Semgrep adapters for the same claim. Executable and stronger evidence requires a separate patched target whose exact delta touches the candidate code, plus verifier-health invariants that pass on both targets. Put auditor-owned PoCs in a separate symlink-free directory:

```bash
nirvana harness hash /absolute/path/to/auditor-harness
```

The sandbox mounts the harness read-only at `/harness`. Supported dynamic adapters are Forge test, Echidna, Medusa, Halmos, Cargo test, Pytest, and Node test. Adapter-specific outcome classifiers reject build, collection, startup, and infrastructure failures.

`exploit_demonstrated` requests must bind an asset-loss, authority-gain, consensus-failure, or equivalent impact claim to structured JSON assertions. `formally_established` is restricted to Halmos and requires explicit assumptions, a completeness scope, and structured proof decisions. These tiers raise the run ceiling only after replay; they are not aliases for ordinary executable tests.

Confirmed findings require exact supporting evidence IDs, SSG node-based causal paths, severity rationale, and a negative-control-backed regression receipt for executable and stronger work:

```bash
nirvana finding confirm <run-directory> finding.json
```

## Differential specification workflow

Implementations are produced in isolated Codex, Claude Code, or Kimi Code sessions from the same pinned specification; Nirvana calls no model API. The harness records source hashes, commands, languages, producer/model/prompt provenance, versions, repeated-run flakes, deterministic fuzz inputs, raw transcript prefixes, and full-stream hashes.

```bash
nirvana spec compare manifest.toml --policy nirvana.toml \
  --execution-mode docker --output differential-report.json \
  --run-directory <run-directory>
nirvana spec minimize manifest.toml <case-id> --policy nirvana.toml \
  --execution-mode docker --output minimized.json
nirvana spec classify differential-report.json <case-id> implementation_bug \
  --rationale "the pinned conformance case selects implementation A" \
  --output triage.json --run-directory <run-directory>
nirvana spec feedback triage.json minimized.json \
  --spec-amendment "clarify the boundary rule" \
  --regression-test "add the minimized seed" \
  --output feedback.json --run-directory <run-directory>
```

Attached mismatches become `localised` hypotheses in the run ledger; they never self-promote to proof. A private, seven-part coordinated-disclosure packet can be prepared, but Nirvana never sends it:

A differential report is valid only when every scheduled execution is accounted for, at least one output is normalizable, and no execution is blocked, timed out, or flaky. When no implementation produces normalizable output for one input, the report records that case as `unnormalizable` agreement-on-rejection and excludes it from comparison without poisoning the run. When only some implementations normalize, crash-versus-output is retained as a real mismatch. Harness-level failures make the CLI print `INVALID`, exit `2`, and refuse `--run-directory`, `spec attach`, classification, and disclosure. Every imported report has its schedule, case counts, implementation outcomes, and validity re-derived before use; the `valid` field is never trusted by itself. Non-zero returns with normalizable output remain valid observable outcomes. Repeating an attachment for the same valid report is idempotent.

```bash
nirvana disclose prepare differential-report.json triage.json minimized.json \
  agent-context.json --impact "..." --output private-disclosure-packet.json \
  --run-directory <run-directory>
```

## Evaluation and learning

Benchmark manifests pin a cutoff, corpora, last-vulnerable commits, hidden-variant transformation hashes, ground truth, prompts, models, tools, budgets, transcripts, environments, and repeated trials:

```bash
nirvana benchmark hash-target cases/CASE-1/target
nirvana benchmark commit-ground-truth cases/CASE-1/ground-truth.json \
  --output cases/CASE-1/commitment.json
nirvana benchmark verify-pack benchmark-case-pack.json \
  --output benchmark-case-pack-report.json
nirvana benchmark seal-trial ./nirvana-runs/<run-id> \
  --trial-id TRIAL-1 --case-id CASE-1 --seed 1 \
  --output ./nirvana-runs/<run-id>/benchmark-trial-checkpoint.json
nirvana benchmark evaluate benchmark-manifest.json --output benchmark-report.json
```

The report computes validated precision, ground-truth recall, high/critical precision, novel validated yield, time to first valid finding, evidence distribution, reproduction rate, coverage completeness, duplicate rate, calibration, patch correctness, cost efficiency, stability, and reached/triggered/detected counts. It evaluates the PDF's research-prototype, Web3-alpha, closed-beta, production-candidate, and universal-expansion gates against explicit `release_evidence`. Every non-statistical release gate also needs a retained, hash-verified evidence artifact for that gate; booleans alone cannot mint a maturity claim.

Closed beta separates the PDF's 80% overall and 90% High/Critical precision targets from `nirvana-closed-beta-v4` suite qualification. A passing suite also needs at least 20 eligible vulnerable cases, 10 eligible benign controls, three distinct seeds per eligible case, a verified independently authored encrypted case pack, a post-trial reveal matching every pre-trial eligibility/class/label and KLOC commitment, finding IDs bound to that committed ground truth, every trial and complete finding set bound to a sealed hash-chained ledger checkpoint with replay-derived reproduction, regression, novelty, duplicate, timing, and six-dimension coverage state, executable-or-stronger evidence for every High/Critical report, complete novelty adjudication, and complete trial cost accounting. A checkpointed finding cannot be suppressed from precision adjudication. A clean smaller pilot remains valid and keeps its supported metrics, but per-KLOC yield is undefined without an independent size commitment, and novelty yield or duplicate rate is undefined when the relevant checkpointed findings lack novelty assessments. A contaminated manifest, commitment mismatch, invalid finding attribution, or broken ledger binding produces `valid: false`, records every violation in `invalid_reasons`, writes `metrics: null` and `magma: null`, forces every release gate closed, prints the violations, and exits `2`. Without `--output`, the report is written beside the manifest rather than into the caller's current directory. Undefined metrics in a valid report stay undefined rather than being reported as zero. See [blind benchmark operations](docs/benchmarking.md) for case-pack custody, pre-reveal trial sealing, and the pinned executable harness.

Every confirmed finding creates a candidate learning bundle. Promotion requires positive and benign-negative regressions, cross-project generalization, a performance/noise budget, human review, and provenance/license review:

```bash
nirvana learning review <run-directory> detector-review.json
```

This records a promotion decision; it never rewrites production detector source.

## Agent compatibility and safety

- Codex: invoke `$nirvana-audit`.
- Claude Code: invoke `/nirvana-audit`.
- Kimi Code: invoke `/skill:nirvana-audit`.

All three read the same canonical workflow in `.agents/skills/nirvana-audit/`. Safety defaults are no target execution unless explicitly reviewed, no execution network, no secrets, no Git writes, no signing or live-chain transactions, no automatic disclosure, no shell strings, and no target instructions treated as agent authority.

Read [the architecture](docs/architecture.md), [the conformance map](docs/conformance.md), [the threat model](docs/threat-model.md), [the evidence model](docs/evidence-model.md), [the differential workflow](docs/differential-analysis.md), and [the benchmark operations guide](docs/benchmarking.md) before extending the engine.

## Development

```bash
make check
```

The test suite is dependency-free and validates Python compilation, runtime contracts, hostile-input boundaries, graph/coverage state, all evidence tiers, differential integration, critic/novelty behavior, deployment attestations, ledger checkpoints, learning gates, and temporal evaluation.
