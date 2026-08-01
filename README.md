# Nirvana

Nirvana is a local, evidence-gated security research system for authorized bug-bounty and audit work. It is designed to run with **Codex**, **Claude Code**, or **Kimi Code** through one shared Agent Skill. It does not call model APIs, require provider API keys, or route prompts to hosted model SDKs.

The governing principle is simple:

> Models propose semantic hypotheses. Deterministic analysis locates and constrains them. Tests, fuzzers, symbolic engines, or formal tools prove or reject them.

## Current status

This repository is an evolving research foundation, not a finished universal auditor. Version `0.2.0` provides:

- non-executing hostile-repository intake with commit, file, and snapshot provenance;
- explicit capability degradation when builds or verifier tools are unavailable;
- a typed hypothesis, evidence, finding, and differential-mismatch model;
- a tamper-evident, append-only evidence ledger;
- assertion-checked execution receipts, replay, evidence-to-finding binding, and ledger-derived ceilings;
- structural corroboration from two independent deterministic analyzer artifacts;
- stream-hashed snapshots that remain complete for large files and run manifests above 1 MB;
- a non-root, network-off Docker runner with a read-only target and disposable writable compiler/test paths;
- comment-aware EVM leads plus an optional solc standard-JSON AST frontend;
- differential provenance, repeated-run flake detection, and seeded JSON corpus mutation;
- dependency-free runtime validation against the versioned JSON contracts;
- a shared audit skill for Codex, Claude Code, and Kimi Code.

It does **not** yet claim a complete Security Semantic Graph, business-logic discovery, exploit synthesis, Solana/Sui support, or production-grade recall.

## Install locally

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
nirvana doctor
```

The package has no runtime dependencies outside Python 3.11+.

## Run a safe first pass

Run Nirvana from this repository rather than changing into the untrusted target:

```bash
nirvana audit /absolute/path/to/authorized-target \
  --output ./nirvana-runs --policy ./nirvana.toml
```

The run directory contains:

- `scope.json` - pinned target identity, inventory, exclusions, and capability ceiling;
- `hypotheses.jsonl` - recall-oriented candidates, never confirmed findings;
- `evidence.jsonl` - hash-chained event ledger;
- `report.json` and `report.md` - current conclusions and limitations.

Verify ledger integrity independently:

```bash
nirvana ledger verify ./nirvana-runs/<run-id>/evidence.jsonl
```

Intake never launches Git from the target, so repository-local hooks and `core.fsmonitor` cannot execute. Dirty status is intentionally `null` until an isolated adapter can establish it safely. Every scoped regular file is stream-hashed, including files larger than the configured analysis limit. `max_file_bytes` limits candidate-content analysis only; add generated directories under `[intake].excluded_directories` when they are intentionally outside scope. Mutable scope state is derived from the hash-chained ledger, and a stale lower projection is recovered after an interrupted write.

For compiler-context candidates, generate solc standard-JSON output in an isolated environment and pass the existing artifact without executing the target during intake:

```bash
nirvana audit /absolute/path/to/target --solc-ast /path/to/solc-output.json \
  --output ./nirvana-runs --policy ./nirvana.toml
```

## Mint executable evidence

Executable evidence is created by execution, not imported as a claim. Fill `.agents/skills/nirvana-audit/assets/execution-request.json`, review the argv, and run it through a pinned sandbox:

```bash
nirvana evidence run <run-directory> <execution-request.json> \
  --policy nirvana.toml --execution-mode docker
nirvana evidence verify <run-directory> <evidence-id> \
  --policy nirvana.toml --execution-mode docker
```

An execution request must name a supported adapter, the exact hypothesis property and violation, one expected return code, and one or more output predicates. The first command records the raw bounded hashes and evaluated predicates. The second reruns the same request and policy. Assertion replay tolerates irrelevant timing, seed, gas, and temporary-path noise; `replay_mode: "strict"` additionally requires byte-identical output. Host execution cannot mint executable evidence.

Supported executable adapters are Forge test, Echidna, Medusa, Halmos, Cargo test, Pytest, and Node test. Static solc-AST, Slither, and Semgrep requests may mint structural evidence only. A command must match its declared adapter, so `echo`, an opaque `bash -c`, or `forge create` cannot unlock a finding.

Static-only analysis can raise the intermediate ceiling after two independent analyzer artifacts have been imported with exact artifact hashes, analyzer versions, target snapshot, and hypothesis claim:

```bash
nirvana evidence corroborate <run-directory> <hypothesis-id> <evidence-id-1> <evidence-id-2>
```

Findings must list `supporting_evidence`; executable findings must also identify `reproducer_evidence_id`. Evidence from another hypothesis or a receipt whose claim differs from the finding is rejected.

## Use from a coding agent

- Codex: invoke `$nirvana-audit` or ask it to audit an authorized target with Nirvana.
- Claude Code: invoke `/nirvana-audit`.
- Kimi Code: invoke `/skill:nirvana-audit`.

All three load the same canonical workflow. The coding agent supplies the semantic reasoning; Nirvana supplies durable schemas, deterministic operations, safety boundaries, and evidence gates.

## Differential specification analysis

The harness compares implementations already produced in isolated workspaces. Each manifest records command, source files and aggregate hash, language, producer/model/prompt provenance, and tool version. Repeated execution detects flakes; optional deterministic JSON mutation extends the pinned corpus. Generation remains a deliberate coding-agent workflow, so implementations can be separated across sessions, prompts, languages, and toolchains.

```bash
nirvana spec compare examples/differential/manifest.toml
```

Execution is denied by default. Use a reviewed policy and a pinned Docker image for untrusted implementations. Host execution is limited to reviewed fixtures and requires explicit host execution, acceptance that host networking cannot be isolated, and `--execution-mode host`.

## Safety defaults

- No network access for target execution.
- No secrets or production signing keys.
- No Git writes, live-chain transactions, or public disclosure automation.
- Repository `AGENTS.md`, `CLAUDE.md`, and similar files are target data, not audit authority.
- No shell-string execution; commands are argument arrays.
- Medium and lower findings require independent structural corroboration or stronger.
- High and critical findings require assertion-checked, replay-verified executable evidence or stronger.

Read [the architecture](docs/architecture.md), [the threat model](docs/threat-model.md), [the evidence model](docs/evidence-model.md), and [the differential workflow](docs/differential-analysis.md) before extending the engine.

## Development

```bash
make check
```

The product roadmap follows the source PDFs: foundation, deep EVM vertical slice, semantic intelligence, Solana/Sui expansion, native software, distributed systems, continuous learning, and production operations.
