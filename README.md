# Nirvana

Nirvana is a local, evidence-gated security research system for authorized bug-bounty and audit work. It is designed to run with **Codex**, **Claude Code**, or **Kimi Code** through one shared Agent Skill. It does not call model APIs, require provider API keys, or route prompts to hosted model SDKs.

The governing principle is simple:

> Models propose semantic hypotheses. Deterministic analysis locates and constrains them. Tests, fuzzers, symbolic engines, or formal tools prove or reject them.

## Current status

This repository is an initial research foundation, not a finished universal auditor. Version `0.1.1` provides:

- non-executing hostile-repository intake with commit, file, and snapshot provenance;
- explicit capability degradation when builds or verifier tools are unavailable;
- a typed hypothesis, evidence, finding, and differential-mismatch model;
- a tamper-evident, append-only evidence ledger;
- runner-minted execution receipts, matching replay, and enforced reporting ceilings;
- comment-aware deterministic EVM candidate generation;
- a differential harness for comparing existing independent implementations;
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
nirvana audit /absolute/path/to/authorized-target --output ./nirvana-runs
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

Intake never launches Git from the target, so repository-local hooks and `core.fsmonitor` cannot execute. Dirty status is intentionally `null` until an isolated adapter can establish it safely. The target snapshot covers every inventoried file and executable verification is refused when that snapshot is incomplete. Mutable scope state is checked against the hash-chained ledger.

## Mint executable evidence

Executable evidence is created by execution, not imported as a claim. Fill `.agents/skills/nirvana-audit/assets/execution-request.json`, review the argv, and run it through a pinned sandbox:

```bash
nirvana evidence run <run-directory> <execution-request.json> \
  --policy nirvana.toml --execution-mode docker
nirvana evidence verify <run-directory> <evidence-id> \
  --policy nirvana.toml --execution-mode docker
```

The first command captures a hashed execution receipt. The second replays it using the same policy and target snapshot. Confirmation remains blocked until the replay matches and raises the run ceiling. Host execution cannot mint executable evidence.

## Use from a coding agent

- Codex: invoke `$nirvana-audit` or ask it to audit an authorized target with Nirvana.
- Claude Code: invoke `/nirvana-audit`.
- Kimi Code: invoke `/skill:nirvana-audit`.

All three load the same canonical workflow. The coding agent supplies the semantic reasoning; Nirvana supplies durable schemas, deterministic operations, safety boundaries, and evidence gates.

## Differential specification analysis

The harness compares implementations already produced in isolated workspaces. Generation remains a deliberate coding-agent workflow, so implementations can be separated across sessions, prompts, languages, and toolchains.

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
- High and critical findings require executable evidence or stronger.

Read [the architecture](docs/architecture.md), [the threat model](docs/threat-model.md), [the evidence model](docs/evidence-model.md), and [the differential workflow](docs/differential-analysis.md) before extending the engine.

## Development

```bash
make check
```

The product roadmap follows the source PDFs: foundation, deep EVM vertical slice, semantic intelligence, Solana/Sui expansion, native software, distributed systems, continuous learning, and production operations.
