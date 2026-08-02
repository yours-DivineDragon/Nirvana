# Source-document conformance

This map records how version 0.4 implements the two founding PDFs and, equally importantly, where a framework exists without domain-complete detector depth. The serialized artifact or ledger event is the acceptance boundary for each row.

## Universal evidence-gated auditor

| Source requirement | Implementation | Acceptance artifact | Remaining maturity limit |
|---|---|---|---|
| Reproducible intake | Metadata-only Git identity, complete stream-hashed inventory, dependency manifests, submodule content snapshots, declared versions, toolchain/framework detection, and exclusions | `scope.json`, `scope_captured` | Dirty state is unknown without an isolated Git adapter |
| Build/test and generated artifacts | Reviewed commands must match intake plans and run in digest-pinned Docker; outputs use a bounded external overlay | `baseline/receipt.json`, `baseline_executed` | No automatic execution of hostile targets; the analyst must approve the request |
| ABI/IDL/bytecode and deployed-code identity | Existing/generated artifacts are hashed; captured deployed bytes are compared offline with compiler-config and capture provenance | `deployment/*.json`, `deployment_bytecode_verified` | Nirvana never fetches chain state; acquisition stays human-controlled |
| Polyglot frontend | Generic bounded index for EVM, Solana, Move/Sui, Rust/native, JVM, WASM, DLT, and Web/API | SSG `support` array, `nirvana doctor` | Non-EVM families are currently syntax-only; no domain-complete claim |
| Security Semantic Graph | Stable nodes and edges for code, state, assets, authority, effects, trust, invariants, upgrades, and dependencies | `semantic-graph.json`, `semantic_graph_created` | Compiler-quality interprocedural data/effect flow is future dialect work |
| Coverage scheduler | Risk-prioritized business flows crossed with nine threat lenses; explicit tracked dimensions | `coverage-initial.json`, `coverage_updated` | A task is not covered until evidence or deterministic negative analysis is recorded |
| Candidate ensemble | Lexical, EVM AST, graph query, attacker sequence, spec inference, test gap, historical variant, retrieval analogy, and differential mismatch | `hypothesis_proposed.generator` | Generators optimize recall and produce no proof; one provenance template yields one historical or retrieval candidate rather than a mirrored pair |
| Hypothesis board | Typed claims, graph slices, assumptions, plans, costs, supporting/contradicting evidence, and status | `hypothesis.schema.json`, ledger | Agent reasoning remains responsible for high-quality property formulation |
| Verification router | Structural, executable, exploit, and formal runner paths with assertion decisions, control health, adapter outcome classification, replay, and auxiliary snapshots | execution receipt v1.5, `evidence_verified`, ceiling events | Real assurance depends on tool availability and a meaningful verifier/control |
| Evidence ladder | Six reachable enum levels; the upper two require structured impact or proof claims | scope ceiling and evidence record | Formal completeness is limited to explicit assumptions/scope |
| Adversarial validation | Typed Devil's Advocate and Rescue decisions with durable rejection/rescue state | `critic_decision`, rejection archive | A critic's rationale is human/agent judgment; cited evidence is separately gated |
| Deduplication and novelty | Post-confirmation causal comparison against a provenance-bearing known-issue corpus | `novelty_assessed`, report dedup list | Corpus completeness determines whether `novel_mechanism` is meaningful |
| Finding contract | Target-bound claim, root cause, locations, prerequisites, assumptions, SSG causal path, reproducer, impact, severity rationale, remediation, regression, evidence IDs | `finding.schema.json`, `finding_confirmed` | Severity still requires expert impact judgment |
| Output and learning | Reports, rejection archive, candidate learning bundle, and six-gate detector review | `learning/*.json`, detector outcome | Production rules are never auto-mutated |
| Efficiency/model routing | Per-hypothesis model cost fields and execution duration accounting; no model APIs | report `cost_accounting`, benchmark metrics | Agent-side token/cost data must be supplied by the agent host |
| Temporal evaluation | Blind cutoff validation, hidden-variant logs, independent encrypted case-pack verification, and archived model/prompt/tool/budget/environment/transcript provenance | benchmark manifest v1.0, case pack/report v1.0, benchmark report v1.3 | Invalid temporal splits set report-level `valid: false`; artifact metrics and Magma results are null, all release gates close, and exit status is nonzero |
| Metrics and release gates | Eleven source metrics, Magma reached/triggered/detected, plus research, Web3-alpha, closed-beta, production, and universal-expansion gates backed by explicit release evidence | `benchmark-report.json` | Valid pilot metrics are distinct from maturity: closed beta also requires the published v1 case-count, benign-control, repeat-seed, independence, actionable-evidence, and accounting floors |
| Ledger anchoring | Hash chain plus portable prefix checkpoints that remain valid after later appends | `ledger-checkpoint.json` | Publishing the checkpoint to an independent trusted store is deployment work |

## Differential specification analysis

| Source requirement | Implementation | Acceptance artifact |
|---|---|---|
| Pinned observable contract | Specification, corpus, manifest, source sets, commands, languages, models/prompts, versions, and runner policy are hashed | differential report v2.2 |
| Independent implementations | Provenance is mandatory for agent-produced implementations | `implementations[]` |
| Proved comparator | JSON/text normalizers have agreement/divergence fixtures | unit tests plus report normalizer |
| Shared and generated cases | Canonical JSONL plus seeded bounded mutation; shortfalls are warnings | case and fuzz counts |
| Repeat/flake detection | Two to twenty runs, observed signatures, stable/flake classification | each outcome plus `flaky_executions` |
| Fail-closed harness validity | Every scheduled run must be accounted for, with at least one normalizable output and no block, timeout, or flake; all-rejection inputs are case-level exclusions and mixed normalization is a mismatch; import gates derive validity from cross-field facts | `valid`, execution/case counts, `unnormalizable_cases`, `invalid_reasons`, CLI exit `2` |
| Four mismatch classes | Durable classification rejects `unclassified` as a final decision | `differential-triage.json` |
| Minimize every seed | Deterministic JSON delta reduction reruns all implementations and refuses flaky cases | `differential-minimization.json` |
| Feed back into prose/tests | Review-only spec amendment and regression corpus case | `differential-feedback.json` |
| Preserve transcripts/provenance | Bounded raw prefixes, full hashes, normalized outputs, commands, source/model provenance | report and attached ledger artifact |
| Feed audit pipeline | Each mismatch becomes a localised hypothesis/evidence record in an existing run | `differential_report_attached`, `H-DIFF-*` |
| Least privilege | argv-only execution, pinned non-root Docker, read-only source, no network/secrets, target instructions as data | policy fingerprint and runner receipt |
| Coordinated disclosure | Private packet includes spec revision, minimized seed, normalized outputs, classification/impact, agent configuration, prompt-injection assessment, and recommended order | `private-disclosure-packet.json`; automatic delivery is false |

## Deliberate non-claims

- A graph node or generated candidate is not a vulnerability.
- Two agreeing implementations do not prove a safe specification.
- A retrieved issue is not evidence for the current target.
- A replayed test is not `exploit_demonstrated` without a machine-checked security effect.
- A bounded symbolic result is not universal proof beyond its recorded assumptions and completeness scope.
- Syntax support is not data-flow, executable, or domain-complete support.
- Passing release thresholds on a fixture is not a product-level benchmark claim.
