# Threat model

Nirvana assumes the audit target is controlled by an adversary attempting to influence the coding agent or execution environment.

## Protected assets

- Host credentials, signing keys, wallets, source repositories, and personal files
- Integrity of scopes, hypotheses, evidence, reports, benchmarks, and detector rules
- Confidentiality of undisclosed findings and target materials
- Availability of the analyst workstation and verifier infrastructure

## Primary threats

| Threat | Default control |
|---|---|
| Prompt injection in comments, docs, issues, or agent files | Treat target content as data; run from trusted Nirvana root |
| Malicious build/test scripts | Deny execution or use pinned network-off read-only sandbox |
| Generated artifact escape or executable smuggling | Dedicated external overlay, path separation, symlink rejection, file/byte limits, hashes, and `trusted_for_execution: false` |
| Secret exfiltration | Empty/minimal environment; no secret forwarding; no egress |
| Generated command injection | Argument arrays and `shell=False` |
| Live-chain harm | No production RPC credentials, signing, or broadcasts |
| Irrelevant command unlocks a finding | Adapter/argv contract, checked claim predicates, explicit supporting evidence IDs, and hypothesis binding |
| False high-severity report | Paired target/control receipts, shared health invariants, candidate-bound control deltas, assertion replay, executable ceiling, and adversarial review |
| Precision collapse | Devil's Advocate validation and semantic deduplication |
| Recall collapse | Rescue Critic and preserved rejection reasons |
| Fabricated novelty | Post-confirmation causal comparison against a hashed provenance-bearing corpus |
| Unsafe detector self-modification | Six explicit promotion gates; review records never rewrite production detector source |
| Benchmark contamination, post-trial relabelling/suppression, metric-input or Magma-level inflation, invented/omitted findings, or one-case overclaim | Cutoff checks across training/retrieval/rules, blocked ground truth and eventual fixes, independent encrypted case-pack hashes, canonical eligibility/class/label commitments, committed KLOC/disclosure/variant metadata, mandatory adjudication of every confirmed finding, pre-reveal trial seals with ledger-derived reproduction/regression, novelty/duplicate, timing, and six-dimension coverage state, ledger-derived detection, trigger lower bounds, Magma monotonicity, hash-verified checkpoints, repeat seeds, benign controls, and archived trial provenance |
| Fabricated deployed-code identity | Offline bytecode comparison bound to compiler config and capture provenance; no chain lookup performed |
| Unsafe disclosure | Human-controlled coordinated-disclosure workflow |

## Trust boundaries

The Nirvana source, local policy, runtime-validated schemas, and analyst-approved base specification are trusted. Audit targets, generated implementations, retrieved content, external tools, and their output are untrusted. Intake never launches target-configured Git. A verifier result becomes executable evidence only inside a digest-pinned Docker sandbox, after Nirvana captures its exact adapter, claim, exploit assertions, shared health invariants, command, policy, target snapshot, candidate-bound patched-control delta and decision, optional auditor-harness hash, bounded output, artifact hash, and successful replay.

The Docker target, patched control, and optional `/harness` mounts are read-only. A non-root numeric user runs with no capabilities, no privilege escalation, no network by default, a no-exec `/tmp`, an executable disposable `/work` area for compiler outputs, and bounded writable generated-output mounts. A baseline artifact overlay is outside the target and harness, scanned without following symlinks, bounded, hashed, and never trusted for execution. Only allowlisted non-secret environment values cross the boundary.

## Known foundation limitations

Working-tree dirty state is intentionally reported as unknown until an isolated Git adapter exists. Worktree-style `.git` redirections are not followed during non-executing intake. The hash chain does not protect against wholesale ledger replacement unless an exported checkpoint is published to an independent store. A benchmark trial seal proves consistency with the retained checkpointed prefix, not that an outside anchor existed before reveal; that publication remains an independent operational control. Generic graph frontends remain syntax-only, compiler-context candidates remain hypotheses, and benchmark metrics remain dependent on explicitly declared agent-host costs/confidence, the independent author/custody process, encryption-key separation, and retained artifacts. Case-pack verification proves byte integrity and declared provenance, not author honesty or cryptographic key custody.
