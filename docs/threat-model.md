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
| Secret exfiltration | Empty/minimal environment; no secret forwarding; no egress |
| Generated command injection | Argument arrays and `shell=False` |
| Live-chain harm | No production RPC credentials, signing, or broadcasts |
| Irrelevant command unlocks a finding | Adapter/argv contract, checked claim predicates, explicit supporting evidence IDs, and hypothesis binding |
| False high-severity report | Runner-minted receipt, assertion replay, executable ceiling, and adversarial review |
| Precision collapse | Devil's Advocate validation and semantic deduplication |
| Recall collapse | Rescue Critic and preserved rejection reasons |
| Benchmark contamination | Separate training, retrieval, and evaluation corpora |
| Unsafe disclosure | Human-controlled coordinated-disclosure workflow |

## Trust boundaries

The Nirvana source, local policy, runtime-validated schemas, and analyst-approved base specification are trusted. Audit targets, generated implementations, retrieved content, external tools, and their output are untrusted. Intake never launches target-configured Git. A verifier result becomes executable evidence only inside a digest-pinned Docker sandbox, after Nirvana captures its exact adapter, claim, assertions, command, policy, target snapshot, bounded output, artifact hash, and successful replay.

The Docker target mount is read-only. A non-root numeric user runs with no capabilities, no privilege escalation, no network by default, a no-exec `/tmp`, and an executable disposable `/work` area for Foundry/Cargo outputs and caches. Only allowlisted non-secret environment values cross the boundary.

## Known foundation limitations

Working-tree dirty state is intentionally reported as unknown until an isolated Git adapter exists. Worktree-style `.git` redirections are not followed during non-executing intake. The hash chain does not protect against wholesale ledger replacement without independent anchoring. The safe default EVM pass remains recall-oriented; compiler-context candidates require supplied solc standard-JSON output and still are not confirmed vulnerabilities.
