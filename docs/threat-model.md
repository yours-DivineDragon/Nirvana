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
| False high-severity report | Executable-evidence gate plus adversarial review |
| Precision collapse | Devil's Advocate validation and semantic deduplication |
| Recall collapse | Rescue Critic and preserved rejection reasons |
| Benchmark contamination | Separate training, retrieval, and evaluation corpora |
| Unsafe disclosure | Human-controlled coordinated-disclosure workflow |

## Trust boundaries

The Nirvana source, local policy, schemas, and analyst-approved base specification are trusted. Audit targets, generated implementations, retrieved content, external tools, and their output are untrusted. A verifier result becomes evidence only with its exact command, version, assumptions, artifact hash, and reproducible outcome.

## Known foundation limitations

The current environment lacks Docker and EVM verifier tools, so only non-executing intake and candidate generation are available here. The hash chain does not protect against wholesale ledger replacement without independent anchoring. The built-in EVM rules are recall-oriented leads, not vulnerability detectors.
