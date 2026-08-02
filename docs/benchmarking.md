# Blind benchmark operations

Nirvana separates a valid measurement from a maturity claim. A small or exploratory blind run may be temporally valid and may report precision, recall, Magma signals, and cost metrics. It does not become closed-beta evidence merely because those ratios are perfect.

`benchmark-report.json` exposes the distinction directly:

- `release_gates.closed_beta.precision_thresholds_met` applies the founding specification's 80% overall and 90% High/Critical precision targets.
- `suite_qualification.qualified` applies Nirvana's conservative `nirvana-closed-beta-v3` operational floors.
- `release_gates.closed_beta.passed` is true only when both are true.

The v3 operational floors are project policy, not a claim that a particular sample size proves general performance:

| Qualification check | Floor |
|---|---:|
| Eligible vulnerable cases | 20 |
| Eligible benign controls | 10 |
| Distinct integer seeds per eligible case | 3 |
| Case provenance | Verified independent encrypted case pack and matching reveal commitments |
| Case sizing | Every KLOC denominator matches its independently authored case-pack value |
| Finding attribution | Every true positive names committed ground truth; every non-null id belongs to that case |
| Run provenance | Every trial and complete finding set matches a sealed ledger checkpoint; confirmed findings cannot be suppressed |
| Derived outcomes | Reproduction and patch-test state match replay-verified reproducer and regression evidence |
| High/Critical evidence | Executable or stronger for every report |
| Trial accounting | Complete tokens, budget, compute, and model cost |

These floors prevent a one-case perfect score from minting closed beta. Precision, recall, confidence intervals, failure clusters, and per-track performance still need human interpretation on larger suites.

## Independent case-pack workflow

The case-pack author and trial operator must be separated by one of three comparable custody models: `separate_human`, `separate_org`, or `escrow`. Before the trial, the author:

1. Pins a cutoff and creates post-cutoff targets without exposing vulnerable-versus-benign labels.
2. Builds each canonical ground-truth document from `.agents/skills/nirvana-audit/assets/benchmark-ground-truth.json`. It binds the case id, eligibility, derived vulnerable/benign class, and complete vulnerability label records.
3. Creates the public commitment, then encrypts that exact ground-truth document for a recipient unavailable to the trial operator. `age` and OpenPGP are the supported contract labels.
4. Retains an authorship/custody attestation, generator source hash and randomness description.
5. Records each target's KLOC before operator access and hashes each target snapshot, commitment artifact, ciphertext, attestation, and complete `benchmark-case-pack.json`.

Use the shipped helpers rather than `RepositoryIntake`, Git tree hashes, or a hand-rolled directory digest:

```bash
nirvana benchmark hash-target cases/CASE-1/target
nirvana benchmark commit-ground-truth cases/CASE-1/ground-truth.json \
  --output cases/CASE-1/commitment.json
```

`hash-target` uses the declared `nirvana-regular-file-tree-v1` algorithm: sorted relative regular-file paths, byte sizes, and SHA-256 values encoded as canonical JSON. `commit-ground-truth` uses `sha256-canonical-ground-truth-v1` and emits no labels—only the case id, algorithm, and commitment. Its output prints both values needed by the pack: `public_commitment_sha256` for the canonical reveal and `public_commitment_artifact_sha256` for the commitment file bytes. Remove the plaintext reveal from trial-operator access after encrypting it; retain it with the reveal custodian.

Case-pack schema v1.2 requires a non-negative KLOC commitment for every target. It remains intentionally incompatible with v1.0 packs, whose public commitment was only an artifact byte hash; recreate those commitments from the canonical reveal before using them for evaluation.

Start from `.agents/skills/nirvana-audit/assets/benchmark-case-pack.json`, then verify the completed pack:

```bash
nirvana benchmark verify-pack benchmark-case-pack.json \
  --output benchmark-case-pack-report.json
```

The verifier rejects path traversal, symlinks, non-regular artifacts, oversized inputs, target snapshot drift, duplicate ids, pre-cutoff cases, unknown custody models, commitment-file/value disagreement, and every hash mismatch. It proves byte integrity and the declared custody contract; it cannot prove that the author was honest or that encryption keys were kept separate. Those remain independent operational controls.

Reference the verified bytes from the post-reveal benchmark manifest with a relative path:

```json
{
  "case_pack": {
    "path": "benchmark-case-pack.json",
    "sha256": "<SHA-256 OF THE CASE-PACK JSON>"
  }
}
```

Evaluation re-verifies the pack instead of trusting a prior report. After the trial, populate each manifest case from the revealed canonical document. Evaluation recomputes every commitment from the manifest's `case_id`, `eligible`, derived vulnerable/benign class, and full `ground_truth` list. The pack cutoff, complete case-id set, case origin timestamps, KLOC values, and all reveal commitments must match. Any mismatch is report-level invalidity: metrics and Magma values are null and every gate closes. This prevents a missed vulnerable case from being relabelled benign or ineligible after results are known, and prevents an operator from shrinking the denominator of per-KLOC yield. A valid pilot without a verified case pack reports per-KLOC yield as undefined.

Adjudication is bound to that same committed label set. A `true_positive` must carry a non-null `ground_truth_id`, and every non-null attribution on any finding must name a vulnerability committed for that case. An unmatched id is a validation violation, never a precision point. This keeps the precision numerator and the recall numerator under the same reveal commitment.

## Trial recording

Run every eligible case with at least three distinct integer seeds. Each trial must retain its prompt, transcript, environment, model, tools, and hashes, and must add:

```json
{
  "token_budget": 100000,
  "tokens_used": 42810,
  "cost_accounting_complete": true,
  "compute_hours": 0.75,
  "model_cost": 0.0
}
```

`tokens_used` must not exceed a non-zero budget. A zero model cost is valid for local inference, but it must be recorded deliberately. A High or Critical claim below `executable` cannot enter a Nirvana `finding_confirmed` event, so it cannot satisfy the trial-ledger binding.

Before ground truth is revealed, seal each completed Nirvana run and export the exact checkpoint the manifest will reference:

```bash
nirvana benchmark seal-trial ./nirvana-runs/<run-id> \
  --trial-id TRIAL-1 --case-id CASE-1 --seed 1 \
  --output ./nirvana-runs/<run-id>/benchmark-trial-checkpoint.json
```

The command derives the complete `finding_confirmed` set from the ledger. Trial seal v1.1 records each finding's severity, evidence tier, reproducer and regression evidence ids, replay-derived reproduction state, and verified patched-control state in a `benchmark_trial_sealed` event. It refuses missing or currently failed replay evidence, then checkpoints that seal. Put the printed artifact SHA-256 and relative paths into manifest v1.2:

```json
{
  "ledger_checkpoint": {
    "algorithm": "nirvana-ledger-checkpoint-v1",
    "run_directory": "nirvana-runs/<run-id>",
    "checkpoint_path": "nirvana-runs/<run-id>/benchmark-trial-checkpoint.json",
    "checkpoint_sha256": "<SHA-256>"
  }
}
```

Evaluation rejects path traversal, symlinks, checkpoint or ledger tampering, a free `run_id` that differs from the run-directory name, a trial/case/seed identity that differs from the seal, invented findings, omitted checkpointed findings, severity or evidence-tier drift, operator-declared reproduction or patch state that differs from the ledger, unverified supporting evidence, and evidence invalidated by a later replay failure. This is a one-to-one binding: every checkpointed finding must be adjudicated `true_positive` or `false_positive`; `suppressed` cannot remove it from the precision denominator. Unconfirmed analyst-queue items stay outside the benchmark finding set. Manifest v1.2 and trial seal v1.1 are intentionally incompatible with older unbound claims.

The checkpoint remains a tamper-evident local commitment until its hash is published to an independent trusted store. Nirvana reports whether the checkpoint contains an `external_anchor`, but does not claim to verify the honesty, independence, or publication time of that outside service.

Only reveal and adjudicate ground truth after all trial artifacts are sealed. Then run:

```bash
nirvana benchmark evaluate benchmark-manifest.json --output benchmark-report.json
```

Temporal contamination, a reveal or finding-attribution mismatch, or a broken trial-ledger binding invalidates the entire report: metrics and Magma values become null, every gate closes, and the CLI exits non-zero. Sample insufficiency does not invalidate a clean pilot; it appears in `suite_qualification.reasons` instead.

## Pinned executable harness

Use a digest-pinned, network-disabled, non-root Docker policy for executable evidence. The target and `/harness` are mounted read-only; compiler outputs live on disposable filesystems. The example in `examples/benchmark-harness/` intentionally contains no floating tag or invented digest. Resolve and review the exact image digest before the run, then archive that digest in each trial's environment record.

Use a harness outside the target and the request template's `--root /harness` pattern. Pair the exploit/property test with an independent baseline health invariant so a crash, broken build, or universally failing test cannot satisfy the claim.
