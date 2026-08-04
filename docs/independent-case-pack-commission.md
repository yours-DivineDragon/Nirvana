# Independent Solidity case-pack commission

## Purpose and status

Nirvana needs one independent author or team to create a small blind pilot. The author owns target construction and label custody; the Nirvana trial operator owns the audits. These roles must remain separate.

This brief is ready to send, but the commission is **unassigned**. A Nirvana contributor, the trial operator, or an agent acting for either cannot self-author the pack without invalidating its independence.

## Pilot deliverable

Provide one encrypted case pack containing exactly five eligible, post-cutoff Solidity targets:

- three targets with one or more committed vulnerabilities;
- two benign controls with empty committed vulnerability lists;
- a fixed cutoff chosen before target construction;
- three-run suitability for every case without changing target bytes between seeds;
- complete KLOC, origin/disclosure time, hidden-variant status, and transformation-log provenance.

The cases may be reduced real protocols or independently designed contracts, but the operator must not have seen their labels or construction notes. Vulnerable and benign cases should be superficially indistinguishable. Do not encode labels in names, directory layout, commit messages, build output, or ciphertext sizes.

## Independence and custody

Start from `.agents/skills/nirvana-audit/assets/benchmark-case-pack.json` and the canonical ground-truth template. The final pack must record:

```json
{
  "author_attestation": {
    "independent_from_trial_operator": true,
    "custody_model": "separate_human"
  }
}
```

`separate_org` or `escrow` is also acceptable. Encrypt each canonical ground-truth document with `age` or OpenPGP to a reveal custodian whose private key is unavailable to the trial operator. The author retains the plaintext labels and decryption authority until all 15 trials have been sealed and checkpointed.

The attestation must identify the author, describe the relationship to the operator, state the custody model, and bind the generator source hash and randomness description. Independence is an operational fact as well as a JSON field; Nirvana verifies the declared artifact contract but cannot prove that the author told the truth or kept the key separate.

## Author procedure

For each case:

1. Finalize the target and its canonical ground-truth document.
2. Hash the exact target bytes:

   ```sh
   nirvana benchmark hash-target cases/CASE-ID/target
   ```

3. Commit the canonical label document:

   ```sh
   nirvana benchmark commit-ground-truth \
     cases/CASE-ID/ground-truth.json \
     --output cases/CASE-ID/commitment.json
   ```

4. Encrypt that unchanged ground-truth document, record the recipient fingerprint, then remove the plaintext from everything accessible to the operator.
5. Record the printed target snapshot digest, then hash the commitment artifact, ciphertext, transformation log when applicable, and author attestation into `benchmark-case-pack.json`.

Before handoff, run:

```sh
nirvana benchmark verify-pack benchmark-case-pack.json \
  --output benchmark-case-pack-report.json
```

The handoff is accepted only when the report contains:

```json
{
  "valid": true,
  "independent": true,
  "case_count": 5
}
```

The operator receives the five targets, commitments, ciphertexts, pack, attestation, generator provenance, and verification report. The operator must not receive plaintext labels, the reveal key, vulnerable/benign counts mapped to case ids, or unredacted construction notes.

## Blind-run protocol

The operator runs every case with three distinct integer seeds, for 15 trials total. For each trial:

1. Audit the unchanged committed target and retain the prompt, transcript, environment, model/tool versions, budgets, costs, and timings.
2. Mint and replay whatever evidence the run can support; never promote a High/Critical claim below executable evidence.
3. Complete novelty assessment and coverage accounting where available.
4. Seal the complete ledger-backed finding set before any reveal:

   ```sh
   nirvana benchmark seal-trial ./nirvana-runs/RUN-ID \
     --trial-id TRIAL-ID --case-id CASE-ID --seed SEED \
     --output ./nirvana-runs/RUN-ID/benchmark-trial-checkpoint.json
   ```

5. Give the reveal custodian the ordered list of all 15 checkpoint hashes. Do not replace, rerun, omit, or edit a trial after that handoff.

Only then may the custodian reveal the five canonical ground-truth documents. Populate the manifest from those exact reveals and run:

```sh
nirvana benchmark evaluate benchmark-manifest.json \
  --output benchmark-report.json
```

Five cases are intentionally below Nirvana's closed-beta qualification floors. `suite_qualification.qualified: false` is the expected pilot result, not a failed measurement.

## Publication commitment

Publish the result regardless of performance. The report must include:

- overall and High/Critical precision and recall;
- Magma reached, triggered, and detected counts;
- evidence-tier distribution, time-to-finding, compute, token, and cost accounting;
- `temporal_validation` and `suite_qualification` blocks verbatim, including every refusal reason;
- one line for every missed committed vulnerability: detector absent, detector did not fire, candidate could not reach executable evidence, or evidence existed but the impact claim failed.

That miss table—not a generic vulnerability taxonomy—becomes the detector roadmap. Modifier-body inlining, path facts, a second typed dialect, or any new vulnerability class should be prioritized only when the blind data supports it.

## Acceptance boundary

The commission is complete only when the operator holds a five-case pack for which `verify-pack` reports `valid: true` and `independent: true`, while the ground truth remains undecryptable to the operator. Writing this brief, generating a self-authored pack, or obtaining a structurally valid pack whose labels the operator can read does not satisfy the milestone.
