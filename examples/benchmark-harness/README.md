# Pinned benchmark harness

Copy `policy.toml.example` to a trial-specific policy and replace the image placeholder with a reviewed 64-hex SHA-256 digest. Mutable tags are rejected by Nirvana. Do not commit a guessed digest: archive the registry resolution and image/tool version output with the trial environment instead.

Run executable evidence in Docker mode with the independently authored harness outside the hostile target:

```bash
nirvana evidence mint <run-directory> evidence.json execution-request.json \
  --policy policy.toml --execution-mode docker
```

The execution request should use an argv-native verifier rooted at `/harness`, as demonstrated by `.agents/skills/nirvana-audit/assets/execution-request.json`. Include both the security property and an independent baseline health invariant. Keep network, secrets, live-chain actions, Git writes, and host execution disabled.

Record the exact policy hash, image digest, compiler/test-tool versions, transcript hash, token budget, tokens used, compute hours, and model cost for every seed. This directory is configuration guidance; it is not benchmark evidence by itself.
