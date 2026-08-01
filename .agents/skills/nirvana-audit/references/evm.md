# EVM vertical slice

## Map business flows

Identify deposit/mint, withdraw/redeem, borrow/repay, liquidation, swap, bridge send/receive, staking/rewards, oracle update, governance, upgrade, emergency, signature/permit, and administrative flows that exist in the target.

For each flow, record:

- user and privileged entry points;
- assets in, assets out, shares/debt, fees, and conservation equations;
- storage transitions and mode changes;
- external calls, callbacks, hooks, fallbacks, and token behavior;
- oracle, bridge, sequencer, keeper, governance, and upgrade trust;
- ordering across calls, transactions, blocks, epochs, and asynchronous messages.

## Apply threat lenses

- Access and delegated authority
- Accounting, rounding, decimals, and share inflation
- Sequencing, replay, nonce, deadline, and stale state
- Oracle freshness, deviation, denomination, and manipulation cost
- Callback/reentrancy and state-before/after-external-control
- Griefing, gas, unbounded work, and forced reverts
- Upgrade, initialization, storage layout, delegatecall, and governance
- Signature domain separation, canonicality, signer binding, and cross-chain replay
- MEV, transaction ordering, JIT liquidity, and economic assumptions
- Integration deviations for ERC-20/4626/721/1155, fee-on-transfer, rebasing, hooks, and non-standard returns

## Verification order

1. Compiler/AST and deterministic scanners
2. Static call/data/effect path confirmation
3. Focused Foundry unit or invariant test
4. Echidna/Medusa stateful campaign
5. Halmos or other symbolic objective
6. Pinned local-state or mainnet-fork reproduction when integration state is essential
7. Economic exploit simulation with explicit market assumptions

Do not infer safety from a clean deterministic scan. Do not infer a bug from a lexical candidate.

## Compiler AST intake

Prefer solc standard-JSON AST context for promoted EVM detector work. Generate it in the pinned sandbox, preserve the compiler version and input hashes, and pass the existing output with `nirvana audit --solc-ast`. Nirvana currently queries AST-visible external-call/state-write ordering, missing authority guards, raw pool observations, and share-conversion arithmetic. These remain hypotheses until independent structural or executable evidence crosses the gate.
