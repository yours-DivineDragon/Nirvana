# Solidity symmetry false-positive study — 2026-08-04

## Result

The pre-fix typed-solc analyzer emitted 23 symmetry hypotheses from ten pinned DeFi repositories. Manual source review classified all 23 as false-positive review leads: 16 expected directional guards, six read-only calls mislabeled as asset effects, and one mapping-key read mislabeled as a state write. No emitted hypothesis represented a confirmed protocol defect.

The three measured causes were corrected in the same change:

- assignment summaries now resolve the storage base of an l-value without treating mapping keys or array indices as writes;
- calls proven `view` or `pure` by compiler types cannot create asset-effect facts, while unresolved and state-changing calls remain conservative;
- known value-flow pairs suppress only directionally expected authority/oracle guards on the risk-bearing operation. Reverse-direction differences and pause, reentrancy, deadline, nonce, state, and effect differences remain candidates.

Re-running the exact same ten AST artifacts after those changes emitted zero symmetry hypotheses. This is a regression result on the tuning sample, not an independent precision estimate and not a recall measurement.

## Repositories and compiler provenance

| Repository | Commit | Root source(s) | solc | Compiler SHA-256 | Source units | AST SHA-256 | Before | After |
|---|---|---|---|---|---:|---|---:|---:|
| morpho-org/morpho-blue | `d09dd1c4b9c7d9d05f976faa7ebfdc424dae5e8c` | `src/Morpho.sol` | 0.8.19 | `7a5c1d3dc9a8eba62bb2ec37192c9178ae5fe8a54a56e5573fd3c9c17cd9eb48` | 14 | `31be2f21436b7548a4ab7452ce410aa6f100baced663c882eac5fadbd901c90c` | 4 | 0 |
| aave/aave-v3-core | `782f51917056a53a2c228701058a6c3fb233684a` | `contracts/protocol/pool/Pool.sol` | 0.8.10 | `c7effacf28b9d64495f81b75228fbf4266ac0ec87e8f1adc489ddd8a4dd06d89` | 46 | `a1508cf0e02bd7c8b74a473d3fa47c8d7d6e5d88aac33b4b404df01308f24882` | 2 | 0 |
| compound-finance/comet | `f766f51583c23acc33b2a7824654ef2029a96804` | `contracts/CometWithExtendedAssetList.sol` | 0.8.15 | `5189155ce322d57fb75e8518d9b39139627edea4fb25b5f0ebed0391c52e74cc` | 11 | `08a160366e08950d1f0ed343e986b4b7af0550f268ef2dea81eef60f29fa09e1` | 3 | 0 |
| euler-xyz/euler-vault-kit | `5b98b42048ba11ae82fb62dfec06d1010c8e41e6` | `src/EVault/modules/Vault.sol` | 0.8.30 | `f3e987dc6ecebd4bd350c48edcbc320b46cf9e3109bd3fc3d88f1acaf4c428f7` | 36 | `b3314102c6d34e9388e33e00a40100277b1c55c4beedbe64080fde6c8a5269fb` | 0 | 0 |
| silo-finance/silo-contracts-v2 | `8e2c1b6283ab23c8640a0deaac08520daab3aae1` | `silo-core/contracts/Silo.sol` | 0.8.28 | `9a0fb7e0db2c0641dbae1c5cc645dc686820c83af516226abb1c0a2f76636f25` | 67 | `8f915c55fa6564421e142defe0eaf0e8e22a61c20938809f0b4a23ec691d73ce` | 1 | 0 |
| balancer/balancer-v3-monorepo | `7da778a3d9d352b26c05b275cf8fa1405ee6734d` | `pkg/vault/contracts/Vault.sol` | 0.8.27 | `b9977d500c17cba6f0032ca939ef98c4decf6363f19f386d05fb02f708115264` | 68 | `a88849daa4e9fa0a8e6b461d8b3ed0dd78ab460c3cf0642feae3248be2470911` | 1 | 0 |
| AngleProtocol/angle-transmuter | `2fa74b73a3f5aa921e619e55744d73228cd2fe71` | `Swapper.sol`, `Redeemer.sol` | 0.8.26 | `d5f23436f443edb85d8e76906d12f0a86ce0490e7663a9e608efeb7a93f149ef` | 34 | `faa68e17a2c0b9dbf9cf209d00c3cb36745983f49adb53d8deaf3cfeaf18a315` | 0 | 0 |
| Gearbox-protocol/core-v3 | `510fc6541c3767ce825929b4c311826fe81d6fa5` | `contracts/pool/PoolV3.sol` | 0.8.23 | `28726a452290c70e1984f15c53ad3088e7d98783ee3070b11b3664da77415732` | 48 | `92f185bfdc59f3da56b8bde9f9b8ac1c271bda6e0b8bc7095f2da681c7b3b4e7` | 10 | 0 |
| sparkdotfi/spark-vaults | `78d37c8919f0d8c9943db02b9bca7077b6c38c10` | `src/UsdcVault.sol` | 0.8.21 | `f2857a898be15c69e8de5598dcd3f3e169e94964a0ce9a0bbb1b111f145a81df` | 8 | `f91eed535a346d80303326d5b11e86c56ee727979a42d6e3014a0e10cd1468c4` | 2 | 0 |
| Uniswap/v4-core | `46c6834698c48bc4a463a86d8420f4eb1d7f3b75` | `src/PoolManager.sol` | 0.8.26 | `d5f23436f443edb85d8e76906d12f0a86ce0490e7663a9e608efeb7a93f149ef` | 45 | `78f338ae3066ea30deed490528ff4c7c9a9ad12a8ffb66b6de6c4d5926199498` | 0 | 0 |

Balancer's declared `@openzeppelin/contracts` dependency was resolved at 5.4.0. Git submodule dependencies were checked out at the gitlinks committed by each target. Dependency source units are included in the AST hashes and counts above.

## Classification of every pre-fix hypothesis

| Repository | Hypothesis | Pair | Classification | Review rationale |
|---|---|---|---|---|
| Morpho | `H-SYM-464CE7A035EE5388` | `borrow/repay` | Expected directional guard | Borrowing needs account authorization; permissionless repayment improves the account. |
| Morpho | `H-SYM-49CF915B44F4F0F1` | `supply/withdraw` | Expected directional guard | Supplying on behalf is safe; withdrawing another account's assets needs authorization. |
| Morpho | `H-SYM-3AF2634D1A717369` | `supplyCollateral/withdrawCollateral` | L-value extraction error | `feeRecipient` is a mapping index read inside interest accrual, not a written state declaration. |
| Morpho | `H-SYM-C6E547424455B06A` | `supplyCollateral/withdrawCollateral` | Expected directional guard | Collateral withdrawal needs authorization and solvency; collateral supply does not. |
| Aave | `H-SYM-03591AF2088F9550` | `borrow/repay` | Expected directional guard | Borrow validates collateral/oracle state; repay's sender-sensitive token path is intentionally different. |
| Aave | `H-SYM-E72D46E31278F5D8` | `executeBorrow/executeRepay` | Expected directional guard | The same intentional asymmetry is repeated at the logic-library layer. |
| Comet | `H-SYM-751D0C7A6F450BD1` | `supply/withdraw` | Expected directional guard | Withdrawal can create debt and therefore checks collateralization; supply cannot worsen solvency. |
| Comet | `H-SYM-96B708491F8CD69D` | `supplyFrom/withdrawFrom` | Expected directional guard | The delegated form preserves the same solvency direction. |
| Comet | `H-SYM-017D5C21C944182E` | `supplyTo/withdrawTo` | Expected directional guard | The destination variant preserves the same solvency direction. |
| Silo | `H-SYM-A5366CFA010B92A1` | `mint/burn` | Expected directional guard | Both paths are `onlySilo`; burn alone spends allowance when owner and spender differ. |
| Balancer | `H-SYM-3C70B7CE9F746DE4` | `addLiquidity/removeLiquidity` | Expected directional guard | Removal burns BPT from `params.from` and must spend router allowance; addition mints to the recipient. |
| Gearbox | `H-SYM-9C5711618EC38638` | `deposit/redeem` | Expected directional guard | Redeem can burn an owner's shares and therefore needs owner/allowance handling. |
| Gearbox | `H-SYM-0BDED3C83BD3E505` | `deposit/withdraw` | Expected directional guard | Withdraw can burn an owner's shares and therefore needs owner/allowance handling. |
| Gearbox | `H-SYM-2613E6E68819D33D` | `mint/redeem` | Expected directional guard | Redeem is the owner-sensitive exit side of ERC-4626. |
| Gearbox | `H-SYM-F3B35941CE299D6B` | dependency `deposit/redeem` | Expected directional guard | The same ERC-4626 behavior is repeated in the pinned OpenZeppelin dependency. |
| Gearbox | `H-SYM-B4A19DE203E8180D` | dependency `deposit/withdraw` | Expected directional guard | The same ERC-4626 behavior is repeated in the pinned OpenZeppelin dependency. |
| Gearbox | `H-SYM-AB6A249A4AC35A87` | dependency `mint/redeem` | Expected directional guard | The same ERC-4626 behavior is repeated in the pinned OpenZeppelin dependency. |
| Gearbox | `H-SYM-114162D9B7A0ADE7` | `maxDeposit/maxWithdraw` | Read-only effect error | `maxWithdraw` is a view calculation; a called name containing `withdraw` is not an asset transfer. |
| Gearbox | `H-SYM-15343391FB056057` | `previewDeposit/previewRedeem` | Read-only effect error | Both operations are view-only previews. |
| Gearbox | `H-SYM-CC8B11F0725BF950` | `previewDeposit/previewWithdraw` | Read-only effect error | Both operations are view-only previews. |
| Gearbox | `H-SYM-322796F681B143DD` | `previewMint/previewRedeem` | Read-only effect error | Both operations are view-only previews. |
| Spark | `H-SYM-EB11EDE3E91CF0F4` | `maxDeposit/maxRedeem` | Read-only effect error | External preview calls are typed `view`; no assets or supply move. |
| Spark | `H-SYM-58481C0CD929F85F` | `maxDeposit/maxWithdraw` | Read-only effect error | External preview calls are typed `view`; no assets or supply move. |

## Reproduction

Each repository was cloned at the exact commit above. Its configured compiler (or a pragma-compatible 0.8.30 for Euler's `^0.8.0` root) produced typed AST output with:

```sh
solc --base-path . [repository remappings] --combined-json ast [root sources] > combined.json
PYTHONPATH=src python tools/scan_symmetry_ast.py /path/to/repository combined.json result.json
```

The resulting `result.ast.json` digest must match the table. Compiler binaries must match their listed SHA-256 digests. The full remappings come from each pinned repository's `foundry.toml` or `remappings.txt`; Balancer uses workspace remappings for `pkg/interfaces` and `pkg/solidity-utils` plus `@openzeppelin/contracts` 5.4.0.

## Limits and next gate

This was a deliberately small, root-contract study. It does not prove recall, does not cover every contract in each repository, and is not an independent or temporally sealed benchmark. The post-fix result uses the same sample that selected the fixes, so it must not be presented as out-of-sample precision. The independent five-target/two-control, three-seed case pack remains external work: Nirvana rejects self-authored packs by design, so that gate cannot honestly be completed by this implementation PR.
