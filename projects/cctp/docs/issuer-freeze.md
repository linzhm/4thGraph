# Issuer-controlled token freezing

Circle's EVM design distinguishes address blocking from pausing the token contract. The proposed first BSV profile freezes a specific token outpoint. The same issuer policy can freeze the currently known set of UTXOs for an owner by spending them in one transaction. Persistent address blocking requires a separate, current policy check for both senders and recipients. [Circle contract design](https://github.com/circlefin/stablecoin-evm/blob/master/doc/tokendesign.md) · [Circle blocklisting process](https://help.circle.com/support/en/understand-circle-s-stablecoin-blocklisting-process?id=support_article_view&sysparm_article=KB0011513)

## Targeted state transition

Extend token state with an active or frozen flag. Preserve the asset ID, quantity, canonical owner descriptor and policy identity on both administrative paths. Bind the issuer's dedicated freeze authorization to the actual transaction and identify each administrative successor by its exact output index. Map each consumed token input to a distinct successor index. A two-input freeze must never use the same successor to satisfy both source locks. Fees can be provided by separate BSV inputs.

| Operation | Authorization | State rule |
|---|---|---|
| Payment | Active holder and token validity proof | Per-asset conservation across all authenticated inputs and outputs |
| Freeze | Issuer freeze role | Active to frozen, same asset, quantity and owner |
| Unfreeze | Issuer freeze role | Frozen to active, same asset, quantity and owner |

Require verified transaction introspection or a proof bound to the actual input and successor for each administrative path. A frozen token only enables the transition back to active. In a race, the confirmed spend of the original outpoint determines which transition takes effect. If ordinary payment wins, freezing a known successor requires another administrative transaction. Reorganizations follow normal BSV confirmation semantics.

## Address blocking and global pause

Checking a recipient or owner against a list requires binding every payment to the applicable policy version. A signed root or merkle proof gives integrity for a particular policy version. It provides no independent evidence that a later version has not revoked the address. Standalone blocklist publication does not supply consensus freshness. Possible designs include an authoritative policy UTXO spent by affected transfers, deterministic policy shards, or an online policy co-signer. A shared UTXO introduces contention. Shards make multi-owner transfers depend on each applicable shard. Co-signing adds issuer availability and changes payment authorization. Test these as separate policies and specify the enforcement timing explicitly.

## Proof obligations

Prove the supply invariant by induction on confirmed transactions. The issuance base case recognizes only the exact anchor and the configured quantity. An ordinary transition consumes authenticated older tokens and conserves quantity. An administrative transition has an injective successor mapping and preserves amount and owner at each edge. In each branch, exact locking templates and transaction commitments must prevent any other outputs from being recognized as valid successors.

The wallet must identify the executed verifier or administrative covenant of the creating transaction, check that its designated output is covered by that execution, and validate the confirmed transaction against its header chain. For a historical output, availability to spend is a separate question from issuance validity.

The certified v3 issuer paths pair token vin 0 with successor vout 0. The exact freeze and unfreeze transactions were mined on an independent BSV regtest. The acceptance matrix covers wrong issuer key, replaced successor, changed owner, quantity, satoshis or policy, and attempted payment or burn while frozen. A separate v2 fixture exercises both orders of the freeze and payment race. Global pause and persistent address blocking have separate activation and freshness requirements. [v3 lifecycle](../fixtures/v3-certified-cross-chain-regtest-summary.json) · [v2 race](../fixtures/freeze-race-regtest-summary.json)

The isolated circuit experiment keeps the native issuer signature and derives public inputs from the real paired output and consumed lock. It moves the freeze-bit and immutable-field checks into a separate BLS12-381 circuit. Compare it against the certified Script path before changing the bridge verifier. [Experiment and validation](dual-route-validation.md#验证构件与冻结小样)
