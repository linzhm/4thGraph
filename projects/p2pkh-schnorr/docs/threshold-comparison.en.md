# MuSig2 and native 2-of-2 multisig

[简体中文](threshold-comparison.zh-CN.md) · [Project overview](../README.md) · [Wallet integration](sdk.en.md#integrate-musig2)

The current P2PKH-Schnorr template supports a UTXO controlled by two MuSig2 participants. At funding, the wallet aggregates two distinct compressed public keys in the agreed order using BIP327, then fills the fixed template with the HASH160 of the aggregate key's x-coordinate. For each input, both signers approve the 32-byte transaction digest, exchange public nonces, and produce partial signatures. The coordinator verifies the partial signatures and combines them into a standard 64-byte BIP340 signature. The existing wallet interface accepts that signature and prepares the coordinate witnesses. The on-chain key and signature are aggregated. The participant keys and count stay off-chain. Native `CHECKMULTISIG` publishes both public keys in the lock. [BIP327](https://github.com/bitcoin/bips/blob/4f9567fd60021cb7dea032250ab241cd68d9ff91/bip-0327.mediawiki) · [Two-party signing fixture](../reference/musig2_fixture.py)

## Transaction and lifecycle costs

Both schemes require both signatures. The fixtures use the same transaction shapes, values, and sighash modes. The 2×2 case creates two protected outputs of the same scheme. Input and output marginals are measured as 3×2 minus 2×2 and 2×3 minus 2×2. A lifecycle starts with ordinary P2PKH funding and ends at two ordinary P2PKH outputs. One turnover inserts a 2×2 transfer to fresh outputs of the same scheme.

| Scheme | ALL mode | Lock | 2×2 unlocks by input | 2×2 transaction | Extra input | Extra output | Fund and exit | With one turnover | First-input peak stack payload |
| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| MuSig2 v0.12.0 | BIP143 | 24,683 | 329 / 329 | 50,142 | 372 | 24,694 | 50,368 | 100,509 | 3,403 |
| Native 2-of-2 | BIP143 | 71 | 146 / 147 | 545 | 186 | 80 | 771 | 1,313 | 211 |
| MuSig2 v0.12.0 | Chronicle OTDA | 24,683 | 49,657 / 49,657 | 148,798 | 49,823 | 74,090 | 50,381 | 199,180 | 99,146 |
| Native 2-of-2 | Chronicle OTDA | 71 | 145 / 146 | 543 | 187 | 81 | 769 | 1,314 | 210 |

All sizes are in bytes. At a common rate of one satoshi per byte, the transaction and lifecycle byte counts also give their fee in satoshis. Native ECDSA DER lengths vary with the signature, so the observed marginals include small witness changes. Stack payload counts main and alternate stack data. The native peak occurs immediately before `CHECKMULTISIG`. The MuSig2 stack figures come from the development evaluator. Internal engine allocations are outside this measurement. [Runner](../reference/compare_threshold.py) · [Benchmark method](../../../docs/benchmark.md)

For the 2×2 fixtures, median chain-gang verification was **10.44 ms** for MuSig2 and **0.74 ms** for native BIP143, and **6.24 ms** and **0.73 ms** for OTDA. BSV Node loopback RPC medians were **29.62 ms** and **1.11 ms** for BIP143, and **34.03 ms** and **1.20 ms** for OTDA. These host-specific medians use 15 measurements after one warmup and include input preparation and verification. Node timings include local RPC overhead.

For OTDA ALL, the current template puts the complete committed outputs in each preimage. When exiting into ordinary P2PKH outputs, each MuSig2 OTDA unlock falls to 336 bytes. Native `CHECKMULTISIG` constructs the signature digest in the node and requires only the dummy item and two signatures in the unlocking script.

## Off-chain signing cost and acceptance

MuSig2 needs two dependent signing-message rounds per input. Each signer produces a 66-byte public nonce and a 32-byte partial signature, totaling **196 bytes**. Native multisig needs one collection round, with both DER signatures and their sighash bytes totaling **142–144 bytes** per input in the fixtures. These counts cover artifacts produced by signers. Transaction distribution, coordinator forwarding, device approvals, and network delays depend on deployment. Rounds for different inputs can run in parallel. Both schemes need both participants. Native ECDSA signatures can be collected independently for the same transaction. A replacement MuSig2 session needs fresh nonces and partial signatures after an abort. [BIP327](https://github.com/bitcoin/bips/blob/4f9567fd60021cb7dea032250ab241cd68d9ff91/bip-0327.mediawiki)

Across the direct-exit and one-turnover lifecycles, the protected inputs produce 392 and 784 bytes of MuSig2 artifacts. Native multisig produces 287 and 572 bytes for BIP143, and 286 and 573 bytes for OTDA. The ordinary funding input is common to both schemes.

Acceptance covers two official BIP327 signature aggregation vectors. Session cases exercise missing nonces and shares, nonce cancellation, retries, mismatched digests, reordered participants, and stale shares. For both on-chain schemes, BSV Node 1.2.3 and chain-gang accepted **12 paired BIP143 / OTDA modes × two transaction versions** and matched the expected locktime and output value mutation results. Funding and exit entered the mempool and were mined under default regtest policy for both schemes under BIP143 ALL and OTDA ALL. The unified Python, TypeScript, Go, and Rust SDK suites replay the MuSig2 aggregate-signature fixtures for BIP143 ALL and OTDA SINGLE. [Acceptance suite](../reference/test_musig2.py) · [Official aggregation vectors](https://github.com/bitcoin/bips/blob/4f9567fd60021cb7dea032250ab241cd68d9ff91/bip-0327/vectors/sig_agg_vectors.json) · [Wallet fixtures](../reference/sdk_fixture.py)

Set up the [project environment](../README.md#validate-the-baseline) and run from the repository root.

```sh
PYTHONPATH=src:. bash tools/verify_node.sh -- \
  projects/p2pkh-schnorr/workspace/p2pkh-schnorr/bin/python projects/p2pkh-schnorr/reference/compare_threshold.py \
  --output /tmp/p2pkh-schnorr-threshold.json
PYTHONPATH=src:. bash tools/verify_node.sh --profile default -- \
  projects/p2pkh-schnorr/workspace/p2pkh-schnorr/bin/python projects/p2pkh-schnorr/reference/compare_threshold.py \
  --admission --output /tmp/p2pkh-schnorr-threshold-admission.json
```
