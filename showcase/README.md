# 4thGraph results

| Result | Evidence and reproduction |
| --- | --- |
| **Native payments** | [P2PK and P2PKH measurements](../projects/p2pk-p2pkh-baseline/README.md) and [Forth builds](../projects/p2pk-p2pkh-baseline/forth/README.md) |
| **P-256 lock optimization** | P2PKH-R1 v0.6.0 measures 41,364 B per lock and 83,498 B per two-input, two-output BIP143 ALL payment. [P2PKH-R1 results](../projects/p2pkh-r1/README.md#measured-results) |
| **Deferred R1 activation** | [Deferred v0.3.0](../projects/p2pkh-r1-deferred/README.md#4thgraph-forth-comparison) uses a 1,085 B funding lock built with `stack` optimization |
| **PELS Counter** | [Build and replay](../projects/pels-counter/README.md) covers the funded `0 → 1 → 2` sequence and rejected mutations |
| **BIP340** | [Schnorr locks and signing](../projects/p2pkh-schnorr/README.md) and [fixed BIP340 vectors](../projects/p2pkh-schnorr/versions/v0.6.0/bip340-vectors.csv) |
| **WOTS+ lock optimization** | WOTS+ v0.12.0 uses a 21,272 B lock and a 48,992 B reconstructed OTDA ALL payment. [Version artifacts](../projects/wots-plus/versions/v0.12.0/manifest.json) · [Compact measurements](../projects/wots-plus/README.md#compact-profile) |
| **BLS12-381 Groth16** | [Fixed-statement comparison](../projects/proof-counter/reference/fixed-statement/README.md) and [recorded benchmark](../projects/proof-counter/versions/v0.1.0/measurements.json) |

The [wallet benchmark](../docs/benchmark.md) specifies transaction shapes, measurement and engine pins for cross-project comparisons.
