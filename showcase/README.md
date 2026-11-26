# 4thGraph results

| Result | Evidence and reproduction |
| --- | --- |
| **Native payments** | [P2PK and P2PKH measurements](../projects/p2pk-p2pkh-baseline/README.md) and [Forth builds](../projects/p2pk-p2pkh-baseline/forth/README.md) |
| **P-256 lock optimization** | P2PKH-R1 v0.6.0 measures 41,364 B per lock and 83,498 B per two-input, two-output BIP143 ALL payment. [P2PKH-R1 results](../projects/p2pkh-r1/README.md#measured-results) |
| **SM2 lock and reconstruction** | P2PKH-SM2 v1.2.0 measures 131,565 B per lock and 287,524 B per two-input, two-output OTDA ALL payment. [SM2 measurements](../projects/p2pkh-sm2/README.md#v120) |
| **Deferred R1 activation** | [Deferred v0.3.0](../projects/p2pkh-r1-deferred/README.md#4thgraph-forth-comparison) uses a 1,085 B funding lock built with `stack` optimization |
| **PELS Counter** | [Build and replay](../projects/pels-counter/README.md) covers the funded `0 → 1 → 2` sequence and rejected mutations |
| **BIP340** | P2PKH-Schnorr v0.7.0 measures 29,660 B per lock and 178,660 B per two-input, two-output Chronicle OTDA ALL payment. [Schnorr results](../projects/p2pkh-schnorr/README.md#measured-sizes) · [Measurements](../projects/p2pkh-schnorr/versions/v0.7.0/measurements.json) · [BIP340 vectors](../projects/p2pkh-schnorr/versions/v0.6.0/bip340-vectors.csv) |
| **Lamport OTS** | The v0.2.0 candidate measures 6,525 B per lock and 48,106 B per two-input, two-output OTDA ALL payment with reconstruction. [Lamport results](../projects/lamport-ots/README.md) · [Versioned measurements](../projects/lamport-ots/versions/v0.2.0/measurements.json) |
| **BLS12-381 Groth16** | [Fixed-statement comparison](../projects/proof-counter/reference/fixed-statement/README.md) and [recorded benchmark](../projects/proof-counter/versions/v0.1.0/measurements.json) |

The [wallet benchmark](../docs/benchmark.md) specifies transaction shapes, measurement and engine pins for cross-project comparisons.
