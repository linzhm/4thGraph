# 4thGraph results

| Result | Evidence and reproduction |
| --- | --- |
| **Native payments** | [P2PK and P2PKH measurements](../projects/p2pk-p2pkh-baseline/README.md) and [Forth builds](../projects/p2pk-p2pkh-baseline/forth/README.md) |
| **P-256 lock optimization** | [P2PKH-R1 results](../projects/p2pkh-r1/README.md#measured-results) report a 41,538 B experimental lock and a 91,692 B OTDA ALL payment |
| **PELS Counter** | [Build and replay](../projects/pels-counter/README.md) covers the funded `0 → 1 → 2` sequence and rejected mutations |
| **BIP340** | [Schnorr locks and signing](../projects/p2pkh-schnorr/README.md) and [fixed BIP340 vectors](../projects/p2pkh-schnorr/template/bip340-vectors.csv) |
| **BLS12-381 Groth16** | [Fixed-statement comparison](../projects/proof-counter/experiments/fixed-statement/README.md) and [recorded benchmark](../projects/proof-counter/experiments/fixed-statement/result.json) |

The [wallet benchmark](../docs/benchmark.md) specifies transaction shapes, measurement and engine pins for cross-project comparisons.
