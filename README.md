# BSV Script Lab

**Add more signing options to your BSV wallet and compare transaction costs before you integrate.**

BSV Script Lab gives wallet and payment infrastructure teams locking templates, reference implementations, and reproducible benchmarks for P-256, SM2, hash-based signatures, and ML-DSA-44. Compare the cost of receiving, transferring, and spending funds, then check your integration against the project's signed transaction vectors.

[Explore projects and costs](#project-index) · [Reproduce the benchmarks](shared/benchmark.md) · [简体中文](README.zh-CN.md)

<a name="project-index"></a>

## Cross-project statistics

The unified runner measured **7 projects, 32 template and sighash combinations, and 260 complete transactions** at commit `beeb4dd`. The mixed-output and paired `SINGLE` replays add **11 combinations and 88 transactions**. The table shows selected baselines and candidates in bytes. Script and stack columns use the first ForkID ALL input. The Deferred activation shape includes one sponsor input. The Deferred v0.2.0 row was rerun at commit `9c5603d`.

| Project | Template | Release status | Inputs×outputs | First prevout lock | First unlock | ForkID ALL | OTDA ALL | Stack payload |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [Native P2PK and P2PKH](projects/p2pk-p2pkh-baseline/README.md) | `p2pk` | v0.1 | 2×2 | 35 | 73 | 326 | 325 | 105 |
| [Native P2PK and P2PKH](projects/p2pk-p2pkh-baseline/README.md) | `p2pkh` | v0.1 | 2×2 | 25 | 107 | 374 | 374 | 145 |
| [P2PKH-R1](projects/p2pkh-r1/README.md) | `v0.2.0` | v0.2.0 | 2×2 | 46,302 | 326 | 93,374 | 101,250 | 3,479 |
| [P2PKH-R1-Deferred](projects/p2pkh-r1-deferred/README.md) | `hash-only` | v0.2.0 | 3×2 | 1,435 | 197 | 93,259 | 93,260 | 359 |
| [P2PKH-SM2](projects/p2pkh-sm2/README.md) | `v1.0.0` | v1.0.0 | 2×2 | 144,925 | 291 | 290,554 | 870,194 | 4,147 |
| [Lamport OTS](projects/lamport-ots/README.md) | `full-key` | v0.1 | 2×2 | 22,780 | 8,357 | 62,392 | 153,436 | 8,515 |
| [Lamport OTS](projects/lamport-ots/README.md) | `committed-key` | v0.1 | 2×2 | 7,746 | 16,549 | 48,708 | 79,616 | 16,707 |
| [WOTS+](projects/wots-plus/README.md) | `canonical` | v0.1 | 2×2 | 42,266 | 2,310 | 89,270 | 258,266 | 2,599 |
| [WOTS+](projects/wots-plus/README.md) | `cached-steps-reconstructed` | v0.1 | 2×2 | 33,956 | 2,310 | 72,650 | 79,090 | 2,701 |
| [Pure ML-DSA-44](projects/ml-dsa/README.md) | `pure-ml-dsa-44` | v0.1 | 2×2 | 926,412 | 2,588 | 1,858,122 | 5,563,725 | — |

v0.1 and v0.2.0 are development versions. SM2 v1.0.0 is a public release. Each project README links its protocol, security, validation, and integration guides.
