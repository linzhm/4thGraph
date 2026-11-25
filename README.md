# BSV Script Lab

**Bring more signature schemes to BSV wallets. Measure the full cost from receiving to spending.**

BSV Script Lab gives wallet teams recognizable locking templates, a shared SDK for external signers, and complete signed transactions they can replay. It covers ordinary payments, integration with P-256 and SM2 signers, deferred activation, and experiments with one-time and post-quantum signatures.

**[Wallet SDK quickstart](shared/sdk/README.md#quickstart)** · [Choose a project](#project-index) · [Compare transaction costs](#transaction-costs) · [Reproduce the benchmarks](shared/benchmark.md) · [简体中文](README.zh-CN.md)

<a name="project-index"></a>

## Find the right starting point

| Project | Where it fits | Integration decision | Version | Wallet SDK |
| --- | --- | --- | --- | --- |
| [Native P2PK and P2PKH](projects/p2pk-p2pkh-baseline/README.md) | A first wallet integration, ordinary secp256k1 payments, or a cost baseline | Choose whether the output carries a public key or its hash | v0.1 development | [Integration guide](projects/p2pk-p2pkh-baseline/docs/sdk.en.md#quickstart) |
| [P2PKH-R1](projects/p2pkh-r1/README.md) | A wallet integration with an existing P-256 signing device or service | Verify its signing mode and keep persistent P-256 nonce history | v0.2.0 development | [Integration guide](projects/p2pkh-r1/docs/sdk.en.md#quickstart) |
| [P2PKH-R1-Deferred](projects/p2pkh-r1-deferred/README.md) | Receive funds into short locks when a separate activation can wait | Budget a fee-paying input and a second step to create the full R1 output | v0.2.0 development | [Integration guide](projects/p2pkh-r1-deferred/docs/sdk.en.md#quickstart) |
| [P2PKH-SM2](projects/p2pkh-sm2/README.md) | A wallet that integrates an SM2 signer or a GB/T 35275-2026 SignedData provider | Match the SM2 message and user ID, and bind the expected signer identity for SignedData | v1.1.0 candidate | [Integration guide](projects/p2pkh-sm2/docs/sdk.en.md#quickstart) |
| [Lamport OTS](projects/lamport-ots/README.md) | A SHA-256 one-time-signature experiment that exposes the cost of storing or revealing a public key | Reserve a fresh key per UTXO and choose between cheaper funding and cheaper inputs | v0.1 development | [Integration guide](projects/lamport-ots/docs/sdk.en.md#quickstart) |
| [WOTS+](projects/wots-plus/README.md) | A SHA-256 one-time-signature experiment with a smaller signature and several receive templates | Manage one-time keys and compare cached output code and OTDA reconstruction | v0.1 development | [Integration guide](projects/wots-plus/docs/sdk.en.md#quickstart) |
| [Pure ML-DSA-44](projects/ml-dsa/README.md) | A FIPS 204 interoperability or large-script experiment | Use a Pure ML-DSA-44 signer and validate relay and mining policy for large locks | v0.1 development | [Integration guide](projects/ml-dsa/docs/sdk.en.md#quickstart) |

Start with native P2PKH to run your first payment. The unified SDK uses the same wallet workflow in TypeScript, Rust, Go, and Python. Follow a project guide to connect your signer, choose a template, and replay the appropriate payment or activation. [Wallet SDK quickstart](shared/sdk/README.md)

<a name="transaction-costs"></a>

## Compare transaction costs

P2PKH-R1 v0.2.0 reduced the two-input, two-output ForkID ALL benchmark from **119,934 to 93,374 bytes**. Deferred uses a **1,435-byte deposit lock** and creates the full **46,302-byte R1 lock** at activation. The right comparison includes both the bytes paid at each step and the number of steps in the wallet's flow. [R1 results](projects/p2pkh-r1/README.md) · [Deferred results](projects/p2pkh-r1-deferred/README.md)

The unified benchmark measured **260 complete transactions** across seven projects and 32 template and sighash combinations at commit `beeb4dd`. Additional mixed-output and paired `SINGLE` replays measured 88 transactions across 11 combinations. The Deferred v0.2.0 row uses the rerun at `9c5603d`.

| Project and measured version | Inputs × outputs | Prevout lock | ForkID ALL unlock | ForkID ALL tx | OTDA ALL tx | ForkID ALL peak stack payload |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Native P2PKH | 2 × 2 | 25 | 107 | 374 | 374 | 145 |
| P2PKH-R1 v0.2.0 | 2 × 2 | 46,302 | 326 | 93,374 | 101,250 | 3,479 |
| P2PKH-R1-Deferred activation | 3 × 2 | 1,435 | 197 | 93,259 | 93,260 | 359 |
| P2PKH-SM2 v1.1.0 candidate | 2 × 2 | 144,925 | 291 | 290,554 | 316,018 | 4,147 |
| Lamport OTS, committed key | 2 × 2 | 7,746 | 16,549 | 48,708 | 79,616 | 16,707 |
| WOTS+, cached steps with reconstruction | 2 × 2 | 33,956 | 2,310 | 72,650 | 79,090 | 2,701 |
| Pure ML-DSA-44 | 2 × 2 | 926,412 | 2,588 | 1,858,122 | 5,563,725 | — |

All sizes are in bytes. Lock, unlock, and stack measurements use the first ForkID ALL input. Peak stack payload is the local evaluator's peak combined data size on the main and alternate stacks. Deferred activation includes a fee-sponsor input. ML-DSA-44 stack data is unavailable. Each project README has the per-input and per-output measurements, the cost of adding an input or output, and the lifecycle totals.

The OTDA ALL measurements for R1 v0.2.0 and cached-steps WOTS+ use explicit reconstruction.

The SM2 candidate uses locking template `1` from v1.0.0 and automatically selects a shorter OTDA unlocking script when available. In the measured OTDA ALL transaction, reconstruction reduces the unlock from 290,109 to 13,023 bytes per input. The complete transaction drops from 870,194 to 316,018 bytes, a 63.7% reduction. [SM2 reconstruction results](projects/p2pkh-sm2/README.md#otda-constructor)

## Reproduce the results

The benchmark guide shows how to replay signed transactions against BSV Node 1.2.3 and the pinned chain-gang version. Each project links its protocol specification, security analysis, acceptance cases, and SDK. [Benchmark guide](shared/benchmark.md)
