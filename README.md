# BSV Script Lab

**Bring more signature schemes to BSV wallets. Measure the full cost from receiving to spending.**

BSV Script Lab provides locking templates that wallets can recognize, SDKs that work with external signers, and signed transaction vectors you can replay. Start with native P2PKH, integrate P-256 or SM2, or compare Lamport, WOTS+, and pure ML-DSA-44 using the same benchmark methodology.

**[Wallet SDK quickstart](shared/sdk/README.md#quickstart)** · [Choose a project](#project-index) · [Compare transaction costs](#transaction-costs) · [Reproduce the benchmarks](shared/benchmark.md) · [简体中文](README.zh-CN.md)

<a name="project-index"></a>

## Find the right starting point

| Project | Use it to | Version | Wallet integration |
| --- | --- | --- | --- |
| [Native P2PK and P2PKH](projects/p2pk-p2pkh-baseline/README.md) | Establish a size and signing baseline with native secp256k1 scripts | v0.1 development | [Integration guide](projects/p2pk-p2pkh-baseline/docs/sdk.en.md#quickstart) |
| [P2PKH-R1](projects/p2pkh-r1/README.md) | Pay to a P-256 public-key hash using a fixed locking template | v0.2.0 development | [Integration guide](projects/p2pkh-r1/docs/sdk.en.md#quickstart) |
| [P2PKH-R1-Deferred](projects/p2pkh-r1-deferred/README.md) | Receive funds with a short lock and activate a standard R1 output later | v0.2.0 development | [Integration guide](projects/p2pkh-r1-deferred/docs/sdk.en.md#quickstart) |
| [P2PKH-SM2](projects/p2pkh-sm2/README.md) | Pay with SM2 signatures, accept GB/T 35275-2026 SignedData off-chain, and reconstruct eligible OTDA outputs | v1.0.0 public release | [Integration guide](projects/p2pkh-sm2/docs/sdk.en.md#quickstart) |
| [Lamport OTS](projects/lamport-ots/README.md) | Evaluate SHA-256 one-time signatures with full-key and committed-key locks | v0.1 development | [Integration guide](projects/lamport-ots/docs/sdk.en.md#quickstart) |
| [WOTS+](projects/wots-plus/README.md) | Evaluate one-time signatures built from SHA-256 hash chains | v0.1 development | [Integration guide](projects/wots-plus/docs/sdk.en.md#quickstart) |
| [Pure ML-DSA-44](projects/ml-dsa/README.md) | Evaluate FIPS 204 pure-mode ML-DSA-44 signatures in Script | v0.1 development | [Integration guide](projects/ml-dsa/docs/sdk.en.md#quickstart) |

Start with native P2PKH to run your first payment. The projects share the same wallet calls in TypeScript, Rust, Go, and Python. Each project guide covers its signing request, template options, and local dependencies. [Wallet SDK quickstart](shared/sdk/README.md)

<a name="transaction-costs"></a>

## Compare transaction costs

P2PKH-R1 v0.2.0 reduced the two-input, two-output ForkID ALL benchmark from **119,934 to 93,374 bytes**. Deferred uses a **1,435-byte deposit lock** and creates the full **46,302-byte R1 lock** at activation. The right comparison includes both the bytes paid at each step and the number of steps in the wallet's flow. [R1 results](projects/p2pkh-r1/README.md) · [Deferred results](projects/p2pkh-r1-deferred/README.md)

The unified benchmark measured **260 complete transactions** across seven projects and 32 template and sighash combinations at commit `beeb4dd`. Additional mixed-output and paired `SINGLE` replays measured 88 transactions across 11 combinations. The Deferred v0.2.0 row uses the rerun at `9c5603d`.

| Project and measured template | Inputs × outputs | Prevout lock | Unlock | ForkID ALL tx | OTDA ALL tx | Peak stack payload |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Native P2PKH | 2 × 2 | 25 | 107 | 374 | 374 | 145 |
| P2PKH-R1 v0.2.0 | 2 × 2 | 46,302 | 326 | 93,374 | 101,250 | 3,479 |
| P2PKH-R1-Deferred activation | 3 × 2 | 1,435 | 197 | 93,259 | 93,260 | 359 |
| P2PKH-SM2 v1.0.0 lock | 2 × 2 | 144,925 | 291 | 290,554 | 870,194 literal / 316,018 reconstructed | 4,147 |
| Lamport OTS, committed key | 2 × 2 | 7,746 | 16,549 | 48,708 | 79,616 | 16,707 |
| WOTS+, cached steps with reconstruction | 2 × 2 | 33,956 | 2,310 | 72,650 | 79,090 | 2,701 |
| Pure ML-DSA-44 | 2 × 2 | 926,412 | 2,588 | 1,858,122 | 5,563,725 | — |

All sizes are in bytes. The lock and unlock columns use the first ForkID ALL input. Peak stack payload is the local evaluator's peak combined data size on the main and alternate stacks for that input. ML-DSA-44 stack data is unavailable. Deferred activation includes a fee-sponsor input. Each project README has the per-input and per-output measurements, the cost of adding an input or output, and the lifecycle totals.

The optional SM2 constructor on `main` uses the v1.0.0 lock. It cuts the two-input, two-output OTDA ALL transaction by 63.7% after Chronicle activation in the measured fixture. The project guide covers eligibility, marginal costs, and lifecycle totals. [SM2 reconstruction results](projects/p2pkh-sm2/README.md#otda-constructor)

## Reproduce the results

The benchmark guide shows how to replay signed transactions against BSV Node 1.2.3 and the pinned chain-gang version. Each project links its protocol specification, security analysis, acceptance cases, and SDK. [Benchmark guide](shared/benchmark.md)
