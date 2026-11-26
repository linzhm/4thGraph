# P2PKH-R1

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md)

P2PKH-R1 lets a BSV wallet use an existing P-256 signer. The output commits to the recipient's public-key HASH160. A spend supplies the uncompressed public key and a 64-byte ECDSA signature in `r || s` format.

**[Wallet SDK quickstart](docs/sdk.en.md#quickstart)** · [Protocol](docs/spec.en.md) · [Security](docs/developer.en.md#security) · [Verification](reference/acceptance.md)

<a name="version-history"></a>
<a name="complete-transactions-and-stack-measurements"></a>
<a name="forth-experiment"></a>

## Measured results

### Latest iteration

**`split-5x4-affine-g`** is the validated experimental template selected this round. The lock is **357 B smaller** than the previous selection, and a two-input, two-output ForkID ALL payment is **714 B smaller**. [Build and replay](experiments/forth/README.md)

| Iteration | Template | Lock | ForkID ALL payment | OTDA ALL payment |
| --- | --- | ---: | ---: | ---: |
| Previous | `split-5x4` | 41,721 B | 84,212 B | 95,282 B |
| Latest | `split-5x4-affine-g` | **41,364 B** | **83,498 B** | **94,864 B** |

The same high-level Forth calls `P256.mul2(u,G,v,Q)`. The compiler uses `Z=1` for nonzero entries in the fixed-generator table to specialize 51 additions and handles the zero index separately. The new template passed funded BSV Node and independent chain-gang replay and acceptance for ForkID ALL, OTDA ALL, and paired OTDA SINGLE. [High-level source](experiments/forth/msm.fth) · [Acceptance matrix](reference/acceptance.md)

<details>
<summary>Earlier version iterations</summary>

Each row shows the validated template selected that round. Payment figures use two inputs and two outputs. Forth window experiments use their reproducible template names.

| Previous selection | Selected template | Main improvement | Lock | ForkID ALL | OTDA ALL |
| --- | --- | --- | ---: | ---: | ---: |
| — | v0.1.0 | First fixed lock with literal OTDA preimages | 59,582 B | 119,934 B | 358,194 B |
| v0.1.0 | v0.2.0 | Reschedule P-256 arithmetic and share curve kernels in OTDA reconstruction | 46,302 B | 93,374 B | 101,250 B |
| v0.2.0 | Forth v0.3.0 | Generate the full lock from Forth and shorten 263 point doublings | 45,776 B | 92,322 B | 100,192 B |
| Forth v0.3.0 | Forth v0.4.0 | Express point arithmetic as bounded formulas and let the compiler rewrite and schedule them | 42,536 B | 85,842 B | 93,664 B |
| Forth v0.4.0 | `split-5x4` | Compile the double-scalar multiplication with a 5-bit fixed table and a 4-bit public-key table to reduce loop additions | 41,721 B | 84,212 B | 95,282 B |

The main sequence selects templates by lock and ForkID payment size. The window iteration also selected `joint-2` for OTDA, where it still gives a 91,692 B two-input, two-output payment. [Window replay results](experiments/forth/results.json)

In v0.4.0, the Forth names values in the formula. After computing `xx = x1*x2` and `yy = y1*y2`, the source expresses a cross term that can be expanded algebraically:

```diff
- x1 y1 int+ x2 y2 int+ int* xx int- yy int- let xy
+ x1 y2 int* x2 y1 int* int+ let xy
```

Expanding all three cross terms reduces unoptimized point addition from 392 B to 345 B. Once the compiler learned that identity, the original formula compiled to 123 B with rewriting and stack scheduling enabled. The full lock from the original source measures 117,775 B with optimization off and 42,536 B with it on. The next round used the high-level double-scalar multiplication to let the compiler choose windows and specialize fixed-table additions. [Forth formulas](experiments/forth/r1.fth) · [Historical benchmarks](experiments/forth/history.md)

</details>

## Wallet integration

The reference wallet uses **v0.2.0** for new outputs and can spend existing v0.1.0 outputs. Use the unified SDK in TypeScript, Rust, Go, or Python. For an existing P-256 signer, confirm its digest interface and signature encoding, and persist nonce-reuse history across signing processes. [SDK guide](docs/sdk.en.md) · [Reference wallet](reference/README.md) · [Wallet template](template/v0.2.0/layout.json)

R1 creates the full lock at funding so the recipient can pay in one spend. Deferred R1 uses a smaller deposit lock and a separate activation transaction. [Deferred workflow](../p2pkh-r1-deferred/README.md)
