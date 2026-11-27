<!-- Generated from manifest.yaml with Copier. -->

# P2PKH-R1 v0.8.0

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md) · [Versions](versions/index.json)

## Developer resources

**[Wallet SDK quickstart](docs/sdk.en.md#quickstart)** · [Unified wallet SDK](../../sdk/README.md#quickstart)

P2PKH-R1 lets a BSV wallet use an existing P-256 signer. The output commits to the recipient's public-key HASH160. A spend supplies the uncompressed public key and a 64-byte ECDSA signature in `r || s` format.

[Protocol](docs/spec.en.md) · [Algorithm and execution](#algorithm-and-execution) · [Reproduce the checks](#reproduce-the-checks) · [Complete transactions and stack measurements](#complete-transactions-and-stack-measurements) · [Measurements data](versions/v0.8.0/measurements.json)

| Entry point | Purpose |
| --- | --- |
| `locking_script_from_public_key` | Build the selected wallet template from an uncompressed P-256 public key. |
| `sign_payment` | Authorize a payment using an external P-256 digest signer. |

## Algorithm and execution

[Protocol](docs/spec.en.md) · [Security](docs/developer.en.md#security) · [Verification](reference/acceptance.md)

The payment lock checks the revealed public key against the owner HASH160, verifies the P-256 signature in Script, and binds the signed digest to the current input. [Wire specification](docs/spec.en.md)

## Reproduce the checks

Run the release commands from the repository root in the compiler experiment environment. [Dependencies and replay profiles](forth/README.md)

```sh
PYTHONPATH=src:.:projects/p2pkh-r1/reference python projects/p2pkh-r1/forth/compile_r1.py --entry r1-baseline-lock --replay-plan projects/p2pkh-r1/versions/v0.8.0/plan.json
PYTHONPATH=src:.:projects/p2pkh-r1/reference bash tools/verify_node.sh --profile raised -- python projects/p2pkh-r1/forth/msm_experiment.py compare --workflow explicit --matrix --candidate v0.7.0 --candidate v0.8.0 --budget 2 --full-budget 2
```

The selected compiler release and the wallet’s default template have separate manifests. Use the compiler guide for the full replay procedure and the acceptance record for the payment matrix. [Compiler experiment](forth/README.md) · [Payment acceptance](reference/acceptance.md)

## Developer and wallet integration

### Wallet integration

Select **v0.8.0** to use the current compiler template with the unified SDK in TypeScript, Rust, Go, or Python. The default wallet template is v0.2.0. For an existing P-256 signer, confirm its digest interface and signature encoding, and persist nonce-reuse history across signing processes. [SDK guide](docs/sdk.en.md) · [Reference wallet](reference/README.md) · [v0.8.0 layout](versions/v0.8.0/layout.json)

R1 creates the full lock at funding so the recipient can pay in one spend. Deferred R1 uses a smaller deposit lock and a separate activation transaction. [Deferred workflow](../p2pkh-r1-deferred/README.md)

## Complete transactions and stack measurements

<a name="version-history"></a>

<a name="forth-experiment"></a>

### Measured results

#### v0.7.0 → v0.8.0

**v0.8.0** saves **148 B per lock**, **296 B per BIP143 ALL payment**, and **1,020 B per OTDA payment** in each of the two measured OTDA modes. Payment sizes count the two-input, two-output spend. [Version manifest](versions/v0.8.0/manifest.json) · [Build and replay](forth/README.md)

| Version | Compiler construction | Lock | BIP143 ALL payment | OTDA ALL payment | OTDA SINGLE payment |
| --- | --- | ---: | ---: | ---: | ---: |
| v0.7.0 | Affine fixed table with a shorter zero guard | 41,262 B | 83,294 B | 94,632 B | 94,561 B |
| **v0.8.0** | Compact fixed table and shared OTDA fragments | **41,114 B** | **82,998 B** | **93,612 B** | **93,541 B** |

The compiler stores only X and Y in the fixed-generator table, using its proof that nonzero entries have `Z=1`. The OTDA constructor reuses repeated byte strings and reconstructs the same lock byte for byte. The iteration reuses the existing Forth source. Funded BSV Node and independent chain-gang replay passed for all three modes. The selected template also passed the R1 acceptance matrix. [Forth entry](forth/r1-baseline.fth) · [Optimization plan](versions/v0.8.0/plan.json) · [Version comparison](versions/v0.8.0/comparison.json) · [Acceptance matrix](reference/acceptance.md)

<details>
<summary>Earlier version iterations</summary>

Each row shows the validated template selected that round. Payments use two inputs and two outputs.

| Previous selection | Selected template | Main improvement | Lock | BIP143 ALL | OTDA ALL |
| --- | --- | --- | ---: | ---: | ---: |
| — | v0.1.0 | First fixed lock with literal OTDA preimages | 59,582 B | 119,934 B | 358,194 B |
| v0.1.0 | v0.2.0 | Reschedule P-256 arithmetic and share curve kernels in OTDA reconstruction | 46,302 B | 93,374 B | 101,250 B |
| v0.2.0 | Forth v0.3.0 | Generate the full lock from Forth and shorten 263 point doublings | 45,776 B | 92,322 B | 100,192 B |
| Forth v0.3.0 | Forth v0.4.0 | Express point arithmetic as bounded formulas and let the compiler rewrite and schedule them | 42,536 B | 85,842 B | 93,664 B |
| Forth v0.4.0 | v0.5.0 (`split-5x4`) | Compile the double-scalar multiplication with a 5-bit fixed table and a 4-bit public-key table to reduce loop additions | 41,721 B | 84,212 B | 95,282 B |
| v0.5.0 | v0.6.0 | Prove `Z=1` for nonzero fixed-generator entries and specialize 51 point additions | 41,364 B | 83,498 B | 94,864 B |
| v0.6.0 | v0.7.0 | Shorten the zero-digit guard at each fixed-generator lookup | 41,262 B | 83,294 B | 94,632 B |

The main sequence selects templates by lock and BIP143 payment size. The window iteration also selected `joint-2` for OTDA, where it still gives a 91,692 B two-input, two-output payment. [Window replay results](versions/v0.6.0/comparison.json)

In v0.4.0, the Forth names values in the formula. After computing `xx = x1*x2` and `yy = y1*y2`, the source expresses a cross term that can be expanded algebraically:

```diff
- x1 y1 int+ x2 y2 int+ int* xx int- yy int- let xy
+ x1 y2 int* x2 y1 int* int+ let xy
```

Expanding all three cross terms reduces unoptimized point addition from 392 B to 345 B. Once the compiler learned that identity, the original formula compiled to 123 B with rewriting and stack scheduling enabled. The full lock from the original source measures 117,775 B with optimization off and 42,536 B with it on. The next round used the high-level double-scalar multiplication to let the compiler choose windows and specialize fixed-table additions. [Forth formulas](forth/r1.fth) · [Historical benchmarks](forth/history.md)

</details>
