# High-level Forth BIP340 experiment

[简体中文](high-level-forth.zh-CN.md) · [Project overview](../README.md) · [Payment format](spec.en.md)

This page tracks compilation and transaction replay from the binary Forth verifier through the tuned 64-window build. The wallet defaults to the published v0.17.0 template. [Recorded comparison and hashes](../experiments/high-level/witness-ordinate-check.json) · [Wallet integration](sdk.en.md#quickstart)

[OTDA constructor](#otda-constructor) · [Replay commands](#replay) · [Optimization history](#optimization-history)

<a name="otda-constructor"></a>

## OTDA constructor

All rows below spend two Schnorr outputs and create two Schnorr outputs with OTDA ALL (`0x61`). Each input rebuilds its full signing preimage from the recognized template fragments and the ordered output amounts and owner hashes. The reconstructed stack values equal those from the literal witness. The constructor changes the serialized unlock and thus the transaction ID. [Constructor implementation](../../../src/fourthgraph/bsv/otda_reconstruction.py)

| Build | Payment lock | Reconstructed transaction | Unlock per input |
| --- | ---: | ---: | ---: |
| Released v0.17.0 | 22,435 B | 54,626 B | 4,819 B |
| Tuned Forth, paired ordinate check | 22,434 B | 54,622 B | 4,818 B |

The released template also has a funded default-policy regtest replay. The tuned build is exercised with the experimental constructor on supplied prevouts under raised regtest policy. BSV Node 1.2.3 and chain-gang checked eight constructor scenarios, 46 extended scenarios, and two OTDA SINGLE companion cases for that build. [Release admission](../README.md#measured-sizes) · [Tuned replay summary](../experiments/high-level/witness-ordinate-check.json)

<a name="compiler-selection-across-transaction-types"></a>

### Constructor selection across transaction types

The selector compares literal pushes, repeated-preimage expansion, per-template dictionaries, and dictionaries with shared prefixes or suffixes. The frozen 54-case matrix contains 87 distinct signed encodings. It covers consolidation, fan-out, change, mixed native and Schnorr inputs and outputs, mixed lock versions, all 12 paired sighash modes in transaction versions 1 and 2, mixed modes in one transaction, pre-activation funding, and the 252/253-output CompactSize boundary. Its automatic input is the historical binary Forth build. [Selector](../../../src/fourthgraph/compiler/preimage.py) · [Frozen matrix](../experiments/high-level/constructor-matrix.json)

| Historical OTDA ALL fixture | Literal transaction | Per-template constructor | Selected encoding |
| --- | ---: | ---: | ---: |
| Three release templates and a native output | 226,887 B | 106,729 B | 99,237 B |
| Binary Forth, two-input, two-output turnover | 1,312,926 B | 446,920 B | 446,920 B |
| Binary Forth and released templates with a native output | 724,224 B | 259,686 B | 258,122 B |

<a name="environment-and-inputs"></a>
<a name="build-and-replay"></a>
<a name="replay"></a>

## Replay

Run from the repository root with Python 3.12 and the project's pinned chain-gang 0.13.2 at `74676b9`. The wrapper starts a BSV Node 1.2.3 regtest. The tuned receipt pins source revision `8f4c5e3` and compiler version 0.2.7. Use that checkout for exact historical sizes and hashes. [Project setup](../README.md#validate-the-baseline) · [Tuned receipt](../experiments/high-level/witness-ordinate-check.json)

```sh
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised --   "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py   --joint-lowerings --forth-tuning --output workspace/schnorr-high-level/tuned-measurements.json

REGTEST_CHRONICLE_HEIGHT=5 PYTHONPATH=src:. bash tools/verify_node.sh --profile raised --   "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py   --joint-lowerings --forth-tuning --matrix-only --output workspace/schnorr-high-level/tuned-matrix.json
```

The first command compiles the candidates and checks detached verification, complete payments, locktime mutations, and both witness encodings for the two-input, two-output fixture. The second runs the eight automatic-template constructor scenarios, including output and sequence mutations. The separate extended run is recorded in the tuned receipt. [Comparison runner](../experiments/high-level/window_compare.py) · [Fixture definitions](../experiments/high-level/constructor_matrix.py)

Replay the historical binary compiler comparison at revision `38616d7` with `compare.py --output workspace/schnorr-high-level --samples 12`. The historical constructor comparison uses revision `7bc0538` and `compare_otda.py --output workspace/schnorr-high-level/otda-measurements.json`. The frozen 54-case matrix uses revision `9dfc719` and `constructor_matrix.py --output workspace/schnorr-high-level/constructor-matrix.json` with `REGTEST_CHRONICLE_HEIGHT=5`. [Binary runner](../experiments/high-level/compare.py) · [Constructor runner](../experiments/high-level/compare_otda.py) · [Historical evidence](../experiments/high-level/otda-measurements.json)

<a name="measurements-and-evidence"></a>
<a name="optimization-history"></a>

## Optimization history

The binary source implements the BIP340 equation with a 256-round joint multiplication. Both doubling and addition use a complete homogeneous formula. Automatic compilation reduced the payment lock from 433,567 B to 218,701 B. The 2×2 OTDA ALL constructor result went from 880,172 B to 446,920 B. Both binary builds and v0.17.0 used literal witnesses for the 348 B native OTDA exit. [Verifier source](../experiments/high-level/verifier.fth) · [Binary timings and sizes](../experiments/high-level/measurements.json) · [Historical constructor evidence](../experiments/high-level/otda-measurements.json)

The following milestones use the same two-input, two-output OTDA ALL constructor fixture. Each link leads to the measured build and its controls.

<a name="64-window-lowering"></a>

### 64-window lowering

The source switches to four 128-bit lanes by splitting the generator scalar and applying GLV to the public-key scalar. A separately compiled joint multiply is linked into the verifier. The lock is 43,999 B and the transaction is 107,404 B. [Measurements](../experiments/high-level/window-measurements.json)

<a name="joint-lowering-candidates"></a>

### Joint lowering candidates

The scaled stack-table variant wins the initial four-way comparison of the reference, packed bytes, stack, and scaled stack layouts. The lock is 26,639 B and the transaction is 71,442 B. [Measurements](../experiments/high-level/joint-lowerings.json)

<a name="dataflow-iteration"></a>

### Dataflow iteration

Direct table construction, dead-value cleanup, and batch decoding of six fixed-width fields remove work around the window loop. The lock is 23,484 B and the transaction is 58,822 B. [Measurements](../experiments/high-level/dataflow-measurements.json)

<a name="stack-and-model-boundaries"></a>

### Stack and model boundaries

The scheduler groups operand moves and reuses retained values at curve call boundaries. The scale lowering compares bounded forms. The lock is 23,190 B and the transaction is 57,646 B. [Measurements](../experiments/high-level/boundary-measurements.json)

<a name="point-comparison-models"></a>

### Point comparison models

Mapping both affine points to the working model produces the smallest measured lock among the three endpoint comparison strategies. The lock is 23,161 B and the transaction is 57,530 B. [Measurements](../experiments/high-level/model-output-measurements.json)

<a name="source-tuning-for-the-64-window-verifier"></a>

### Source tuning for the 64-window verifier

Explicit layouts carry the same field prime through witness checks, curve validation, and coordinate mapping. The lock is 22,992 B and the transaction is 56,854 B. [Measurements](../experiments/high-level/forth-tuning-measurements.json)

<a name="sharing-the-endomorphism-at-two-row-starts"></a>

### Sharing the endomorphism at two row starts

One Forth formula maps both projective row starts, 2Q and 3Q. The lock is 22,940 B and the transaction is 56,646 B. [Measurements](../experiments/high-level/table-tuning-measurements.json)

<a name="sharing-beta-across-all-variable-table-row-starts"></a>

### Sharing β across all variable-table row starts

The mapping also returns Q and passes the same endomorphism constant to all three row starts. The lock is 22,902 B and the transaction is 56,494 B. [Measurements](../experiments/high-level/window-beta-measurements.json)

<a name="packing-the-fixed-base-scalar-directly"></a>

### Packing the fixed-base scalar directly

The fixed-base scalar is encoded once and then split into its two byte lanes. The lock is 22,855 B and the transaction is 56,306 B. [Measurements](../experiments/high-level/fixed-scalar-measurements.json)

<a name="sharing-the-group-order-with-the-glv-split"></a>

### Sharing the group order with the GLV split

The Forth verifier passes the group order already used by challenge reduction to the GLV split. The lock is 22,832 B and the transaction is 56,214 B. [Measurements](../experiments/high-level/shared-order-measurements.json)

<a name="scheduling-named-layouts-with-dataflow"></a>

### Scheduling named layouts with dataflow

The general scheduler follows declared value identities across layouts and calls, including multiple results. The three table bodies drop from 348 B to 264 B each. The lock is 22,465 B and the transaction is 54,746 B. [Measurements](../experiments/high-level/layout-dataflow-measurements.json)

<a name="variable-table-row-starts"></a>

### Reusing unchanged variable-table coordinates

The secp256k1 library emits only transformed coordinates. The curve lowering supplies the existing affine Y and three Z values from the table. The lock is 22,436 B and the transaction is 54,630 B. [Measurements](../experiments/high-level/row-start-layout.json)

<a name="paired-witness-ordinate-check"></a>

### Checking both witness ordinates together

The Schnorr Forth source checks the sum of the two unsigned remainders modulo 2 once. The independent parity fixture covers both odd values as well as each one alone. [Current transaction sizes](#otda-constructor) · [Measurements](../experiments/high-level/witness-ordinate-check.json)
