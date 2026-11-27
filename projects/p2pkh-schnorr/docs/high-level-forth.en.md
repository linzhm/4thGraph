# High-level Forth BIP340 experiment

[简体中文](high-level-forth.zh-CN.md) · [Project overview](../README.md)

## Environment and inputs

The experiment uses 4thGraph 0.2.7 from compiler revision `64624db`, Python 3.12 with the Schnorr project requirements, BSV Node 1.2.3, and chain-gang 0.13.2 at `74676b9`. Run the commands from the repository root. [Project setup](../README.md#validate-the-baseline)

The high-level verifier checks the public witnesses, computes the tagged challenge, and evaluates `sG + (n − e)P`. It uses a 256-round binary loop and the same complete homogeneous addition formula for doubling, adding the generator, and adding the public key. It checks both coordinates of the even nonce and rejects infinity. The field ranges bound signed Script remainders. The top-level verifier validates the untrusted witness bytes before they reach the point formulas. [Verifier Forth](../experiments/high-level/verifier.fth) · [Arithmetic Forth](../experiments/high-level/arithmetic.fth)

Both high-level builds use the same Forth source, external signer, and payment wrapper. The wrapper verifies ownership and binds the signature to the actual current input. Every test payment supplies its complete literal signing preimage. The handwritten v0.17.0 build uses a different multiplication algorithm with GLV, a fixed generator split, and window tables. [Payment format](spec.en.md)

## Build and replay

Use the project interpreter from the setup instructions.

```sh
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/compare.py \
  --output workspace/schnorr-high-level --samples 12
```

The runner compares 17 compiler plans, including the source baseline with optional passes disabled, automatic selection, and explicit pass plans. It checks each byte-distinct artifact in both engines against all 19 pinned BIP340 vectors, eight malformed witnesses, all 12 paired payment modes, and native P2PKH exits. Changing the locktime after signing must fail for every payment. The output directory contains the emitted scripts, a comparison report with SHA-256 fingerprints and engine results, and the selected formula schedule trace. A fresh traced compile must reproduce the winning bytes. [Comparison runner](../experiments/high-level/compare.py)

## Measurements and evidence

| Build | Detached verifier | Payment lock | Complete point addition |
| --- | ---: | ---: | ---: |
| High-level Forth with optional passes disabled | 432,757 B | 433,567 B | 311 B |
| High-level Forth with automatic optimization | 217,891 B | 218,701 B | 96 B |
| Handwritten v0.17.0 | 21,625 B | 22,435 B | — |

The optional passes save **214,866 B (49.6%)** in the payment lock. The point formula accounts for 215 B of savings per occurrence across 768 emitted calls. Each loop contains two conditional additions, which contribute to lock size regardless of whether a given signature executes them. The measured high-level lock remains 9.75 times the size of v0.17.0. The tested passes simplify formulas and schedule stack access within the source algorithm. [Recorded measurements](../experiments/high-level/measurements.json)

| Complete signed transaction | High-level baseline | Automatic | Handwritten v0.17.0 |
| --- | ---: | ---: | ---: |
| 2×2 BIP143 ALL | 867,914 B | 438,182 B | 45,646 B |
| 2×2 OTDA ALL | 2,602,122 B | 1,312,926 B | 135,310 B |
| 1×1 native P2PKH exit, BIP143 / OTDA | 416 / 348 B | 416 / 348 B | 416 / 348 B |

An OTDA ALL witness includes the serialized outputs, so smaller destination locks also shrink each signing preimage. For the 2×2 BIP143 fixture, the high-level build's input-zero stack peaks dropped from 62 to 44 main items and from 3,351 to 1,236 bytes of combined stack payload. The development evaluator measures those peaks. BSV Node and chain-gang independently verify the complete inputs using the supplied prevouts. [Stack and transaction records](../experiments/high-level/measurements.json)

For 12 alternating detached verification runs per build and engine, chain-gang medians were 16.381 ms for the high-level baseline, 11.627 ms for the automatic build, and 3.308 ms for v0.17.0. BSV Node medians were 132.240, 83.314, and 13.953 ms. These host-specific RPC timings include serialization and transmission of the previous output lock. [Paired measurements](../experiments/high-level/measurements.json)

<a name="otda-constructor"></a>

## OTDA constructor

The same 2×2 OTDA ALL transactions were replayed with output constructors. Each constructor stores the recognized template fragments once per input and assembles the original ordered outputs with their amounts and owner hashes. It expands repeated byte ranges in the template using Script byte concatenation. The signer and locking script see the same complete preimage in both encodings. [Preimage construction](../../../src/fourthgraph/bsv/otda_reconstruction.py)

| Build | Literal transaction | Reconstructed transaction | Reconstructed unlock per input |
| --- | ---: | ---: | ---: |
| v0.17.0 | 135,310 B | 54,626 B | 4,819 B |
| High-level baseline | 2,602,122 B | 880,172 B | 6,458 B |
| High-level automatic | 1,312,926 B | 446,920 B | 4,698 B |

The native P2PKH exit uses a literal witness and measures 348 B for all three builds. Only the frozen release templates participate in default wallet recognition. The high-level builds use the constructor in the experiment. To replay funded admission with the release template, use `v0.17.0-reconstructed` as the template in the project overview’s admission command.

```sh
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/compare_otda.py \
  --output workspace/schnorr-high-level/otda-measurements.json
```

[Comparison evidence](../experiments/high-level/otda-measurements.json)

## Compiler selection across transaction types

The compiler compares literal, repeated preimage, template, and shared-template encodings for the same complete preimage. Shared templates can copy a common prefix or suffix from an earlier dictionary entry. The 54-case matrix exercises 87 distinct signed encodings and compares against the previous per-template constructor. It includes consolidation, fan-out, change, mixed native inputs and outputs, mixed lock versions, all 12 sighash modes in transaction versions 1 and 2, mixed modes within a transaction, pre-activation funding, and the 252/253-output CompactSize boundary. The automatic Forth build is reproduced by its frozen hash. The released build serves as a control.

| OTDA ALL case | Literal | Per-template constructor | Compiler selection |
| --- | ---: | ---: | ---: |
| Three release templates, plus a native output | 226,887 B | 106,729 B | 99,237 B |
| Automatic Forth 2×2 turnover | 1,312,926 B | 446,920 B | 446,920 B |
| Automatic Forth and release templates, plus a native output | 724,224 B | 259,686 B | 258,122 B |

Each variant is independently checked with its supplied prevouts. The matrix records the expected effect of changing an amount, output order, locktime or input sequence on the chosen sighash modes. It measures verification under the raised regtest profile. [Matrix evidence](../experiments/high-level/constructor-matrix.json)

```sh
REGTEST_CHRONICLE_HEIGHT=5 PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/constructor_matrix.py \
  --output workspace/schnorr-high-level/constructor-matrix.json
```

<a name="64-window-lowering"></a>

## Curve-aware 64-window lowering

The second high-level version splits the generator scalar as `s = s0 + 2^128 s1` and uses the secp256k1 GLV relation `k = k1 + λk2 mod n`. Two indexed point tables cover the two-bit digits of the four 128-bit lanes. Each of the 64 windows doubles the accumulator twice and adds one point from each table. Index zero represents infinity. The Forth uses the same generated complete point-add formula as the high-level binary verifier. The compiler generates the fixed table from the curve generator and links the standard GLV split. [Joint lowering](../../../src/fourthgraph/compiler/secp256k1-joint.fth) · [BIP340 wrapper](../experiments/high-level/window-verifier.fth)

| Build | Payment lock | 2×2 OTDA ALL using the template constructor |
| --- | ---: | ---: |
| High-level binary, automatic | 218,701 B | 446,920 B |
| High-level 64 windows, optional passes disabled | 114,753 B | 264,448 B |
| High-level 64 windows, inline automatic | 56,414 B | 137,720 B |
| High-level 64 windows, separately compiled and linked | 43,999 B | 107,404 B |
| Handwritten v0.17.0 | 22,435 B | 54,626 B |

Switching the algorithm under automatic compilation saves 162,287 B per lock. Compiling the same joint word separately and linking it saves another 12,415 B. The linked build uses typed layouts for table access and generic point addition. The hand-tuned control uses compact stack lookups, specialized doubling and mixed addition. These choices account for further implementation differences within the 64-window algorithm.

The table and measurement file record the compiler at commit `7882fb7`. Run the commands below from that checkout to reproduce the recorded Script bytes. With the shared stack scheduler changes in #109, the same replay emits 113,983 B for the build with optional passes disabled and 55,644 B for the automatic inline build. The linked build still emits 43,999 B. [Measurement checkout](https://github.com/linzhm/4thGraph/tree/7882fb793b1d354614df9210b59b8c30037f2343) · [PR #109](https://github.com/linzhm/4thGraph/pull/109)

The replay checks the pinned BIP340 vectors, malformed witnesses, all 12 paired payment modes, native exits and changed locktime in both engines. The linked build additionally runs the eight automatic transaction cases from the constructor matrix, with output and sequence mutation controls. [Measurements](../experiments/high-level/window-measurements.json) · [Transaction matrix](../experiments/high-level/window-matrix.json)

```sh
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py \
  --output workspace/schnorr-high-level/window-measurements.json
REGTEST_CHRONICLE_HEIGHT=5 PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py \
  --matrix-only --output workspace/schnorr-high-level/window-matrix.json
```
