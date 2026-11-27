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

## Joint lowering candidates

The compiler reuses the same BIP340 wrapper and 64-window GLV decomposition for all four automatic candidates. The packed plan computes window indices up front and uses paired doubling and mixed addition. The stack plans use those techniques with affine fixed entries and direct `OP_PICK` lookups. The scaled stack plan also selects the registered `a=0, 3*b=1` point kernels. The compiler maps the input point and returns coordinates on the original curve. [Curve model selection](../../../docs/optimization-paths.md#coordinate-model-selection)

| Lowering | Payment lock | 2×2 OTDA ALL using the template constructor |
| --- | ---: | ---: |
| `glv-joint-window-2` | 43,999 B | 107,404 B |
| `glv-joint-packed-2` | 33,357 B | 84,302 B |
| `glv-joint-stack-2` | 27,983 B | 74,090 B |
| `glv-joint-scaled-2` | 26,639 B | 71,442 B |
| Handwritten v0.17.0 | 22,435 B | 54,626 B |

The scaled plan and v0.17.0 emit the same 18,379 bytes for the first window and the 63 regular windows. The remaining payment lock difference is outside the loop.

| Region | v0.17.0 | Scaled plan | Difference |
| --- | ---: | ---: | ---: |
| Witness checks and challenge | 409 B | 1,593 B | +1,184 B |
| Joint multiplication preparation | 2,763 B | 5,486 B | +2,723 B |
| 64 windows | 18,379 B | 18,379 B | 0 B |
| Cleanup and nonce comparison | 74 B | 371 B | +297 B |
| Owner and preimage binding | 810 B | 810 B | 0 B |

Variable table construction and unpacking account for 2,531 B of the gap. The generated plan builds a packed projective table, then unpacks it onto the stack. The handwritten plan constructs the stack entries directly and uses the endomorphism for the `2Q` and `3Q` row starts. The generated BIP340 wrapper also repeats coordinate decoding and signature splitting. Each 2×2 OTDA transaction has two locks and two template constructors that are each 4,204 B larger, for a total of 16,816 B.

This table records commit 7ea588c. The commands in this section reproduce that snapshot from the pinned revision. [Pinned source](https://github.com/linzhm/4thGraph/tree/7ea588cbcfba39ce1099e0034d0b196768c1d1fd)

The replay checks the pinned vectors, malformed witnesses, 12 paired payment modes, two native exits and changed locktime for each candidate. The selected scaled plan also runs all eight automatic cases from the constructor matrix. [Measurements](../experiments/high-level/joint-lowerings.json) · [Transaction matrix](../experiments/high-level/joint-lowerings-matrix.json)

```sh
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py \
  --joint-lowerings --output workspace/schnorr-high-level/joint-lowerings.json
REGTEST_CHRONICLE_HEIGHT=5 PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py \
  --joint-lowerings --matrix-only --output workspace/schnorr-high-level/joint-lowerings-matrix.json
```

## Dataflow iteration

The stack plan now builds the variable table directly. The Forth row code uses mixed addition, and the endomorphism maps `2P` and `3P` to the starts of the last two rows. The compiler schedules the typed layouts and chooses how to clear dead stack slots. In the batched verifier, the Forth computes the challenge from the original encodings and decodes the six checked-width fields together through the shared library. [Compiler dataflow](../../../docs/optimization-paths.md#dataflow-and-return-boundaries) · [Forth row construction](../../../src/fourthgraph/compiler/secp256k1-joint-stack.fth)

| Stage | Payment lock | 2×2 OTDA ALL with reconstruction |
| --- | ---: | ---: |
| Previous scaled stack plan | 26,639 B | 71,442 B |
| Direct variable table | 24,465 B | 62,746 B |
| Dataflow and shorter return cleanup | 23,870 B | 60,366 B |
| Forth batch decoding | 23,484 B | 58,822 B |
| Handwritten v0.17.0 | 22,435 B | 54,626 B |

The table and measurement file record the dataflow builds at `70d7ec8`. Run the replay commands from that checkout to reproduce those Script bytes. With the shared scheduler from #109, the dataflow build emits a 23,869 B payment lock and a 60,362 B reconstructed payment. The batch build emits a 23,482 B lock and a 58,814 B payment. [Measurement checkout](https://github.com/linzhm/4thGraph/tree/70d7ec80ea4694c7d373f3a2368bb56303907dd1)

The shortest build retains the identical 18,379 B window script. The remaining 1,049 B per lock comprises 392 B of witness and challenge handling, 549 B of joint preparation, and 108 B of cleanup and nonce comparison. Each candidate replays 27 vector and malformed-witness cases, 12 paired payment modes, and both native exits. The selected build replays eight constructor matrix cases. [Measurements](../experiments/high-level/dataflow-measurements.json) · [Transaction matrix](../experiments/high-level/dataflow-matrix.json)

```sh
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py \
  --joint-lowerings --output workspace/schnorr-high-level/dataflow-measurements.json
REGTEST_CHRONICLE_HEIGHT=5 PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py \
  --joint-lowerings --matrix-only --output workspace/schnorr-high-level/dataflow-matrix.json
```

## Stack and model boundaries

The stack plan retains the field modulus from affine mapping through joint table preparation. The affine and homogeneous coordinate adapters compare precomputed factors with computing the powers from one root. The dataflow scheduler groups adjacent operands, removes dead slots in an already ordered return sequence, and fuses comparisons consumed only by `verify`. The shared decoder generates repeated masks by doubling and appending. [Compiler and libraries](../../../docs/optimization-paths.md#dataflow-and-return-boundaries)

| Build | Payment lock | 2×2 OTDA ALL with reconstruction |
| --- | ---: | ---: |
| Previous dataflow and batch build | 23,484 B | 58,822 B |
| Optimized stack and model boundaries | 23,190 B | 57,646 B |
| Handwritten v0.17.0 | 22,435 B | 54,626 B |

The table and measurements record commit `e1ee42b`. Run the commands below from that checkout to reproduce the recorded Script bytes. With the shared scheduler on `main` at `c02df4a`, the selected lock measures 23,188 B and the reconstructed two-input, two-output transaction measures 57,638 B. [Measurement checkout](https://github.com/linzhm/4thGraph/tree/e1ee42b455225934d580d172e562540286c42c56)

The 18,379 B window loop matches the frozen manual implementation byte for byte. The remaining 755 B per lock is split into 441 B of joint preparation, 250 B of witness and challenge handling, and 64 B of cleanup and nonce comparison. The verifier replays the BIP340 vectors, malformed witnesses, 12 paired payment modes and two native exits. The selected build also passes the eight-case constructor matrix. [Measurements](../experiments/high-level/boundary-measurements.json) · [Transaction matrix](../experiments/high-level/boundary-matrix.json)

```sh
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py \
  --joint-lowerings --output workspace/schnorr-high-level/boundary-measurements.json
REGTEST_CHRONICLE_HEIGHT=5 PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py \
  --joint-lowerings --matrix-only --output workspace/schnorr-high-level/boundary-matrix.json
```

## Point comparison models

The baseline is built from commit `641153b` of PR #113. The comparison at `90dd9d6` keeps the same batched witness, dataflow compilation, window loop, payment binding, and reconstruction method. The first candidate restores the multiplication result to the original model before checking the nonce point. The second moves the inverse scale inside the modular zero tests. The third maps the public and nonce points together before multiplication, and compares in the scaled model. It uses the same scale factors and passes the field prime into the joint word. [Shared model formulas](../../../src/fourthgraph/stdlib/weierstrass-model.fth)

| Comparison | Before the windows | After the windows | Payment lock | 2×2 OTDA ALL with reconstruction |
| --- | ---: | ---: | ---: | ---: |
| Restore before comparison | 3,861 B | 138 B | 23,188 B | 57,638 B |
| Inverse scale inside the residual | 3,861 B | 127 B | 23,177 B | 57,594 B |
| Map both affine points together | 3,890 B | 82 B | 23,161 B | 57,530 B |
| Handwritten v0.17.0 | 3,172 B | 74 B | 22,435 B | 54,626 B |

All four builds use the same 18,379 B window sequence. The paired map adds 29 B before the loop and saves 56 B after it. The remaining 726 B per lock comprises 374 B before the joint word, 344 B in joint preparation, and 8 B after the windows. Both engines replay the detached vectors and malformed witnesses, all paired signature modes and native exits. The smallest candidate also passes the eight constructor cases. [Measurements](../experiments/high-level/model-output-measurements.json) · [Transaction matrix](../experiments/high-level/model-output-matrix.json)

```sh
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py \
  --joint-lowerings --output workspace/schnorr-high-level/model-output-measurements.json
REGTEST_CHRONICLE_HEIGHT=5 PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py \
  --joint-lowerings --matrix-only --output workspace/schnorr-high-level/model-output-matrix.json
```

## Source tuning for the 64-window verifier

The tuned Forth carries the same field prime through the four coordinate bounds, the public curve equation, and the paired coordinate map. The script checks the original encodings and both ordinate parities before mapping, then checks the two modular residuals and rejects `Z = 0`. At `f4b29f9`, the compiler uses the same `dataflow` profile and secp256k1 joint word as the paired build. [Tuned Forth](../experiments/high-level/window-verifier-tuned.fth)

| Build | Before the windows | After the windows | Payment lock | 2×2 OTDA ALL with reconstruction |
| --- | ---: | ---: | ---: | ---: |
| Paired coordinates at `90dd9d6` | 3,890 B | 82 B | 23,161 B | 57,530 B |
| Paired coordinates, tuned Forth | 3,723 B | 80 B | 22,992 B | 56,854 B |
| Handwritten v0.17.0 | 3,172 B | 74 B | 22,435 B | 54,626 B |

The joint word and its 18,379 B window sequence are byte-identical between the automatic builds. The remaining 557 B per lock comprises 207 B before the joint word, 344 B in joint preparation, and 6 B after the windows. The dual-engine replay covers 27 standalone cases, 14 payment cases and their locktime mutations, and eight constructor cases for the tuned lock. [Measurements](../experiments/high-level/forth-tuning-measurements.json) · [Transaction matrix](../experiments/high-level/forth-tuning-matrix.json)

```sh
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py \
  --joint-lowerings --forth-tuning --output workspace/schnorr-high-level/forth-tuning-measurements.json
REGTEST_CHRONICLE_HEIGHT=5 PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py \
  --joint-lowerings --forth-tuning --matrix-only --output workspace/schnorr-high-level/forth-tuning-matrix.json
```

## Sharing the endomorphism at two row starts

The variable table maps `2P` and `3P` to `2Q` and `3Q` before extending their rows. The Forth word compares the signed ordinates of `P` and `Q` once. A single formula then maps both inputs as `(X, Y, Z) → (βX mod p, ±Y, Z)` with the same field prime, sign, and β. The linker passes the two points to that compiled word. Both the scaled and original-model stack tables use it. [Forth composition](../../../src/fourthgraph/compiler/secp256k1-joint-stack.fth) · [Row map formula](../../../src/fourthgraph/stdlib/secp256k1-window.fth)

| Build | Joint preparation | Payment lock | 2×2 OTDA ALL with reconstruction |
| --- | ---: | ---: | ---: |
| Separate row maps at `f4b29f9` | 3,107 B | 22,992 B | 56,854 B |
| Shared row map | 3,055 B | 22,940 B | 56,646 B |
| Handwritten v0.17.0 | 2,763 B | 22,435 B | 54,626 B |

The shared map saves 52 B, all in joint preparation. The 18,379 B window sequence is byte-identical across the three builds. Compared with the handwritten lock, the remaining 505 B consists of 207 B before the joint word, 292 B in joint preparation, and 6 B after the windows. Both engines replayed the standalone and payment cases and the eight constructor scenarios. [Measurements](../experiments/high-level/table-tuning-measurements.json) · [Transaction matrix](../experiments/high-level/table-tuning-matrix.json)

```sh
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py \
  --joint-lowerings --forth-tuning --output workspace/schnorr-high-level/table-tuning-measurements.json
REGTEST_CHRONICLE_HEIGHT=5 PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" projects/p2pkh-schnorr/experiments/high-level/window_compare.py \
  --joint-lowerings --forth-tuning --matrix-only --output workspace/schnorr-high-level/table-tuning-matrix.json
```
