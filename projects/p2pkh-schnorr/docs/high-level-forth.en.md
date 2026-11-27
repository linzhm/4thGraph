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
