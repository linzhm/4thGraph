<!-- Generated from manifest.yaml with Copier. -->

# BLS12-381 Groth16 verifier v0.10.0

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md) · [Versions](versions/index.json)

## Developer resources

Import the 4thGraph Groth16 standard library in Forth, build a proof lock and witness, and replay funded BSV spends.

[Algorithm and execution](#algorithm-and-execution) · [Reproduce the checks](#reproduce-the-checks) · [Measurements data](versions/v0.10.0/measurements.json)

| Entry point | Purpose |
| --- | --- |
| `verify-proof` | Project word that calls the standard-library verifier. |
| `groth16-bls12-381-verify` | Standard-library word that verifies a BLS12-381 Groth16 proof and its public signals. |

## Algorithm and execution

The project word imports the verifier with `REQUIRE` and calls its public entry. The shared backend compiles that call to BSV Script for the selected verification key and public-input configuration. [Project Forth](verifier.fth) · [Standard-library source](../../src/fourthgraph/stdlib/groth16-bls12-381.fth) · [Verifier layouts and ABI](../../docs/groth16-bls12-381.md)

The compact verifier constructs its Fp2 kernel with `ScriptBuilder` and inlines the cross-product rewrite. The lock manifest records the formula hash and ordered rule. [Fp2 formula](../../src/fourthgraph/stdlib/bls12-381-fp2.fth)

The compact verifier compares two assertion schedules and automatically consumes fixed-width packet fields from the unread suffix when the reads are ordered and disjoint. [Packet lowering measurements](versions/v0.4.0/measurements.json)

The shared stack scheduler recognizes when to keep a live right operand with `OP_TUCK` and pushes one-byte numeric constants at their uses. [Operand scheduling measurements](versions/v0.5.0/measurements.json)

The high-level Forth experiment searches uniform and call-site Fp2 lowerings and measures verifier source edits with a common compiler. [Experiment and replay](docs/verification.en.md#high-level-forth-experiment)

The search also compares signed and unsigned public-input MSM by the serialized size of each lock and its matching witness. [MSM measurements](versions/v0.8.0/measurements.json)

The signed MSM experiment compares explicit point tables with slope-based reconstruction and recompiles a Forth source edit. [Table and source measurements](versions/v0.9.0/measurements.json)

The same high-level Forth source compiles with deferred MSM table reductions and compares three Miller reduction schedules. [MSM and Miller measurements](versions/v0.10.0/measurements.json)

## Reproduce the checks

Run from the repository root with Python 3.11 or later. The build uses the Python standard library. Funded replay uses the pinned chain-gang binding and an isolated Linux BSV Node 1.2.3.

```sh
python3 -m pip install ecdsa -r tools/requirements-chronicle.txt
```

```sh
PYTHONPATH=src:. python3 projects/groth16-verifier/experiments/high-level/optimize.py \
  --residue-association accumulator-frobenius-first --fp2-selection callsite --msm signed-radix4
REGTEST_CHRONICLE_HEIGHT=1000 bash tools/verify_node.sh --profile raised -- \
  python3 -m fourthgraph.replay.bls12381_verifier \
  --source projects/groth16-verifier/experiments/high-level/verifier.fth \
  --entry verify-proof --witness-layout affine-inline --script-era genesis \
  --arithmetic-plan projects/groth16-verifier/workspace/build/high-level/genesis-plan.json \
  --output projects/groth16-verifier/workspace/build/high-level/genesis-replay.json
```

The high-level experiment writes `search.json`, the winning locks and plans, and the funded replay under `projects/groth16-verifier/workspace/build/high-level/`. The replay mines two valid spends and checks rejection of swapped statements and G1 points outside the subgroup. [Verification guide](docs/verification.en.md)
