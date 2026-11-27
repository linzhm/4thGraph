<!-- Generated from manifest.yaml with Copier. -->

# BLS12-381 Groth16 verifier v0.4.0

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md) · [Versions](versions/index.json)

## Developer resources

Import the 4thGraph Groth16 standard library in Forth, build a proof lock and witness, and replay funded BSV spends.

[Algorithm and execution](#algorithm-and-execution) · [Reproduce the checks](#reproduce-the-checks) · [Measurements data](versions/v0.4.0/measurements.json)

| Entry point | Purpose |
| --- | --- |
| `verify-proof` | Project word that calls the standard-library verifier. |
| `groth16-bls12-381-verify` | Standard-library word that verifies a BLS12-381 Groth16 proof and its public signals. |

## Algorithm and execution

The project word imports the verifier with `REQUIRE` and calls its public entry. The shared backend compiles that call to BSV Script for the selected verification key and public-input configuration. [Project Forth](verifier.fth) · [Standard-library source](../../src/fourthgraph/stdlib/groth16-bls12-381.fth) · [Verifier layouts and ABI](../../docs/groth16-bls12-381.md)

The compact verifier constructs its Fp2 kernel with `ScriptBuilder` and inlines the cross-product rewrite. The lock manifest records the formula hash and ordered rule. [Fp2 formula](../../src/fourthgraph/stdlib/bls12-381-fp2.fth)

The compact verifier compares two assertion schedules and automatically consumes fixed-width packet fields from the unread suffix when the reads are ordered and disjoint. [Packet lowering measurements](versions/v0.4.0/measurements.json)

## Reproduce the checks

Run from the repository root with Python 3.11 or later. The build uses the Python standard library. Funded replay uses the pinned chain-gang binding and an isolated Linux BSV Node 1.2.3.

```sh
python3 -m pip install ecdsa -r tools/requirements-chronicle.txt
```

```sh
PYTHONPATH=src:. python3 projects/groth16-verifier/reference/build.py
REGTEST_CHRONICLE_HEIGHT=1000 bash tools/verify_node.sh --profile raised -- \
  python3 -m fourthgraph.replay.bls12381_verifier \
  --source projects/groth16-verifier/verifier.fth --entry verify-proof \
  --script-era genesis --objective path-bytes --tx-version 2 \
  --output projects/groth16-verifier/workspace/build/replay.json
```

Look in `projects/groth16-verifier/workspace/build/` for `lock.json`, `witness.hex`, and `replay.json`. The replay mines two valid spends and checks rejection of swapped statements and G1 points outside the subgroup. [Verification guide](docs/verification.en.md)
