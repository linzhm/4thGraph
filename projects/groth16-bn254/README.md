<!-- Generated from manifest.yaml with Copier. -->

# BN254 Groth16 verifier v0.1.0

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md) · [Versions](versions/index.json)

## Developer resources

Assemble an owner-authorized, fixed-statement BN254 Groth16 lock from typed Forth and replay it on Chronicle regtest.

[Algorithm and execution](#algorithm-and-execution) · [Reproduce the checks](#reproduce-the-checks) · [Measurements data](versions/v0.1.0/measurements.json)

| Entry point | Purpose |
| --- | --- |
| `verify-bn254-proof` | Construct the authorization and bind the five public inputs before emitting the Rúnar verifier predicate. |

## Algorithm and execution

The Forth entry composes an owner guard, the fixed statement module, and the predicate that checks the public-input MSM and pairing with a residue witness. [Forth entry](verifier.fth) · [Statement module](forth/statement.fth) · [Arithmetic and verification](docs/verification.en.md)

## Reproduce the checks

Run from the repository root with Python 3.11 or later, Go 1.26.6, and the pinned Rúnar checkout at `workspace/runar`. Funded replay also needs the Chronicle chain-gang binding and BSV Node.

```sh
git clone https://github.com/icellan/runar.git workspace/runar
git -C workspace/runar checkout --detach dbcc4269f8e0895c4738cf86948b05b7d62a2010
python3 -m pip install ecdsa -r tools/requirements-chronicle.txt
```

```sh
bash projects/groth16-bn254/reference/build.sh workspace/runar
REGTEST_CHRONICLE_HEIGHT=2 bash tools/verify_node.sh --profile long-script -- \
  python3 -m fourthgraph.replay.groth16_bn254 --runar workspace/runar \
  --verifier-source projects/groth16-bn254/verifier.fth \
  --fixture projects/groth16-bn254/versions/v0.1.0/fixture.json \
  --output projects/groth16-bn254/workspace/build/replay.json
```

The build uses a checked-in test-only fixture and writes the lock and witness prefix. The funded replay tests the valid statement and four rejection controls with BSV Node and chain-gang. [Measurements](versions/v0.1.0/measurements.json)
