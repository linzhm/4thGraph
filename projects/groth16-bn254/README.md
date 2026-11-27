<!-- Generated from manifest.yaml with Copier. -->

# BN254 Groth16 verifier v0.4.0

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md) · [Versions](versions/index.json)

## Developer resources

Assemble an owner-authorized, fixed-statement BN254 Groth16 lock from typed Forth and replay it on Chronicle regtest.

[Algorithm and execution](#algorithm-and-execution) · [Reproduce the checks](#reproduce-the-checks) · [Measurements data](versions/v0.4.0/measurements.json)

| Entry point | Purpose |
| --- | --- |
| `verify-bn254-proof` | Compile the complete fixed-statement verifier from the typed Forth modules. |

## Algorithm and execution

The Forth modules define the Jacobian formulas, subgroup and Miller schedules, and residue checks. The compiler combines paired stack moves. The wrap fixture uses a 505,179 B lock and 6,765 B witness prefix. [Forth entry](forth/verifier.fth) · [Verification guide](docs/verification.en.md)

## Reproduce the checks

Run from the repository root with Python 3.11 or later, Go 1.26.6, and the pinned Rúnar checkout at `workspace/runar`. Funded replay also needs the Chronicle chain-gang binding and BSV Node.

```sh
git clone https://github.com/icellan/runar.git workspace/runar
git -C workspace/runar checkout --detach dbcc4269f8e0895c4738cf86948b05b7d62a2010
python3 -m pip install ecdsa -r tools/requirements-chronicle.txt
```

```sh
bash projects/groth16-bn254/reference/build.sh workspace/runar \
  projects/groth16-bn254/forth/verifier.fth
REGTEST_CHRONICLE_HEIGHT=2 bash tools/verify_node.sh --profile long-script -- \
  python3 -m fourthgraph.replay.groth16_bn254 --runar workspace/runar \
  --verifier-source projects/groth16-bn254/forth/verifier.fth \
  --fixture projects/groth16-bn254/versions/v0.1.0/fixture.json \
  --output projects/groth16-bn254/workspace/build/replay.json
```

The build writes the lock and proof witness prefix. The funded replay checks a valid proof and five rejection controls, including a G2 point outside the subgroup. [Measurements](versions/v0.4.0/measurements.json)
