<!-- Generated from manifest.yaml with Copier. -->

# Proof counter v0.1.0

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md) · [Versions](versions/index.json)

## Developer resources

Compile and verify a public counter transition with direct Script or a proof backend.

[Algorithm and execution](#algorithm-and-execution) · [Reproduce the checks](#reproduce-the-checks) · [Measurements data](versions/v0.1.0/measurements.json)

| Entry point | Purpose |
| --- | --- |
| `4thgraph-circuit` | Compile the public Forth relation to a Circom circuit. |

## Algorithm and execution

**[Generate a circuit](#generate-a-circuit)** · [Verification paths](../../docs/language/stdlib.md#verification-paths) · [Fixed-statement experiment](reference/fixed-statement/README.md)

[The public relation](verify-state.fth) imports shared [counter rules](counter.fth). Use the same rules for direct Script and Circom. The [Forth workflow](workflow.fth) uses the counter as a stage.

## Reproduce the checks

Run the release commands from the repository root with Python 3.11 or later. The funded replay uses the pinned Chronicle binding and an isolated node. [Regtest infrastructure](../../docs/infrastructure.md)

```sh
python -m pip install ecdsa -r tools/requirements-chronicle.txt
```

```sh
PYTHONPATH=src:. python -m fourthgraph.verification.circuit_backend projects/proof-counter/verify-state.fth --output /tmp/counter.circom
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- python -m fourthgraph.replay.groth16_bls12381 --output /tmp/proof-counter-replay.json
```

### Generate a circuit

Run from the repository root with Python 3.11 or later.

```sh
bash tools/setup-workspaces.sh
PYTHONPATH=src:. python3 -m fourthgraph.verification.circuit_backend \
  projects/proof-counter/verify-state.fth \
  --output projects/proof-counter/workspace/build/counter.circom
```

The generated `counter.circom` contains the transition and route constraints with public signals for the spend binding. To generate a Groth16 proof, use a witness and setup artifacts that match the compiled circuit. See the [verification paths](../../docs/language/stdlib.md#verification-paths) for builds with keys and funded replay. The [BLS12-381 fixed-statement experiment](reference/fixed-statement/README.md) records a verifier comparison with the same public statement.
