# Proof counter

[简体中文](README.zh-CN.md) · [Project index](../README.md) · [Versions](versions/index.json)

**[Generate a circuit](#generate-a-circuit)** · [Verification paths](../../docs/language/stdlib.md#验证路径) · [Fixed-statement experiment](reference/fixed-statement/README.md)

[The public relation](verify-state.fth) imports shared [counter rules](counter.fth). Use the same rules for direct Script and Circom. The [Forth workflow](workflow.fth) uses the counter as a stage.

## Generate a circuit

Run from the repository root with Python 3.11 or later.

```sh
bash tools/setup-workspaces.sh
PYTHONPATH=src:. python3 -m fourthgraph.verification.circuit_backend \
  projects/proof-counter/verify-state.fth \
  --output projects/proof-counter/workspace/build/counter.circom
```

The generated `counter.circom` contains the transition and route constraints with public signals for the spend binding. To generate a Groth16 proof, use a witness and setup artifacts that match the compiled circuit. See the [verification paths](../../docs/language/stdlib.md#验证路径) for builds with keys and funded replay. The [BLS12-381 fixed-statement experiment](reference/fixed-statement/README.md) records a verifier comparison with the same public statement.
