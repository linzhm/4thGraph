# Proof counter

[The public relation](verify-state.fth) imports shared [counter rules](counter.fth). Use the same rules for direct Script and Circom. The [Forth workflow](workflow.fth) uses the counter as a stage.

From the repository root, run:

```sh
bash tools/setup-workspaces.sh
PYTHONPATH=src:. python -m fourthgraph.verification.circuit_backend \
  projects/proof-counter/verify-state.fth \
  --output projects/proof-counter/workspace/build/counter.circom
```

See the [verification paths](../../docs/language/stdlib.md#验证路径) for builds with keys and funded replay. The [BLS12-381 fixed-statement experiment](experiments/fixed-statement/README.md) records a verifier comparison with the same public statement.
