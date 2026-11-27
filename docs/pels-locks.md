# Compile and assemble PELS locks

[简体中文](pels-locks.zh-CN.md) · [Forth library](language/stdlib.md)

Use `REQUIRE stdlib/pels.fth` to express the required input count, complete ordered outputs, and transaction field assertions in Forth. The standalone compiler covers one input and build-time output expressions. The [settlement fixture](../projects/workflow-examples/pels-settle.fth) requires a payment, a receipt, and locktime 42.

An `IF` flag must resolve to a Forth cell at build time. The compiler evaluates the selected branch and retains the assertions verified on that branch.

## Compile targets

Choose the transaction version in `--target` and the preimage policy in `--sighash-family`. The policies are `bip143`, `otda`, `both`, and `auto`. The compiler checks required coverage before comparing linked lock and witness fields, including serialized length prefixes. A previous-output amount assertion requires BIP143 in this implementation.

The compiler checks that the output total stays within the currency limit and any fixed prevout amount. Witness assembly checks the same output total against the actual prevout for each sighash family.

```sh
export PYTHONPATH=src:.
python3 -m fourthgraph.workflow.protocol projects/workflow-examples/pels-settle.fth \
  --entry settle --bind-bytes recipient-lock=51 --target chronicle-v2 \
  --sighash-family auto --explain > lock.json
python3 -m fourthgraph.workflow.protocol pels-witness lock.json \
  --parent parent.hex --unsigned unsigned.hex
```

The compile example uses a synthetic fixture output. For witness assembly provide the actual parent and matching unsigned candidate as serialized transaction hex. For a dual-mode build pass `--sighash-family bip143` or `--sighash-family otda` to select an included path. The compiled artifact records Script bytes, candidates, fragment ranges and hashes, and each path's witness layout. Independently verify the assembled spend against its parent and applicable chain context. [Acceptance tests](../tests/test_pels_lock.py)
