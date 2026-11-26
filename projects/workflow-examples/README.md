# Transaction workflow examples

[简体中文](README.zh-CN.md) · [Project index](../README.md)

**[Compile a word](#compile-a-word)** · [Build transaction plans](../../docs/toolchain.md#交易与验证) · [Gforth frontend](gforth/README.md)

[Parallel branches](example.fth), [a gated variant](gated.fth), [a fork/join graph](fork-join-graph.fth) and [a serial graph](serial-graph.fth) show different transaction dependencies. [Library composition](library-composition.fth) imports public Forth words. The [Gforth frontend](gforth/README.md) builds a transaction plan from Forth definitions.

## Compile a word

Run from the repository root with Python 3.11 or later.

```sh
PYTHONPATH=src:. python3 -m fourthgraph.workflow.protocol projects/workflow-examples/example.fth --entry inc
```

The command emits the Script for `inc` as JSON. To compare complete transaction plans, use the same source with the test role keys and task ID from a replay. See the [build and replay guide](../../docs/toolchain.md#复放与编译).
