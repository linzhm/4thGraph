# Transaction workflow examples

[Parallel branches](example.fth), [a gated variant](gated.fth), [a fork/join graph](fork-join-graph.fth) and [a serial graph](serial-graph.fth) show different transaction dependencies. [Library composition](library-composition.fth) imports public Forth words. The [Gforth frontend](gforth/README.md) builds a transaction plan from Forth definitions.

From the repository root, run:

```sh
PYTHONPATH=src:. python -m fourthgraph.workflow.protocol projects/workflow-examples/example.fth --entry inc
```

For signed transactions and funded replays, follow the [toolchain guide](../../docs/toolchain.md#复放与编译).
