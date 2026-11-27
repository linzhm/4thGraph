<!-- Generated from manifest.yaml with Copier. -->

# Transaction workflow examples v0.1.0

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md) · [Versions](versions/index.json)

## Developer resources

Compile Forth examples into Bitcoin Script and replay transaction plans with different dependencies.

[Algorithm and execution](#algorithm-and-execution) · [Reproduce the checks](#reproduce-the-checks)

| Entry point | Purpose |
| --- | --- |
| `4thgraph --entry inc` | Compile the increment word and return the Script in the build report. |

## Algorithm and execution

**[Compile a word](#compile-a-word)** · [Build transaction plans](../../docs/toolchain.md#交易与验证) · [Gforth frontend](gforth/README.md)

[Parallel branches](example.fth), [a gated variant](gated.fth), [a fork/join graph](fork-join-graph.fth) and [a serial graph](serial-graph.fth) show different transaction dependencies. [Library composition](library-composition.fth) imports public Forth words. The [Gforth frontend](gforth/README.md) builds a transaction plan from Forth definitions.

[PELS settlement](pels-settle.fth) declares one input and two ordered outputs. Use the [Agent tuning loop](../../docs/README.md#agent-tuning-loop) to compare build choices and verify their results.

## Reproduce the checks

Run the release commands from the repository root with Python 3.11 or later and the workflow test dependencies. [Gforth test environment](gforth/README.md)

```sh
python -m pip install ecdsa -r tools/requirements-chronicle.txt
```

```sh
PYTHONPATH=src:. python -m fourthgraph.workflow.protocol projects/workflow-examples/example.fth --entry inc
PYTHONPATH=src:. python -m unittest discover -s tests -p test_workflow_forth.py
```

### Compile a word

Run from the repository root with Python 3.11 or later.

The command emits the Script for `inc` as JSON. To compare complete transaction plans, use the same source with the test role keys and task ID from a replay. See the [build and replay guide](../../docs/toolchain.md#复放与编译).
