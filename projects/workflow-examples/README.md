<!-- Generated from manifest.yaml with Copier. -->

# CPN workflow examples v0.1.0

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md) · [Versions](versions/index.json)

## Developer resources

Compile Forth workflows into BSV transaction plans and compare the generated CPN, candidate costs, and funded replays.

[Algorithm and execution](#algorithm-and-execution) · [Reproduce the checks](#reproduce-the-checks)

| Entry point | Purpose |
| --- | --- |
| `4thgraph --cpn` | Draw the selected transaction graph in Mermaid. Use --cpn-plan for its canonical encoding. |
| `4thgraph --search --explain` | Compare supported transaction boundaries and explain the selected layout. |

## Algorithm and execution

[CPN architecture](../../docs/architecture.md#cpn-planning-and-verification) · [SPV Token compilation design](../../docs/design/README.md#spv-token-cpn)

[The gated workflow](gated.fth) checks a prerequisite before processing two branches and joining their results. The compiler can fuse the workflow, merge the gate with the split, or submit the gate independently. The same source drives candidate search and the funded replay.

[Parallel branches](example.fth), [fork and join](fork-join-graph.fth), and [serial state](serial-graph.fth) show other dependency forms. [Library composition](library-composition.fth) imports public Forth words. The [Gforth frontend](gforth/README.md) builds a transaction plan from Forth definitions.

## Reproduce the checks

Run from the repository root with Python 3.11 or later and jq. Install the workflow and regtest dependencies for funded replay. [Regtest setup](../../docs/toolchain.md#复放与编译)

```sh
python -m pip install ecdsa -r tools/requirements-chronicle.txt
```

```sh
PYTHONPATH=src:. python -m fourthgraph.workflow.protocol projects/workflow-examples/example.fth --entry inc
PYTHONPATH=src:. python -m unittest discover -s tests -p test_workflow_forth.py
```

<a name="compile-and-replay-a-cpn"></a>

### Compile and replay a CPN

Run the gated fixture to verify its settlement and review paths. The replay records the public test keys and task ID used to rebuild the same plan as a candidate report, a Mermaid graph, and canonical JSON.

```bash
export PYTHONPATH=src:.
out=projects/workflow-examples/workspace/build
mkdir -p "$out"

bash tools/verify_node.sh --profile default -- \
  python -m fourthgraph.replay.workflow --search --topology gated-parallel \
  --target both --optimize stack --samples 1 --output "$out/cpn-replay.json"

jq -e '.fixture_public_keys' "$out/cpn-replay.json" > "$out/cpn-keys.json"
task=$(jq -er .task_id "$out/cpn-replay.json")
cpn=(python -m fourthgraph.workflow.protocol projects/workflow-examples/gated.fth
     --keys "$out/cpn-keys.json" --task-id "$task" --target both --optimize stack --search)

"${cpn[@]}" --explain > "$out/cpn-build.json"
"${cpn[@]}" --cpn > "$out/cpn.mmd"
"${cpn[@]}" --cpn-plan > "$out/cpn-plan.json"
python -m fourthgraph.reporting "$out/cpn-replay.json" --output-dir "$out/cpn-decision"
```

Use `plan_sha256` in `cpn-build.json` to identify the selected plan. The decision report compares estimated and replayed bytes, verification, and confirmation for the candidates.

### Compile a word

The release commands above also compile the standalone `inc` word and run the workflow tests.
