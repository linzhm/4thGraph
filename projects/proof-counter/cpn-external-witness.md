# A CPN with an external witness

[中文](cpn-external-witness.zh-CN.md) ·
[Public model](cpn-external-witness.json) ·
[Private model](cpn-external-witness-private.json) ·
[Forth words](cpn-external-words.fth)

This example has two transitions. `advance` increments a public `u32` state;
`decide` consumes that state and the externally supplied `delta` and chooses a
route. The word checks `1 <= delta < 5` and adds it with `u32` wraparound
before calling the existing `decide` word. With initial state 19 and delta 1,
the decision sees 21. The first input to `decide` is the state, the second is
the witness; this is also the Forth stack order. A candidate may keep the
intermediate state inside one transaction or carry it via an output to another.

`delta-input` is an **off-chain input**, not a Bitcoin UTXO or persistent Script
stack value. Its initial CPN marking models availability, not a funded output.
The public example uses `require-proof` and explicitly allows full assignment
disclosure, so the transparent R1CS backend can be selected. R1CS publishes the
assignment and is **not zero knowledge**. In this implementation direct Script
with witness operands is currently excluded as `unsupported_witness_layout`,
even though a policy may otherwise permit direct verification.

From the checkout root, with the project dependencies installed, run:

```sh
mkdir -p workspace
cpn_example_dir=$(mktemp -d workspace/cpn-external.XXXXXX)
cp projects/proof-counter/{cpn-external-witness.json,cpn-external-words.fth,counter.fth} "$cpn_example_dir/"
export PYTHONPATH="src:.:${PYTHONPATH:-}"
python -m fourthgraph.workflow.protocol cpn test-keys > "$cpn_example_dir/keys.json"
python -m fourthgraph.workflow.protocol cpn tune-model "$cpn_example_dir/cpn-external-witness.json" \
  --source "$cpn_example_dir/cpn-external-words.fth" --output "$cpn_example_dir/workflow.fth" \
  --keys "$cpn_example_dir/keys.json" --current 19 --optimizations stack > "$cpn_example_dir/report.json"
python -m fourthgraph.workflow.protocol cpn verify-model "$cpn_example_dir/cpn-external-witness.json" \
  --source "$cpn_example_dir/cpn-external-words.fth" --workflow "$cpn_example_dir/workflow.fth" \
  --report "$cpn_example_dir/report.json" > "$cpn_example_dir/provenance.json"
printf 'Results: %s\n' "$cpn_example_dir"
```

`test-keys` are deterministic **test-only** keys. Inspect the selected candidate,
other candidates and exclusion reasons in `report.json`. `verify-model` checks
that the model, generated Forth, imports and report agree; it does **not** rerun
the search, execute a transaction, verify a proof or check chain state. Tuning
alone supplies no witness value and does not execute the transition.

To execute the public candidate with `delta=1`, install the regtest dependencies
and pinned chain-gang described in the [CPN reference](../../skills/4thgraph/references/cpn.md). Then run:

```sh
REGTEST_MIN_MINING_FEE=0.00000001 bash tools/verify_node.sh --profile long-script -- \
  python -m fourthgraph.workflow.protocol cpn replay "$cpn_example_dir/workflow.fth" \
  --report "$cpn_example_dir/report.json" --candidate 'fused/r1cs~stack' \
  --witness delta=1 --output "$cpn_example_dir/replay.json"
python -m fourthgraph.workflow.protocol cpn verify "$cpn_example_dir/replay.json" \
  --report "$cpn_example_dir/report.json" --candidate 'fused/r1cs~stack' > "$cpn_example_dir/verified.json"
```

This replay uses public test keys on local regtest. `verify` checks the saved
receipt and re-executes the included spend with chain-gang; the Node result is
an observation recorded during replay, not a query of current chain state.

The private model changes the witness visibility to `private` and requires ZK.
To inspect it, use the private JSON as the model and a fresh output path; e.g.:

```sh
cp projects/proof-counter/cpn-external-witness-private.json "$cpn_example_dir/"
if python -m fourthgraph.workflow.protocol cpn tune-model "$cpn_example_dir/cpn-external-witness-private.json" \
  --source "$cpn_example_dir/cpn-external-words.fth" --output "$cpn_example_dir/private-workflow.fth" \
  --keys "$cpn_example_dir/keys.json" --current 19 --optimizations stack > "$cpn_example_dir/private-report.json"; then
  printf 'A candidate was selected.\n'
else
  printf 'No candidate selected; inspect private-report.json and the diagnostic.\n'
fi
python -m fourthgraph.workflow.protocol cpn verify-model "$cpn_example_dir/cpn-external-witness-private.json" \
  --source "$cpn_example_dir/cpn-external-words.fth" --workflow "$cpn_example_dir/private-workflow.fth" \
  --report "$cpn_example_dir/private-report.json" > "$cpn_example_dir/private-provenance.json"
```

Without a matching proving setup this private run reports no eligible candidate;
Script and transparent R1CS cannot meet the private policy, and Groth16 requires
matching circuit setup supplied via `--backend-catalog`. A suitable ZK backend,
its setup and an actual proof are required to claim private verification. See
the [CPN reference](../../skills/4thgraph/references/cpn.md) for setup and replay.
