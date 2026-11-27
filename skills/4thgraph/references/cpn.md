# Build, tune and verify a staged CPN

[简体中文](cpn.zh-CN.md) · [4thGraph skill](../SKILL.md) · [Workflow design](../../../docs/design/README.md)

Keep the Forth relations, public state, private operands, signing roles and transaction requirements fixed when comparing candidates. Use `atomic:` when stages must share a transaction, and `independent-submit:` when they must remain separately submittable. Give an R1CS stage `assignment-disclosure: STAGE allow ;` only when its full assignment may be public. `require-zk` and private witnesses exclude direct Script and transparent R1CS.

## Explore the workbench

For a new logical model, run `4thgraph cpn design --output workspace/cpn-draft.html` and open the resulting offline editor. Add Places and Transitions, connect typed ports, and export the model as JSON. Node metadata can record Forth source, assertions, witness requirements, authorization, proof strategies and state carriers.

Run `4thgraph cpn check-model projects/workflow-examples/token-model.json` to check a two-input, two-output token-count cycle, or pass the exported model. The bounded analysis enumerates token counts and reports its explored markings, transitions, deadlocks and cutoffs. Its result is an overapproximation. Token values, Forth, guards, authorization, timing, transaction validity and metadata are not evaluated. The token model records proposed constraints and is a logical design fixture.

For the currently supported linear subset, `4thgraph cpn lower-model MODEL --source WORDS.fth --output WORKFLOW.fth` generates a staged workflow in the same directory as the Forth source. Declare one initial token, capacity 1 on every Place, public `u32` states ending in a `route`, a single input and output per transition, and one authorizer per transition. The command rejects a graph or requirement it cannot lower. Feed the generated workflow into `4thgraph cpn plan` or `tune` and retain it with its imported Forth files and report.

The [linear example](../../../projects/proof-counter/cpn-linear.json) and [Forth imports](../../../projects/proof-counter/cpn-words.fth) can be tried in an isolated directory:

```sh
mkdir -p workspace/cpn-linear
cp projects/proof-counter/{cpn-linear.json,cpn-words.fth,counter.fth} workspace/cpn-linear/
4thgraph cpn lower-model workspace/cpn-linear/cpn-linear.json --source workspace/cpn-linear/cpn-words.fth \
  --output workspace/cpn-linear/workflow.fth
4thgraph cpn test-keys > workspace/cpn-linear/keys.json
4thgraph cpn plan workspace/cpn-linear/workflow.fth --keys workspace/cpn-linear/keys.json \
  --current 19 --target both > workspace/cpn-linear/report.json
```

On the terminal transition, `metadata.witnesses` accepts objects with `name`, `type: "u32"` and `visibility: "public"` or `"private"`. For example, `"witnesses": [{"name":"delta","type":"u32","visibility":"private"}]` together with `"evidence": [{"policy":"require-zk"}]` lowers to the corresponding Forth declarations. The word must accept state followed by the declared witnesses. Supply matching circuit setup through the backend catalog. For public assignments, an evidence object can set `"assignment_disclosure":"allow"` under a compatible policy. The planner still checks each candidate.

A transition can also declare one structured range constraint such as `{"kind":"range","operand":"delta","range":"private-delta"}`. The named `u32` range must exist in the Forth source, the operand must be the top item on entry, and the word must begin with its matching `check-range`. The compiler checks that the selected Script and applicable circuit lower that check. Other constraints require their own lowering.

The existing CCTP archive can supply a second, historical input. In a checkout containing commit `11c919a`, run the commands below and import the generated model into the editor. The inspector checks serialized transaction identities, slots, token template and reported token quantities. Its logical boundary marking describes the archived subgraph. Script execution, issuance authorization, block inclusion and current UTXO status require their own evidence.

```sh
mkdir -p workspace/cpn-dev
git show 11c919a:projects/spv-token/fixtures/covenant-backtrace-2x2-regtest.json.xz > workspace/cpn-dev/cctp.json.xz
4thgraph cpn inspect-cctp workspace/cpn-dev/cctp.json.xz --logical > workspace/cpn-dev/cctp-model.json
4thgraph cpn check-model workspace/cpn-dev/cctp-model.json > workspace/cpn-dev/cctp-analysis.json
4thgraph cpn inspect-cctp workspace/cpn-dev/cctp.json.xz --flow-report > workspace/cpn-dev/cctp-flow.json
4thgraph cpn design --model workspace/cpn-dev/cctp-model.json --output workspace/cpn-dev/cctp.html
```

With the regtest dependencies below and Node.js installed, run `bash tools/cpn_demo.sh` from the checkout root and open `workspace/cpn-demo/index.html`. The command compiles one Forth source, funds and verifies three paths, and creates a self-contained HTML file. It leaves the source, catalog, original report and replay receipts in the same directory.

Start with the logical graph. A Place describes the state at an interface, and a Transition declares the inputs it consumes and the outputs it produces. Select a transition to inspect its typed computation, Forth word and validation policy. Its external inputs can include witness operands, role signatures and a proof packet. The transaction view maps the same interfaces to the ordered `vin` and `vout` of deployed or spent outputs.

Select `path/handoff~stack` to trace `next: u32` across two transactions. In the logical graph select `next` to see the continuation UTXO as its carrier. In the transaction graph select the corresponding state output to see its amount, decoded state, workflow root, producing slot and consuming input. The receipt records the actual outpoint. A fused spend can carry the same value on its own input stack. The zero-value public receipt is an unspendable output with serialized data.

Use `4thgraph cpn workbench REPORT --receipt RECEIPT --output index.html` for an existing build. Repeat `--receipt` to associate different measured candidates. Add `--source SOURCE` to display the Forth definition from the matching source and imports. Download the plan, planning report and available receipt from the inspector. With pinned chain-gang installed, the recipient can run `4thgraph cpn verify receipt.json --report report.json` offline. Keep the Forth source, catalog and setup together when the recipient also needs to rebuild.

## Direct Script from a clean checkout

Run from the checkout root with Python 3.11 or later in a virtual environment. The first command installs the dependencies for test keys, funded replay and offline verification. Use an installed CLI built from this checkout. [CLI installation](../../../docs/install.md)

```sh
python -m pip install ecdsa -r tools/requirements-chronicle.txt
OUT="$PWD/workspace/cpn-dev"
SOURCE=projects/proof-counter/workflow.fth
mkdir -p "$OUT"
4thgraph --version
4thgraph cpn test-keys > "$OUT/keys.json"
4thgraph cpn tune "$SOURCE" --keys "$OUT/keys.json" --current 19 --target both > "$OUT/tune.json"
4thgraph cpn plan "$SOURCE" --select-candidate "$OUT/tune.json" 'fused/script~stack' --cpn-plan > "$OUT/plan.json"
REGTEST_MIN_MINING_FEE=0.00000001 bash tools/verify_node.sh --profile long-script -- \
  4thgraph cpn replay "$SOURCE" --report "$OUT/tune.json" --candidate 'fused/script~stack' --output "$OUT/replay.json"
4thgraph cpn verify "$OUT/replay.json" --report "$OUT/tune.json" --candidate 'fused/script~stack' > "$OUT/verified.json"
```

Use `plan` for a single lowering profile. `tune` compares `baseline`, `safe` and `stack` by default. Each tuned candidate has a `~PROFILE` suffix. Use `--optimizations` to constrain the profiles and `--objective`, `--max-tx-bytes`, `--max-lock-bytes` or `--max-constraints` to control the search. Read `schedule_explanation.ranked_candidates`, `rank_order`, and each row's cost, backend and exclusions. An empty eligible list exits with a diagnostic and a JSON report. Keep source and imports, the original report, selected ID and canonical plan.

`replay` uses deterministic fixture keys and the pinned node on loopback regtest. Read actual transaction bytes, combined stack payload, preparation time and engine timings from its receipt. `verify` rechecks the artifact and plan digests, reruns chain-gang against the included parent transactions at the recorded heights, and checks the reordered-output control. Node admission and mining are observations from the recorded run. Use a fresh funded replay for fresh Node evidence. Paths requiring full nested STARK verification or recursive lineage currently retain their typed obligations and appear as exclusions.

## Mix R1CS and Groth16

Use Node.js and npm to produce **test-only** BLS12-381 parameters for the `decide` Forth stage, then supply a catalog. The first stage publishes its R1CS assignment, and the second uses a Groth16 proof. The two inputs must agree on the intermediate and ordered outputs.

```sh
MIX="$OUT/mixed"
mkdir -p "$MIX/setup"
cp projects/proof-counter/counter.fth "$MIX/counter.fth"
cp "$SOURCE" "$MIX/workflow.fth"
printf '\nassignment-disclosure: advance allow ;\n' >> "$MIX/workflow.fth"
4thgraph-circuit "$MIX/workflow.fth" --stage decide --output "$MIX/setup/decide.circom"
(
  set -e
  cd "$MIX/setup"
  snarkjs() { npx --yes --package=snarkjs@0.7.5 snarkjs "$@"; }
  npx --yes --package=circom2@0.2.22 circom2 decide.circom --r1cs --O1 --prime bls12381
  snarkjs powersoftau new bls12381 9 start.ptau
  snarkjs powersoftau contribute start.ptau contributed.ptau --name="regtest" -e="4thGraph local regtest fixture"
  snarkjs powersoftau prepare phase2 contributed.ptau phase2.ptau
  snarkjs groth16 setup decide.r1cs phase2.ptau start.zkey
  snarkjs zkey contribute start.zkey decide.zkey --name="regtest" -e="4thGraph local regtest stage fixture"
)
cat > "$MIX/catalog.json" <<'JSON'
{
  "groth16-bls12-381": {"decide": {"zkey": "setup/decide.zkey", "ptau": "setup/phase2.ptau"}},
  "workflow_paths": {
    "settlement": {"layout": "atomic", "stages": {
      "advance": {"role": "compute next state", "backend": "r1cs"},
      "decide": {"role": "choose settlement", "backend": "groth16-bls12-381"}
    }}
  }
}
JSON
4thgraph cpn tune "$MIX/workflow.fth" --keys "$OUT/keys.json" --current 19 --target both \
  --backend-catalog "$MIX/catalog.json" > "$MIX/tune.json"
REGTEST_MIN_MINING_FEE=0.00000001 bash tools/verify_node.sh --profile long-script -- \
  4thgraph cpn replay "$MIX/workflow.fth" --report "$MIX/tune.json" --candidate 'path/settlement~stack' \
  --backend-catalog "$MIX/catalog.json" --output "$MIX/replay.json"
4thgraph cpn verify "$MIX/replay.json" --report "$MIX/tune.json" --candidate 'path/settlement~stack' > "$MIX/verified.json"
```

Retain the `.zkey`, `.ptau`, and catalog used for the original build. Changing the setup changes the deployment lock. For the private terminal variant, generate a setup for its own `decide` circuit, and supply `--witness delta=1` only during the fixture replay. Compare at the relevant boundary states and record which source, outputs and engines were exercised. [Private example](../../../projects/proof-counter/workflow-private.fth) · [Transaction bindings and test cases](../../../docs/design/README.md#first-release-and-validation)
