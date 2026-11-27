# Build, tune and verify a staged CPN

[简体中文](cpn.zh-CN.md) · [4thGraph skill](../SKILL.md) · [Workflow design](../../../docs/design/README.md)

Keep the Forth relations, public state, private operands, signing roles and transaction requirements fixed when comparing candidates. Use `atomic:` when stages must share a transaction, and `independent-submit:` when they must remain separately submittable. Give an R1CS stage `assignment-disclosure: STAGE allow ;` only when its full assignment may be public. `require-zk` and private witnesses exclude direct Script and transparent R1CS.

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
