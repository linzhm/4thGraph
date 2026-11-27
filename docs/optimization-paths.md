# Optimization paths by workload

[简体中文](optimization-paths.zh-CN.md) · [Architecture](architecture.md)

Use the same `experiment run` and `experiment replay` commands for computation and library calls. The legal plans depend on the source contract. Formula plans compare algebra and stack scheduling. A library plan selects a bundled kernel for one call site using its proven inputs or build parameters. All rankings below use the maximum serialized funding-plus-spend size across one fixture's vectors.

| Workload | Alternatives | Selected path and evidence |
| --- | --- | --- |
| Signed 256-bit, 2×2 integer matrix multiplication | Direct multiplication or Strassen's seven-product algorithm, under the same pass plan | Direct with `stack + search` reaches **710 B** versus Strassen's **753 B**. Direct takes eight `OP_MUL`s and peaks at 403 B of stack payload. Strassen takes seven and peaks at 650 B. Both pass the same 64 positive and 64 negative spends. |
| SHA-256 with a retained intermediate digest | One `OP_SHA256` per round, or `OP_HASH256` for pairs in an uninterrupted region | Keep the one-round checkpoint and pair the following 65 rounds. This emits 32 `OP_HASH256`s and one `OP_SHA256` for the long region, bringing the full path from 4,363 B to **4,331 B**. Both pass 29 positive and 29 negative spends with inputs from empty to 4,096 B. |
| secp256k1 point addition | Complete projective, constant-proven affine, or guarded affine with projective fallback | Select constant affine with general runtime addition at **777 B**. The **882 B** guarded alternative remains replayable. Both decisions use the call site's coordinate evidence. |
| Signed modular accumulation | Fold literal subgraphs, factor shared multipliers, and remove a proved redundant signed remainder | The same Forth with `stack` starts at **202 B** and reaches **187 B** with all three rules. Each candidate passes 96 positive and 96 negative spends. |

The matrix comparison fixes the input domain and the four result slots. `stack` is 712 B for the direct source, and adding search saves another 2 B. Adding `rewrite` and `share` to that plan gives the same size, so the shorter pass list wins. Matrix inputs exercise the signed bounds, mixed signs, zero entries, and deterministic full-width inputs. Stack payload is measured by the development evaluator with caller sentinels.

The hash fixture returns both its intermediate and final digest. The compiler selects the paired kernel only for a build-time region of at least two rounds. It records the round count, bundled kernel digest, linked byte range, and the cost of a trailing odd round. The single-round checkpoint and any kernel for a different operation are rejected as paired bindings. [Matrix sources](../src/fourthgraph/benchmark/formulas/matrix-mul.fth) · [Hash caller](../src/fourthgraph/benchmark/fixtures/hash-chain.fth) · [Hash kernels](../src/fourthgraph/stdlib/hash-chain.fth)

## Ordered formula rules

Use these rules on closed formulas whose caller establishes canonical ScriptNum encodings and the declared input intervals.

| Rule | Legality check | Full path with `stack` and only this rule |
| --- | --- | ---: |
| `fold-literals` | All operands are literal and the typed operation is valid. Evaluation uses the same signed-remainder semantics as Script. | 195 B |
| `factor-products` | Two products share the same graph value. Preserve subtraction order and recheck the ScriptNum limit for the new intermediate and product. | 196 B |
| `elide-redundant-remainder` | The dividend is already in a proved identity range or is the result of taking a remainder by the same positive divisor. | 200 B |

With the rules combined, the Script has two multiplications and one remainder, down from five multiplications and two remainders with `stack` alone. Its measured stack payload peak moves from 48 B to 44 B. The rule search admits 32 candidates at most and also includes the unoptimized reference when the terminal pass list is nonempty. The empty rule list under the same terminal passes gives a control for measuring rule effects. `compile.lowering.ordered_rules` records application counts, while traces give resulting ranges and source positions. Explicit rules also work with `ScriptBuilder(..., formula_passes=["stack"], experimental_rules=[...])`. [Fixture](../src/fourthgraph/benchmark/formulas/modular-dot.fth)

## Replay

From the repository root, use an installed `4thgraph` and [pinned chain-gang](../tools/requirements-chronicle.txt). The JSON reports include candidate IDs, source and library digests, per-vector verdicts, observed compile time, and the observed stack peaks.

```sh
mkdir -p workspace/tuning
printf '%s\n' '{"fixture":"matrix-mul","evaluation":"spend","enumerate":"sets"}' > workspace/tuning/matrix-passes-request.json
printf '%s\n' '{"fixture":"matrix-mul","axis":"B","evaluation":"spend","plans":[{"passes":["stack","search"]},{"implementation":"matrix-mul-strassen","passes":["stack","search"]}]}' > workspace/tuning/matrix-algorithms-request.json
printf '%s\n' '{"fixture":"hash-chain","evaluation":"spend","enumerate":"bindings"}' > workspace/tuning/hash-bindings-request.json
printf '%s\n' '{"fixture":"modular-dot","evaluation":"spend","enumerate":"orders","trace":true}' > workspace/tuning/modular-orders-request.json
for experiment in matrix-passes matrix-algorithms hash-bindings modular-orders; do
  4thgraph experiment run "workspace/tuning/$experiment-request.json" > "workspace/tuning/$experiment.json"
  4thgraph experiment replay "workspace/tuning/$experiment.json" > "workspace/tuning/$experiment-replay.json"
done
4thgraph experiment next workspace/tuning/modular-orders.json > workspace/tuning/modular-next.json
4thgraph experiment run workspace/tuning/modular-next.json --parent workspace/tuning/modular-orders.json > workspace/tuning/modular-follow.json
4thgraph experiment replay workspace/tuning/modular-follow.json --parent workspace/tuning/modular-orders.json > workspace/tuning/modular-follow-replay.json
```

Run the independent BSV Node checks for the matrix, hash-chain and modular accumulation vectors in an isolated regtest. The tests also require pinned chain-gang.

```sh
REGTEST_CHRONICLE_HEIGHT=10 bash tools/verify_node.sh -- python -m unittest \
  tests.test_project_experiment.FormulaExperiments.test_large_arithmetic_and_hash_spends_match_regtest \
  tests.test_project_experiment.FormulaExperiments.test_modular_spends_match_regtest
```

The payment regression matrix exercises the full R1, Schnorr, SM2, Lamport, WOTS+, and ML-DSA templates against changed witnesses and transaction fields. It complements the compiler fixtures by checking authorization and transaction commitments in their project contexts. [Project matrix](../tests/test_optimization_matrix.py)
