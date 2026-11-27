# Optimization paths by workload

[简体中文](optimization-paths.zh-CN.md) · [Architecture](architecture.md)

Use the same `experiment run` and `experiment replay` commands for computation and library calls. The legal plans depend on the source contract. Formula plans compare algebra and stack scheduling. A library plan selects a bundled kernel for one call site using its proven inputs or build parameters. All rankings below use the maximum serialized funding-plus-spend size across one fixture's vectors.

| Workload | Alternatives | Selected path and evidence |
| --- | --- | --- |
| Signed 256-bit, 2×2 integer matrix multiplication | Direct multiplication or Strassen's seven-product algorithm, under the same pass plan | Direct with `stack + search` reaches **710 B** versus Strassen's **751 B**. Direct takes eight `OP_MUL`s and peaks at 403 B of stack payload. Strassen takes seven and peaks at 587 B. Both pass the same 64 positive and 64 negative spends. |
| SHA-256 with a retained intermediate digest | One `OP_SHA256` per round, or `OP_HASH256` for pairs in an uninterrupted region | Keep the one-round checkpoint and pair the following 65 rounds. This emits 32 `OP_HASH256`s and one `OP_SHA256` for the long region, bringing the full path from 4,363 B to **4,331 B**. Both pass 29 positive and 29 negative spends with inputs from empty to 4,096 B. |
| secp256k1 point addition | Complete projective, constant-proven affine, or guarded affine with projective fallback | Select constant affine with general runtime addition at **777 B**. The **882 B** guarded alternative remains replayable. Both decisions use the call site's coordinate evidence. |
| Signed modular accumulation | Fold literal subgraphs, factor shared multipliers, and remove a proved redundant signed remainder | The same Forth with `stack` starts at **202 B** and reaches **187 B** with all three rules. Each candidate passes 96 positive and 96 negative spends. |
| Fixed-width fields and byte constants | Split per field or reverse six in parallel, and push a literal or expand a proven repeating seed | Combining both bindings reaches **912 B**. A 500 B observed stack payload budget selects seed expansion alone at **1,542 B**. |

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

`expand-cross-products` recognizes `(a+b)(c+d)-ac-bd` and rewrites it as `ad+bc` after checking the new intermediate ranges. For Groth16, `ScriptBuilder` applies this rule to the Fp2 formula and the verifier inlines the result into its full arithmetic graph. This gives the stack scheduler access to values shared with adjacent operations. [Fp2 formula](../src/fourthgraph/stdlib/bls12-381-fp2.fth) · [Verifier project](../projects/groth16-verifier/README.md)

## Fixed-width fields and repeating constants

The `byte-layout` caller reverses and masks a single 32-byte field and a packed group of six fields. The compiler emits the same exact-width check for both reversal bindings. The packed binding uses the BIP340 kernel for six fields and preserves their order. The constant binding can store just a seed when the build-time literal is formed by successive copies of identical halves. The 192-byte mask uses a three-byte seed and six `OP_DUP OP_CAT` steps. The single-field and irregular-mask call sites use the general implementations. [Caller](../src/fourthgraph/benchmark/fixtures/byte-layout.fth) · [Library](../src/fourthgraph/stdlib/byte-layout.fth)

| Bindings | Full path | Observed combined stack payload |
| --- | ---: | ---: |
| Split fields and literal mask | 1,720 B | 425 B |
| Packed reversal | 1,090 B | 617 B |
| Repeating seed | 1,542 B | 425 B |
| Packed reversal and repeating seed | 912 B | 617 B |

Use `"enumerate":"binding-combinations"` to try the baseline, single substitutions, and combinations across distinct call sites. The search allows one kernel per site and admits up to 32 plans. It links and verifies each plan before ranking. `max_payload_bytes` filters the ranking by the observed main-plus-alternate stack payload on the fixed development vectors, including caller sentinels. The report retains the spend receipts and exclusion reason for over-budget candidates. Replay rechecks the budget and ranking. All four variants pass 24 positive and 24 changed-content spends, and both engines reject malformed field lengths.

## Replay

From the repository root, use an installed `4thgraph` and [pinned chain-gang](../tools/requirements-chronicle.txt). The JSON reports include candidate IDs, source and library digests, per-vector verdicts, observed compile time, and the observed stack peaks.

```sh
mkdir -p workspace/tuning
printf '%s\n' '{"fixture":"matrix-mul","evaluation":"spend","enumerate":"sets"}' > workspace/tuning/matrix-passes-request.json
printf '%s\n' '{"fixture":"matrix-mul","axis":"B","evaluation":"spend","plans":[{"passes":["stack","search"]},{"implementation":"matrix-mul-strassen","passes":["stack","search"]}]}' > workspace/tuning/matrix-algorithms-request.json
printf '%s\n' '{"fixture":"hash-chain","evaluation":"spend","enumerate":"bindings"}' > workspace/tuning/hash-bindings-request.json
printf '%s\n' '{"fixture":"modular-dot","evaluation":"spend","enumerate":"orders","trace":true}' > workspace/tuning/modular-orders-request.json
printf '%s\n' '{"fixture":"byte-layout","evaluation":"spend","enumerate":"binding-combinations"}' > workspace/tuning/byte-layout-request.json
printf '%s\n' '{"fixture":"byte-layout","evaluation":"spend","enumerate":"binding-combinations","max_payload_bytes":500}' > workspace/tuning/byte-layout-budget-request.json
for experiment in matrix-passes matrix-algorithms hash-bindings modular-orders byte-layout byte-layout-budget; do
  4thgraph experiment run "workspace/tuning/$experiment-request.json" > "workspace/tuning/$experiment.json"
  4thgraph experiment replay "workspace/tuning/$experiment.json" > "workspace/tuning/$experiment-replay.json"
done
4thgraph experiment next workspace/tuning/modular-orders.json > workspace/tuning/modular-next.json
4thgraph experiment run workspace/tuning/modular-next.json --parent workspace/tuning/modular-orders.json > workspace/tuning/modular-follow.json
4thgraph experiment replay workspace/tuning/modular-follow.json --parent workspace/tuning/modular-orders.json > workspace/tuning/modular-follow-replay.json
```

Run the independent BSV Node checks for the arithmetic and byte workloads in an isolated regtest. The tests also require pinned chain-gang.

```sh
REGTEST_CHRONICLE_HEIGHT=10 bash tools/verify_node.sh -- python -m unittest \
  tests.test_project_experiment.FormulaExperiments.test_large_arithmetic_and_hash_spends_match_regtest \
  tests.test_project_experiment.FormulaExperiments.test_modular_spends_match_regtest \
  tests.test_project_experiment.FormulaExperiments.test_byte_layout_spends_and_malformed_fields_match_both_engines
```

The payment regression matrix exercises the full R1, Schnorr, SM2, Lamport, WOTS+, and ML-DSA templates against changed witnesses and transaction fields. It complements the compiler fixtures by checking authorization and transaction commitments in their project contexts. [Project matrix](../tests/test_optimization_matrix.py)

## Elliptic-curve lowering

For a checked scalar in `[0,n)` and the registered generator, the compiler can select binary, two-bit or four-bit fixed-base windows on secp256k1, P-256 and SM2. It derives constant points from the curve parameters and compares the emitted Script bytes. The generated Script returns homogeneous `X Y Z`. Infinity has `Z = 0`.

A separate secp256k1 operation accepts a checked affine public point and two scalars, and returns `p X Y Z` for the generator plus public-point combination. It uses the GLV endomorphism and a two-bit window over four 128-bit components. The operation checks input ranges and curve membership. P-256 and SM2 use the registered fixed-base plans.

For the joint operation, `auto` compares the original 64-window code, a packed byte table with precomputed indices, direct stack lookup, and stack lookup on a scaled curve. The optimized plans use paired doubling and mixed addition for the affine fixed table. The CLI report includes the coordinate model, table layout, bytes, and Script hash. An explicit strategy pins the lowering for reproduction.

In a Forth source file, a `curve-multiply:` declaration binds the selected Script to a typed word. `auto` uses the same size comparison as the CLI. The declared word runs its input checks when called.

```forth
curve-multiply: mul-p256-generator p256 generator auto ;
curve-multiply: mul-secp256k1-joint secp256k1 joint auto ;
```

The replay uses OpenSSL as the independent point reference and the project verification environment for BSV Node and chain-gang.

```sh
PYTHONPATH=src:. python -m fourthgraph.workflow.protocol curve-multiply --curve p256 --strategy auto
PYTHONPATH=src:. python -m fourthgraph.workflow.protocol curve-multiply --curve secp256k1 --operation joint
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" -m unittest tests.test_curve_windows
```

[Source and measured BIP340 comparison](../projects/p2pkh-schnorr/docs/high-level-forth.en.md#64-window-lowering)

### Coordinate model selection

`REQUIRE stdlib/weierstrass.fth` exposes `weierstrass-scale ( p X Y Z u2 u3 -- p X' Y' Z )`. It applies the homogeneous map `(u²X, u³Y, Z)` to short Weierstrass points. The matching coefficients are `a' = a·u⁴` and `b' = b·u⁶` modulo `p`. The compiler verifies the registered secp256k1 scale before selecting the `a=0, 3*b=1` kernels, pre-scales the fixed table, maps the input point, and restores the original model at the output. [Shared Forth word](../src/fourthgraph/stdlib/weierstrass.fth)

P-256 uses the shared point-model interface and the original `a=-3` kernels. The sixth-power test gives `(3b)^((p-1)/6) ≠ 1 mod p`, so the `3*b=1` model is unavailable for P-256. A scale that preserves `a=-3` in this field also preserves `b`.
