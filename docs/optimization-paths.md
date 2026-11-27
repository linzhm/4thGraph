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
| secp256k1 doubling window | Complete rounds or paired rounds, with the field at stack bottom or cached below the point | Pair the private nine-round window with a nearby field copy at **1,144 B**. A 700 B observed payload budget selects nearby-field complete rounds at **1,156 B**. |

The matrix comparison fixes the input domain and the four result slots. `stack` is 712 B for the direct source, and adding search saves another 2 B. Adding `rewrite` and `share` to that plan gives the same size, so the shorter pass list wins. Matrix inputs exercise the signed bounds, mixed signs, zero entries, and deterministic full-width inputs. Stack payload is measured by the development evaluator with caller sentinels.

The hash fixture returns both its intermediate and final digest. The compiler selects the paired kernel only for a build-time region of at least two rounds. It records the round count, bundled kernel digest, linked byte range, and the cost of a trailing odd round. The single-round checkpoint and any kernel for a different operation are rejected as paired bindings. [Matrix sources](../src/fourthgraph/benchmark/formulas/matrix-mul.fth) · [Hash caller](../src/fourthgraph/benchmark/fixtures/hash-chain.fth) · [Hash kernels](../src/fourthgraph/stdlib/hash-chain.fth)

## R1 same-source automatic selection

Freeze `r1-baseline-lock` and its imports, then measure the current compiler before selecting a window plan. The original window-only entry `--auto --auto-rounds 1` ranks six linked Scripts by lock size. It can replace the verified P-256 multiplication region only when the input and dependency digests match. It preserves the original result check and transaction binding. Other input snapshots use the existing formula plans.

| Compile mode | Lock bytes | BIP143 funding + spend bytes | Main / alternate stack peak items |
| --- | ---: | ---: | ---: |
| Baseline | 415,058 | 415,511 | 71 / 39 |
| Existing `--optimize` | 139,333 | 139,786 | 24 / 39 |
| `--auto`, selected `split-5x4-affine-g-ifdup` | 41,264 | 41,715 | 161 / 119 |

The transaction metric is for one synthetic input spending into one output. The development evaluator observes the stack peaks. Pinned chain-gang and BSV Node regtest verify all six candidates under BIP143 ALL, OTDA ALL and both paired and unpaired OTDA SINGLE. Each rejects the stale witness at the transaction binding check after a locktime change. [Build and replay](../projects/p2pkh-r1/forth/README.md)

With `--auto-rounds 6`, the search compiled 32 distinct candidates in five rounds and stopped at the candidate budget. The same spend checks cover all 32 candidates. Adjusting the window widths and guard choices left the winning Script at 41,264 B. The JSON records which candidates entered each round and the best lock through that round.

## R1 ordered method exploration

The initial matrix and search figures below use the original compiler snapshot. [Original build and plans](https://github.com/linzhm/4thGraph/tree/9b13dfbbd50487ca868831788f653e2b75f9cd5a)

Each matrix cell applies the row method followed by the column method. Both matrices use the same Forth and two-input, two-output fixture. The first starts with separate generic tables. The second starts with a proven affine G kernel so that compact storage and its zero-digit guard can be compared in each order. The five methods select a joint window, specialize fixed G calls, compact the G table, shorten the zero guard, and run explicit stack search on the point-add kernels visible at that step.

Applying affine specialization before stack search emits a 41,927 B lock. Applying stack search first leaves the new affine kernel on its default lowering and emits 41,366 B. Compact storage and the guard commute from the affine seed and emit the same 41,165 B lock. This compact plan leads on the BIP143 ALL path at 165,575 B. The joint window leads on the OTDA ALL path at 176,617 B, compared with 176,807 B for the compact plan.

The run records all 50 ordered pairs. The 25 eligible cells link to nine distinct lock and reconstruction artifacts, each verified against actual fixture prevouts by pinned chain-gang. The report ranks targets separately and can be reproduced with `method-matrix --replay`. [Build and replay](../projects/p2pkh-r1/forth/README.md)

The `method-search` command starts from the generic split state and expands every applicable method, including independent G-window widening. The measured run on six registered methods exhausted the reachable graph after 19 compiler states and 114 attempted transitions. The longest discovered prefix had five methods. BIP143 ALL selected affine G, compact G and the shortened guard in sequence, while both OTDA modes selected the single joint-window step. `--replay` uses the original budget.

The next method-search revision adds an OTDA packing choice for repeated fragments. For `joint-2`, the constructor can build 128 copies of a window by doubling and remove the final copy. It tries the alternative only when it uses fewer bytes and its temporary fits within the suffix being reconstructed. The 42,382 B lock is byte-identical. The constructor falls from 3,062 B to 3,043 B. With two signed inputs, the complete fixture path falls from 176,617 B to 176,579 B under OTDA ALL and from 176,546 B to 176,508 B under paired OTDA SINGLE. The BIP143 paths and the observed stack peaks are unchanged.

The expanded search also compares a narrower separate Q window, repeats constructed on the main stack, and one dictionary lookup for consecutive copies of an identical kernel. The two packing choices are admitted only when the emitted constructor is smaller on the current state. All retained candidates are ranked using complete verified transactions. The report distinguishes reaching the state budget from exhausting the graph. The ten-method run reached the 64-state budget and independently verified 61 distinct artifacts. Narrowing Q made the generic split's OTDA ALL path 8,229 B larger even though its constructor shrank. Main-stack repetition reduced the compact affine candidate's OTDA path by 16 B. Adjacent references reduced the winning joint-window OTDA path by another 2 B, to 176,577 B under ALL and 176,506 B under paired SINGLE. The best BIP143 ALL path was 165,575 B.

With the compiler at `c02df4a`, all three payment searches exhausted their 152 states within the 160-state budget. Each chose a 41,114 B lock. The OTDA goals also chose main-stack repetition and adjacent kernel packing. `--replay-plan` checks the compiler source digest, applies the saved sequence and verifies both artifact hashes. Chain-gang 0.13.2 measured 165,371 B for BIP143 ALL, 176,547 B for OTDA ALL, and 176,476 B for paired OTDA SINGLE across funding and spending. [Plans and commands](../projects/p2pkh-r1/forth/README.md)

## Ordered formula rules

Use these rules on closed formulas whose caller establishes canonical ScriptNum encodings and the declared input intervals.

| Rule | Legality check | Full path with `stack` and only this rule |
| --- | --- | ---: |
| `fold-literals` | All operands are literal and the typed operation is valid. Evaluation uses the same signed-remainder semantics as Script. | 195 B |
| `factor-products` | Two products share the same graph value. Preserve subtraction order and recheck the ScriptNum limit for the new intermediate and product. | 196 B |
| `elide-redundant-remainder` | The dividend is already in a proved identity range or is the result of taking a remainder by the same positive divisor. | 200 B |

With the rules combined, the Script has two multiplications and one remainder, down from five multiplications and two remainders with `stack` alone. Its measured stack payload peak moves from 48 B to 44 B. The rule search admits 32 candidates at most and also includes the unoptimized reference when the terminal pass list is nonempty. The empty rule list under the same terminal passes gives a control for measuring rule effects. `compile.lowering.ordered_rules` records application counts, while traces give resulting ranges and source positions. Explicit rules also work with `ScriptBuilder(..., formula_passes=["stack"], experimental_rules=[...])`. [Fixture](../src/fourthgraph/benchmark/formulas/modular-dot.fth)

`expand-cross-products` recognizes `(a+b)(c+d)-ac-bd` and rewrites it as `ad+bc` after checking the new intermediate ranges. For Groth16, `ScriptBuilder` applies this rule to the Fp2 formula and the verifier inlines the result into its full arithmetic graph. This gives the stack scheduler access to values shared with adjacent operations. [Fp2 formula](../src/fourthgraph/stdlib/bls12-381-fp2.fth) · [Verifier project](../projects/groth16-bls12-381/README.md)

## Fixed-width fields and repeating constants

The `byte-layout` caller reverses and masks a single 32-byte field and a packed group of six fields. The compiler emits the same exact-width check for both reversal bindings. The packed binding uses the BIP340 kernel for six fields and preserves their order. The constant binding can store just a seed when the build-time literal is formed by successive copies of identical halves. The 192-byte mask uses a three-byte seed and six `OP_DUP OP_CAT` steps. The single-field and irregular-mask call sites use the general implementations. [Caller](../src/fourthgraph/benchmark/fixtures/byte-layout.fth) · [Library](../src/fourthgraph/stdlib/byte-layout.fth)

| Bindings | Full path | Observed combined stack payload |
| --- | ---: | ---: |
| Split fields and literal mask | 1,720 B | 425 B |
| Packed reversal | 1,090 B | 617 B |
| Repeating seed | 1,542 B | 425 B |
| Packed reversal and repeating seed | 912 B | 617 B |

Use `"enumerate":"binding-combinations"` to try the baseline, single substitutions, and combinations across distinct call sites. The search allows one kernel per site and admits up to 32 plans. It links and verifies each plan before ranking. `max_payload_bytes` filters the ranking by the observed main-plus-alternate stack payload on the fixed development vectors, including caller sentinels. The report retains the spend receipts and exclusion reason for over-budget candidates. Replay rechecks the budget and ranking. All four variants pass 24 positive and 24 changed-content spends, and both engines reject malformed field lengths.

## secp256k1 doubling windows

`doubling-window` exposes the exact coordinates after its first doubling, then runs a separate nine-round window. Each binding checks the secp256k1 field prime at stack bottom. A nearby-field plan copies the prime below `X Y Z` once and drops the copy at exit. It preserves the caller stack, and the report includes setup, cleanup, field check, and linked kernel spans. [Forth caller](../src/fourthgraph/benchmark/fixtures/doubling-window.fth) · [Bundled kernels](../src/fourthgraph/stdlib/secp256k1.fth)

The paired path starts the window with one complete doubling. Each subsequent pair receives reduced signed coordinates from the preceding block, and an odd remainder of rounds uses one complete tail. Delaying the first `X` reduction within a pair preserves the exact signed residue. The next `X` uses it only as a linear factor, and the next `Y` and `Z` depend only on the already reduced `Y` and `Z`. A nonzero signed remainder preserves the sign of that factor. A zero remainder implies that the later product is divisible by the prime. Reduced inputs bound the largest delayed `X` intermediate to 226 ScriptNum bytes. The one-round checkpoint is too short for pairing.

| Binding in the nine-round window | Full path | Observed combined stack payload |
| --- | ---: | ---: |
| Complete rounds, field at stack bottom | 1,171 B | 653 B |
| Paired rounds, field at stack bottom | 1,155 B | 748 B |
| Complete rounds, field below the point | 1,156 B | 686 B |
| Paired rounds, field below the point | 1,144 B | 781 B |

These four rows keep the checkpoint on the stack-bottom field kernel. The search also evaluates the four matches that place the field near the point at the checkpoint. The nearby field costs an additional 9 B there. The winning paired plan removes four `OP_MOD`s across the full caller. All eight plans pass 32 positive and 32 substituted-point spends. The vectors include infinity, signed representatives and initially unreduced coordinates. Both engines also reject a wrong field prime for each plan.

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
printf '%s\n' '{"fixture":"doubling-window","evaluation":"spend","enumerate":"binding-combinations"}' > workspace/tuning/doubling-window-request.json
printf '%s\n' '{"fixture":"doubling-window","evaluation":"spend","enumerate":"binding-combinations","max_payload_bytes":700}' > workspace/tuning/doubling-window-budget-request.json
for experiment in matrix-passes matrix-algorithms hash-bindings modular-orders byte-layout byte-layout-budget doubling-window doubling-window-budget; do
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
  tests.test_project_experiment.FormulaExperiments.test_byte_layout_spends_and_malformed_fields_match_both_engines \
  tests.test_project_experiment.FormulaExperiments.test_doubling_window_checkpoint_and_field_checks_match_both_engines
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

## Dataflow and return boundaries

`--optimize dataflow` evaluates reusable Script rewrites alongside the existing stack compilation and retains the smaller result. In a typed lock block it reuses marked deterministic operations with identical operands after their first execution. Exact byte widths come from size checks, literal splits, concatenation and hash results. A registered width-specific lowering is selected only when its input width is proven. Conditional arms have their own dataflow analysis, and transaction-dependent operations retain their calls.

At an eligible return boundary, liveness identifies a contiguous suffix of live values above dead slots. The scheduler compares moving each dead value with saving the live suffix, dropping the dead slots in pairs and restoring the suffix. The second option preserves the caller's alternate stack. The standard frontend also accepts `layout:` for named typed stack permutations, so Forth library algorithms can express their stacks without encoding depths by hand.

In `dataflow`, a declared layout can keep the original value slot for each output. This lets the final scheduler handle reordering, duplication, and dropped values together with the surrounding calls. The compiler evaluates this candidate for typed locks and for straight-line words with explicit stack operands, including calls with multiple returns. It compares the complete emitted Script and retains the smaller schedule. [Compiler regression cases](../tests/test_dataflow.py) · [Schnorr replay](../projects/p2pkh-schnorr/docs/high-level-forth.en.md#scheduling-named-layouts-with-dataflow)

The shared Script library can decode one fixed 32-byte big-endian field or a build-time count of consecutive fields. It uses the same mask and group-swap words as the window code. The batch decoder preserves field order and unsigned values. [Shared fragments](../src/fourthgraph/stdlib/script-fragments.fth) · [Schnorr comparison](../projects/p2pkh-schnorr/docs/high-level-forth.en.md#dataflow-iteration)

The dataflow scheduler also compares moving adjacent operands as a group with moving them individually. It keeps the order of already staged operands and checks all remaining uses before moving a value. At a return boundary it can remove interleaved dead slots directly if the retained slots already occur in order. A comparison whose only consumer is `verify` can use a native verify instruction where available. [Boundary replay](../projects/p2pkh-schnorr/docs/high-level-forth.en.md#stack-and-model-boundaries)

`weierstrass-scale-affine` maps `p X Y u2 u3` to `p X' Y'`. The affine and homogeneous `-root` variants compute the full square and cube from one nonzero field element. The compiler compares both forms for registered reduced coordinates. The 256-bit lowering bounds the largest intermediate from the root form to 129 ScriptNum bytes. The batch decoder uses `bsv-tile-top` to form repeated masks by doubling and appending the runtime byte item. [Scale words](../src/fourthgraph/stdlib/weierstrass.fth) · [Decoder](../src/fourthgraph/stdlib/script-fragments.fth)

The `dataflow` pass recognizes a run of `bytes-cat` operations that repeats one value. It needs an exact input width and exclusive use of every intermediate inside the run. The compiler compares the entire assembled Script with and without the replacement to account for stack effects. In the six-copy regression, it emits 16 B compared with 21 B from the existing `stack` profile. The explicit build word remains available for constructing a Script from fragments. [Regression cases](../tests/test_dataflow.py)

For a linked call that declares an output as the same value as an input, the scheduler may move that input into the call even if it remains live afterward. The modular scale lowering compares precomputed factors with powers of the registered root once the modulus, coordinate bound and numeric size budget are available. With missing evidence or a wider intermediate, it uses the precomputed-factor instructions. The Schnorr stack-table builder compares both forms of the modulus operand and keeps the smaller schedule. [Modular scale lowering](../src/fourthgraph/compiler/modular_scale.py)

### Projective comparisons across models

The shared Weierstrass formulas offer two ways to check an affine reference point against scaled projective coordinates. A zero-tested residual can include the inverse scale directly, because dropping the intermediate reduction changes the difference by a multiple of the field prime. The signed remainder can change sign, and its zero test remains equivalent. Alternatively, map both affine inputs with the same forward scale and compare within that model. The formula compiler binds the known factors, checks the intermediate ScriptNum bound and compares their emitted cost. Both checks retain the requirement that `Z` is nonzero. [Shared formulas](../src/fourthgraph/stdlib/weierstrass-model.fth) · [Schnorr comparison](../projects/p2pkh-schnorr/docs/high-level-forth.en.md#point-comparison-models)

## STARK verifier iteration

Both profiles generate a complete Forth verifier for the same public statement `(0, 1, 987)`. Each candidate uses the v0.1.0 proofs and the same packet format. The Python comparison checks two accepted statements and 12 rejection controls before ranking by combined lock and unlock bytes. [BabyBear measurements](../projects/plonky3-stark-verifier/versions/v0.2.0/measurements.json) · [Goldilocks measurements](../projects/goldilocks-stark-verifier/versions/v0.2.0/measurements.json)

| Cumulative plan | Reusable compiler change | BabyBear lock | Goldilocks lock |
| --- | --- | ---: | ---: |
| `baseline` | Original assertion order and arithmetic | 358,385 B | 153,829 B |
| `schedule` | Compare grouped operand staging and fuse a numeric comparison used solely by `assert` into `OP_NUMEQUALVERIFY` | 357,357 B | 153,058 B |
| `lookup` | Lower a fixed-width packed table to a single index calculation and exact row read | 342,839 B | 141,059 B |
| `affine` | Factor repeated weighted differences into a shared affine form before reading per-query samples | **292,315 B** | **137,656 B** |

`PackedLookup` derives a row offset from a ScriptNum index and aborts on out-of-range indices. The proof verifier stores the coset point and inverse subgroup point together and selects the row using the Fiat–Shamir index. `WeightedDifferences` rewrites a sum of weighted differences as a shared weighted sum of claims minus a weighted sum of samples. It combines weights for repeated sample columns. The rewrite uses only linearity over the coefficient ring. [Packed lookup](../src/fourthgraph/compiler/packed_lookup.py) · [Weighted differences](../src/fourthgraph/compiler/linear_form.py)

The selected plan puts the tables on the main stack. Observed combined payload peaks move from 73,138 B to 74,722 B for BabyBear and from 73,430 B to 77,267 B for Goldilocks. Peak main stack item counts move from 216 to 115 and from 88 to 63, respectively. Measurements of these peaks use the development evaluator. Funded deployments and valid spends were mined on isolated BSV Node 1.2.3 regtest with the long-script profile. Pinned chain-gang and the node both reject all 12 controls per profile. [BabyBear replay](../projects/plonky3-stark-verifier/versions/v0.2.0/replay.json) · [Goldilocks replay](../projects/goldilocks-stark-verifier/versions/v0.2.0/replay.json)

From the repository root, use `reference/verify.py compare` in either project to regenerate the candidate report. Use `generate` to write `verifier.fth` and compile that file with `4thgraph script-build --entry stark-lock --output lock.bin`. [Named assertion graphs](language/specification.md#forth-断言图) · [BabyBear Forth](../projects/plonky3-stark-verifier/versions/v0.2.0/verifier.fth) · [Goldilocks Forth](../projects/goldilocks-stark-verifier/versions/v0.2.0/verifier.fth)
