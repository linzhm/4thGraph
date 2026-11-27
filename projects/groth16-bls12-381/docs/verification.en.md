# Groth16 verifier build and replay

[简体中文](verification.zh-CN.md) · [Project overview](../README.md)

## Forth call and inputs

The project calls `groth16-bls12-381-verify` through the standard-library import. Its Forth result type denotes a successful proof check. An invalid proof aborts Script. Applications can add signature authorization and transaction binding around the verifier. [Project source](../verifier.fth) · [Verifier interface](../../../docs/groth16-bls12-381.md)

```forth
REQUIRE stdlib/groth16-bls12-381.fth

: verify-proof ( -- groth16-verified )
    groth16-bls12-381-verify
;
```

The demonstration uses the public test verification key and two proofs from Proof counter v0.1.0. The five public signals are supplied at spend time in verification-key order, with widths of 32, 1, 32, 2, and 2 bits. [Proof fixture](../../proof-counter/versions/v0.1.0/bls12381-counter.json) · [Input configuration](../versions/v0.1.0/input-sources.json)

## Build and replay

For the standard-library example, run the v0.5.0 build and verify commands from the repository root. The build selects `verify-proof` with the BLS12-381 backend, targets Genesis Script, and uses `path-bytes` to select a witness layout. It saves the lock manifest and push-only witness for the `wrap` fixture. The lock manifest records the imported library and entry name. [Standard-library build and replay commands](../versions/v0.5.0/manifest.json)

The funded replay uses BSV Node 1.2.3 and the pinned chain-gang binding. It deploys the same lock for each proof and mines both v2 spends before Chronicle activation. Both engines reject the swapped public statement and the proof with a G1 point outside the prime-order subgroup for each spend. The commands write their results to `projects/groth16-bls12-381/workspace/build/`. [Engine pin](../../../tools/requirements-chronicle.txt)

## Measurements and evidence

The v0.5.0 records compare automatic operand scheduling with the v0.4.0 build using the same public input configurations and proof fixture. The layout objective counts the serialized lock and witness script fields. The funded replay totals cover a complete deployment and spend, including the funding signature and transaction framing. The development evaluator measures stack peaks as byte payloads. [v0.5.0 operand measurements](../versions/v0.5.0/measurements.json) · [v0.4.0 packet measurements](../versions/v0.4.0/measurements.json) · [Version index](../versions/index.json)

To reproduce the Chronicle replay, set `REGTEST_CHRONICLE_HEIGHT=2`, pass `--script-era chronicle`, and use a separate output file. To replay a specific layout in either era, replace `--objective path-bytes` with `--witness-layout affine-witness` or `--witness-layout projective`.

## Current Forth entry

[`forth/verifier.fth`](../forth/verifier.fth) imports three modules with `REQUIRE` and calls them from `verify-proof ( -- groth16-verified )`. The root [`verifier.fth`](../verifier.fth) is the minimal example that imports the standard-library verifier. This project targets BLS12-381.

| Module | Typed Forth flow | Arithmetic |
| --- | --- | --- |
| [`public-inputs.fth`](../forth/public-inputs.fth) | Read the witness, check proof points A and C, and prepare the pairing key. | The backend enforces the public-input bounds, checks the G1 points, and computes (VK_x=IC_0+\sum_i s_iIC_i). The selected affine plan checks the signed radix-4 MSM slopes. [Affine lowering](../../../src/fourthgraph/verification/bls12381/affine_witness.py) |
| [`miller.fth`](../forth/miller.fth) | Build and execute the 63-round schedule after the leading BLS12-381 seed bit. | A zero bit applies the tangent lines. A one bit also applies the chord lines and the residue factor. The backend checks every B slope and its subgroup relation. [Miller lowering](../../../src/fourthgraph/verification/bls12381/affine_witness.py) |
| [`residue.fth`](../forth/residue.fth) | Combine the accumulator, verification-key factor and Frobenius image of the witness residue. Require membership in Fp6 and nonzero. | The compiler lowers the Fp12 product and both assertions through the field tower. [Residue lowering](../../../src/fourthgraph/verification/bls12381/verifier.py) |

The definitions describe the control flow and stack effects. The [typed stage vocabulary](../../../src/fourthgraph/verification/bls12381/build.py) connects these words to the group and field backend. The field tower loads the [Fp2 multiplication formula](../../../src/fourthgraph/stdlib/bls12-381-fp2.fth) through the formula compiler. The artifact records the root source, imported modules, Fp2 formula and arithmetic plan by digest. [Field tower](../../../src/fourthgraph/verification/bls12381/field.py)

Build the selected release and optionally fund both proofs from the repository root.

```sh
PYTHONPATH=src:. python3 projects/groth16-bls12-381/reference/replay_plan.py --release current
REGTEST_CHRONICLE_HEIGHT=1000 bash tools/verify_node.sh --profile raised -- \
  python3 projects/groth16-bls12-381/reference/replay_plan.py --release current --funded
```

For Chronicle set the activation height to `2` and add `--script-era chronicle`. The runner writes the checked lock and both witnesses under `projects/groth16-bls12-381/workspace/build/pinned-v0.13.0/`, with a replay report for funded runs. The pinned plan verifies file and bytecode digests. [v0.13.0 replay plan](../versions/v0.13.0/replay-plan.json)

v0.12.0 retains the v0.11.0 MSM and Miller plan and compares G1 reduction after each doubling against reduction after a pair of consecutive doublings. Pairing these reductions saves 1,282 bytes in either era. The serialized lock and witness total 238,122 bytes on Genesis and 237,217 bytes on Chronicle for the five bounded dynamic inputs in the fixture. The measured stack peak stays at 29,891 bytes and verification takes longer in the paired timing samples. [v0.12.0 measurements](../versions/v0.12.0/measurements.json)

v0.13.0 compares G1 Z batches of 1, 4, 8 and 16 doublings with and without compact numeric boolean lowering. The search selects 16 with the boolean pass enabled. The serialized lock and witness total 237,225 bytes on Genesis and 236,566 bytes on Chronicle. Both fixture witnesses retain their hashes and the measured stack peak is 29,891 bytes. Paired verification timings are mixed across the two engines and Script eras. The report records the medians for batch sizes 4, 8 and 16 against v0.12.0. [v0.13.0 measurements](../versions/v0.13.0/measurements.json)

## nChain and sCrypt comparison

The Genesis regtest compares the same BLS12-381 key, two proofs, five bounded spend-time inputs, and transaction version. The serialized script path is the lock plus the unlock with both CompactSize lengths. The ranges cover the two proofs. [v0.13.0 funded replay](../versions/v0.13.0/nchain-comparison.json)

| Implementation and layout | Locking script | Unlocking script | Serialized script path |
| --- | ---: | ---: | ---: |
| 4thGraph v0.13.0, affine with inline lines | 227,839 B | 9,378 B | 237,225 B |
| nChain affine, fixed pairing gradients in lock | 385,600 B | 8,604–11,027 B | 394,212–396,635 B |
| nChain affine, pairing gradients in witness | 373,355 B | 21,926–24,349 B | 395,289–397,712 B |
| nChain projective | 448,202 B | 1,112–1,134 B | 449,322–449,344 B |

4thGraph's path is 39.8–40.2% smaller than the shortest tested nChain path. The nChain projective layout has the smallest unlock. All eight valid spends mined and both BSV Node and chain-gang rejected all eight crossed statements. The nChain rows use unmodified `fc20fb7` at a 6,400-bit reduction threshold, selected from the earlier three-threshold sweep. [nChain source](https://github.com/nchain-innovation/zkscript_package/tree/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4) · [Earlier sweep](../versions/v0.11.0/nchain-comparison.json)

The public transactions below use the original examples' keys and statements. Their sizes come from the identified transaction inputs and outputs. The sCrypt BLS12-381 example supplies a deployment only, so its available measurement is the locking script. The sCrypt factorization tutorial uses BN254 and one fixed public input. [Transaction IDs and hashes](../versions/v0.13.0/public-comparison.json) · [nChain paper](https://eprint.iacr.org/2024/1498) · [sCrypt BLS12-381 example](https://scryptplatform.medium.com/guest-post-elliptic-curve-bls12-381-support-on-bitcoin-bc7bfa605135) · [sCrypt BN254 tutorial](https://docs.scrypt.io/bsv-docs/tutorials/zkp/)

| Published example | Network and curve | Locking script | Unlocking script | Serialized script path |
| --- | --- | ---: | ---: | ---: |
| nChain Groth16 | BSV mainnet, BLS12-381 | 482,601 B | 39,876 B | 522,485 B |
| BLS12-381 library example written in sCrypt | BSV testnet, BLS12-381 | 27,549,371 B | — | — |
| sCrypt factorization tutorial | BSV testnet, BN254 | 1,515,332 B | 264 B | 1,515,604 B |

Run from the repository root with the pinned chain-gang Python environment. The separate Python 3.12 environment installs the nChain generator dependencies. The final command downloads or reads cached raw transactions and checks both their IDs and the measured script sizes.

```sh
checkout="$PWD"
ref="$checkout/projects/groth16-bls12-381/reference"
out="$checkout/projects/groth16-bls12-381/workspace/build/comparison"
git clone https://github.com/nchain-innovation/zkscript_package "$out/nchain"
git -C "$out/nchain" checkout --detach fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4
(
  cd "$out/nchain"
  python3.12 -m venv .venv
  .venv/bin/python -m pip install -r requirements.txt
  PYTHONPATH=src:. .venv/bin/python "$ref/prepare_nchain.py" "$out/nchain-scripts.json"
)
REGTEST_CHRONICLE_HEIGHT=1000 bash tools/verify_node.sh --profile raised -- \
  python3 "$ref/replay_nchain.py" "$out/nchain-scripts.json" "$out/nchain-replay.json"
PYTHONPATH=src:. python3 "$ref/check_public_comparison.py"
```

## High-level Forth experiment

The v0.6.0 experiment defines proof preparation, the 63 Miller rounds after the leading seed bit, and the terminal product of the Miller accumulator, verification-key factor, and Frobenius of the witness residue. The two terminal words require that the product lies in Fp6 and is nonzero. The backend checks the round sequence against the BLS12-381 seed and supplies the witness, group, and field arithmetic primitives. [High-level Forth](../experiments/high-level/verifier.fth)

The search enumerates legal rewrites of the same Fp2 formula and all three choices for the first pair of factors in the Fp12 product. It can also compare the Fp2 formulas at each call site, using constant folding, shared definitions, and a local stack emission as the cost estimate. The search compares both kinds of lowering on the complete verifier with the `affine-inline` witness layout. Each candidate runs both proofs and four rejection controls in the development evaluator. The search selects the smallest serialized lock-and-witness path in each Script era, breaking ties by enumeration order. [Search runner](../experiments/high-level/optimize.py) · [v0.6.0 measurements](../versions/v0.6.0/measurements.json)

The v0.7.0 experiment holds the residue multiplication order fixed and edits the same Forth file twice. It measures the original order, both G1 checks before public-input MSM, and MSM between the A and C checks. Each round records its Git revision. To reproduce a round, extract its `experiments/high-level/verifier.fth` from that revision and pass the copy using `--source` in the search and replay. The current Forth source runs both G1 checks before MSM. [v0.7.0 measurements](../versions/v0.7.0/measurements.json)

The v0.8.0 search compares unsigned and signed radix-4 MSM on that Forth source, generating a matching witness for each strategy. The signed digits reuse positive multiples for negative digits and can require extra slope windows for carries. Search ranks the serialized lock and witness together. Set `--msm unsigned-radix4 --miller-reductions per-operation --miller-kernel cross-products` to reproduce the earlier unsigned comparison. The signed plan applies to both affine layouts. [v0.8.0 MSM measurements](../versions/v0.8.0/measurements.json)

The v0.9.0 experiment holds signed radix-4 fixed and compares explicit points with a table that reconstructs points from verification-key doubling slopes. Both encodings share the same witness. The source trial changes the high-level Forth to check C before A. It recompiles both sources and records the full lock and witness size for each. Set `--msm-table points --miller-reductions per-operation --miller-kernel cross-products` to reproduce the v0.8.0 point-table comparison. [v0.9.0 table and source measurements](../versions/v0.9.0/measurements.json)

The v0.10.0 search keeps the same Forth source, fixture and Fp2 policy. It compares three signed MSM table representations with three Miller reduction schedules. The selected plan reduces the MSM accumulator after point selection and reduces the Fp12 accumulator once per Miller round. It uses the same serialized witness as v0.9.0. For the v0.10.0 schedules, omit the stack limit and set `--miller-kernel cross-products`. Set `--miller-reductions per-step` to measure the shorter group, or combine `--msm-table doubling-slopes` with `--miller-reductions per-operation` to reproduce the v0.9.0 baseline. [v0.10.0 measurements](../versions/v0.10.0/measurements.json)

The v0.11.0 experiment pins the selected v0.10.0 MSM table and compares the existing Miller kernel with direct sparse products and normalized G2 point updates. Two new reduction schedules split rounds that have chord lines, with an optional checkpoint before multiplying by the residue. The reproduction command selects the smallest path with a combined main-stack and alt-stack payload of at most 32,000 bytes across the two valid development proofs using `affine-inline`. Omit the stack limit to select by bytes alone. To reproduce the selected v0.10.0 plan, omit the stack limit and set `--miller-kernel cross-products --miller-reductions per-round`. [v0.11.0 measurements](../versions/v0.11.0/measurements.json)

Run the search and replay its selected Genesis plan from the repository root.

```sh
PYTHONPATH=src:. python3 projects/groth16-bls12-381/experiments/high-level/optimize.py \
  --residue-association accumulator-frobenius-first --fp2-selection callsite --msm signed-radix4 \
  --msm-table deferred-doubling-slopes --max-fixture-stack-bytes 32000
out=projects/groth16-bls12-381/workspace/build/high-level
REGTEST_CHRONICLE_HEIGHT=1000 bash tools/verify_node.sh --profile raised -- \
  python3 -m fourthgraph.replay.bls12381_verifier \
  --source projects/groth16-bls12-381/experiments/high-level/verifier.fth \
  --entry verify-proof --witness-layout affine-inline --script-era genesis \
  --arithmetic-plan "$out/genesis-plan.json" --output "$out/genesis-replay.json"
```

For Chronicle, use an activation height of `2` and replace `genesis` with `chronicle` in the replay arguments. The replay compiles the supplied Forth and arithmetic plan and checks the resulting lock with BSV Node and chain-gang.
