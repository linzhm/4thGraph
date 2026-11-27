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

The funded replay uses BSV Node 1.2.3 and the pinned chain-gang binding. It deploys the same lock for each proof and mines both v2 spends before Chronicle activation. Both engines reject the swapped public statement and the proof with a G1 point outside the prime-order subgroup for each spend. The commands write their results to `projects/groth16-verifier/workspace/build/`. [Engine pin](../../../tools/requirements-chronicle.txt)

## Measurements and evidence

The v0.5.0 records compare automatic operand scheduling with the v0.4.0 build using the same public input configurations and proof fixture. The layout objective counts the serialized lock and witness script fields. The funded replay totals cover a complete deployment and spend, including the funding signature and transaction framing. The development evaluator measures stack peaks as byte payloads. [v0.5.0 operand measurements](../versions/v0.5.0/measurements.json) · [v0.4.0 packet measurements](../versions/v0.4.0/measurements.json) · [Version index](../versions/index.json)

To reproduce the Chronicle replay, set `REGTEST_CHRONICLE_HEIGHT=2`, pass `--script-era chronicle`, and use a separate output file. To replay a specific layout in either era, replace `--objective path-bytes` with `--witness-layout affine-witness` or `--witness-layout projective`.

## High-level Forth experiment

The v0.6.0 experiment defines proof preparation, the 63 Miller rounds after the leading seed bit, and the terminal product of the Miller accumulator, verification-key factor, and Frobenius of the witness residue. The two terminal words require that the product lies in Fp6 and is nonzero. The backend checks the round sequence against the BLS12-381 seed and supplies the witness, group, and field arithmetic primitives. [High-level Forth](../experiments/high-level/verifier.fth)

The search enumerates legal rewrites of the same Fp2 formula and all three choices for the first pair of factors in the Fp12 product. It compiles the complete verifier for each candidate with the `affine-inline` witness layout. Each candidate runs both proofs and four rejection controls in the development evaluator. The search selects the smallest serialized lock-and-witness path in each Script era, breaking ties by enumeration order. It writes the candidate matrix and the winning lock and plan files. [Search runner](../experiments/high-level/optimize.py) · [v0.6.0 measurements](../versions/v0.6.0/measurements.json)

Run the search and replay its selected Genesis plan from the repository root.

```sh
PYTHONPATH=src:. python3 projects/groth16-verifier/experiments/high-level/optimize.py
out=projects/groth16-verifier/workspace/build/high-level
REGTEST_CHRONICLE_HEIGHT=1000 bash tools/verify_node.sh --profile raised -- \
  python3 -m fourthgraph.replay.bls12381_verifier \
  --source projects/groth16-verifier/experiments/high-level/verifier.fth \
  --entry verify-proof --witness-layout affine-inline --script-era genesis \
  --arithmetic-plan "$out/genesis-plan.json" --output "$out/genesis-replay.json"
```

For Chronicle, use an activation height of `2` and replace `genesis` with `chronicle` in the replay arguments. The replay compiles the supplied Forth and arithmetic plan and checks the resulting lock with BSV Node and chain-gang.
