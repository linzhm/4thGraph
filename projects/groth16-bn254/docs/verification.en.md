# BN254 Groth16 verification

[简体中文](verification.zh-CN.md) · [Project](../README.md)

## Forth wiring and arithmetic

The fixed-statement entry checks the owner signature, reads the witness, validates the proof points, and runs the subgroup, Miller and residue checks. The compiler folds the MSM point \(L\) and \(-\gamma\) into the \(\alpha,-\beta\) factor and precomputes the lines for \(-\delta\). The witness carries the proof points, the variable Miller slopes for \(B\), and the residue witness. [Forth entry](../forth/verifier.fth) · [Fixed statement](../forth/statement.fth)

The Forth Jacobian definitions specify the doubling and mixed-add formulas over Fp2. The subgroup module specifies the 127-round signed ladder for \([6u^2]B\) and its Frobenius comparison. The Miller module specifies 65 rounds for \(6u+2\), with tangent lines, signed additions, residue folds and final Frobenius lines. The residue module requires the paired value to equal one. The backend lowers Fp2 and Fp12 arithmetic and validates both schedules against the BN254 constants and witness layout before emission. [Jacobian formulas](../forth/jacobian.fth) · [Subgroup](../forth/subgroup.fth) · [Miller](../forth/miller.fth) · [Residue](../forth/residue.fth) · [Backend](../../../src/fourthgraph/verification/runar/forth_groth16.go)

The owner guard verifies a BIP143 ALL signature over the actual spend. The replay uses the authorization preparation function shared with the preimage constructor to obtain the signing digest. For `wrap` the preimage is 505,340 B. The signer receives the digest and the unlocking script contains the proof witness and signature, with zero preimage bytes. Construction of an explicit preimage witness is useful when Script must inspect transaction fields, such as in a covenant. [Shared preimage constructor](../../../src/fourthgraph/workflow/preimage_constructor.py)

## Build and replay

Follow the project setup instructions and run the v0.4.0 build and replay commands from the repository root. The build writes the lock artifact and the push-only proof prefix to `workspace/build/` within this project. The replay defaults to `wrap`. Pass `--fixture-case other` to compile a lock for the other statement and replay its proof. The v0.3.0 entry reproduces the previous lock and witness hashes. [Release commands](../versions/v0.4.0/manifest.json) · [v0.3.0 entry](../forth/compact-verifier.fth)

The fixture uses a test-only key and two statements. Both valid spends mined on Chronicle regtest. Both BSV Node and chain-gang rejected a valid proof for the other statement, a negated proof point, a G2 point outside the subgroup, a wrong sighash flag and a changed output with a stale signature. An isolated codegen test also compares the subgroup check against gnark without running a pairing. [Fixture](../versions/v0.1.0/fixture.json) · [Funded evidence](../versions/v0.4.0/measurements.json) · [Subgroup test](../../../src/fourthgraph/verification/runar/compact_groth16_test.go)

## Stack scheduling result

The compiler replaces two equal-depth moves with one pair operation. The wrap lock fell from 539,934 B to 505,179 B at the same 64 B reduction threshold. Across the two fixtures it makes 1,291 replacements with `OP_2OVER`, 809 with `OP_2SWAP`, and 9,485 with `OP_2ROT` per lock. Each replacement saves three bytes. The wrap witness prefix is 6,765 B and the combined stack payload peaks at 8,872 B. The measured script path, including the full unlock and both CompactSize prefixes, is 512,024 B. [Compiler pass](../../../src/fourthgraph/compiler/stack_schedule.py) · [v0.4.0 measurements](../versions/v0.4.0/measurements.json)

## Compiler plan comparison

The search used the same key and both proofs on one Chronicle regtest node, with five timed samples per plan and statement after warm-up. The table shows `wrap` sizes. The report includes the raw timings and `other` results. The peak counts main and alternate stack payloads. [Full comparison](../versions/v0.3.0/plan-comparison.json)

| Compiled plan | Lock | Witness prefix | Serialized script path | Stack peak |
| --- | ---: | ---: | ---: | ---: |
| v0.2.0 | 821,788 B | 31,056 B | 852,925 B | 31,071 B |
| Fixed pairings and affine subgroup check | 598,775 B | 19,634 B | 618,490 B | 19,998 B |
| Fixed pairings and projective binary ladder | 652,046 B | 6,765 B | 658,891 B | 8,863 B |
| Fixed pairings and projective NAF ladder | 627,022 B | 6,765 B | 633,868 B | 8,863 B |
| Projective NAF and 64 B reduction threshold | **539,934 B** | **6,765 B** | **546,780 B** | **8,872 B** |

NAF uses 127 doublings and 39 additions instead of 126 and 69 for binary. The 64 B plan was the smallest candidate that verified both fixtures. The 128, 256 and 512 B candidates failed valid-proof checks in BSV Node and were excluded. The chosen plan reduces the wrap lock by 34.3%, the witness prefix by 78.2%, and the serialized script path by 35.9%. The path includes the owner signature and CompactSize prefixes. Signature length can vary by a byte between transactions.

```sh
REGTEST_CHRONICLE_HEIGHT=2 bash tools/verify_node.sh --profile long-script -- \
  python3 projects/groth16-bn254/reference/compare_plans.py --runar workspace/runar \
  --output projects/groth16-bn254/workspace/build/plan-comparison.json
```

The command writes the report after both fixtures pass with the baseline and the selected 64 B plan. It records script rejections for other candidates and exits on compiler or RPC errors.

## BN254 size comparison

| Implementation and case | Public inputs | Locking script | Unlocking script | Serialized script path |
| --- | ---: | ---: | ---: | ---: |
| 4thGraph v0.1.0, Chronicle regtest | 5 | 1,524,095 B | 31,128 B | 1,555,231 B |
| 4thGraph v0.2.0, same fixture and era | 5 | 821,788 B | 31,129 B | 852,925 B |
| 4thGraph v0.4.0, same fixture and era | 5 | 505,179 B | 6,837 B | 512,024 B |
| sCrypt factorization tutorial, public BSV testnet | 1 | 1,515,332 B | 264 B | 1,515,604 B |

The two historical 4thGraph runs use the same key, statement, and proof. v0.2.0 saves 702,307 B of locking script, or 46.1%. Both have the same 31,056 B witness prefix and hash. The one-byte difference in unlocking size comes from the owner's DER signature. The path includes both scripts and their CompactSize lengths. [v0.2.0 measurements](../versions/v0.2.0/measurements.json)

The sCrypt tutorial uses a separate verification key and a single fixed public input. Its unlocking script comes from the tutorial's published spend. These bytes describe the public example. The benchmark with nChain uses BLS12-381. [sCrypt tutorial](https://docs.scrypt.io/bsv-docs/tutorials/zkp/) · [BLS12-381 verification](../../groth16-bls12-381/docs/verification.en.md)
