# BN254 Groth16 verification

[简体中文](verification.zh-CN.md) · [Project](../README.md)

## Forth wiring and arithmetic

The fixed-statement entry checks the owner signature, reads the witness, validates the proof points, and runs the subgroup, Miller and residue checks. The compiler folds the MSM point \(L\) and \(-\gamma\) into the \(\alpha,-\beta\) factor and precomputes the lines for \(-\delta\). The witness carries the proof points, the variable Miller slopes for \(B\), and the residue witness. [Forth entry](../forth/optimized-verifier.fth) · [Fixed statement](../forth/statement.fth)

The Forth Jacobian definitions specify the doubling and mixed-add formulas over Fp2. The subgroup module specifies the 127-round signed ladder for \([6u^2]B\) and its Frobenius comparison. The Miller module specifies 65 rounds for \(6u+2\), with tangent lines, signed additions, residue folds and final Frobenius lines. The residue module requires the paired value to equal one. The backend lowers Fp2 and Fp12 arithmetic and validates both schedules against the BN254 constants and witness layout before emission. [Jacobian formulas](../forth/jacobian.fth) · [Subgroup](../forth/subgroup.fth) · [Miller](../forth/miller.fth) · [Residue](../forth/residue.fth) · [Backend](../../../src/fourthgraph/verification/runar/forth_groth16.go)

The owner guard verifies a BIP143 ALL signature over the actual spend. The replay uses the authorization preparation function shared with the preimage constructor to obtain the signing digest. For `wrap` the preimage is 464,558 B. The signer receives the digest and the unlocking script contains the proof witness and signature, with zero preimage bytes. Construction of an explicit preimage witness is useful when Script must inspect transaction fields, such as in a covenant. [Shared preimage constructor](../../../src/fourthgraph/workflow/preimage_constructor.py)

## Build and replay

Follow the project setup instructions and run the v0.7.0 build and replay commands from the repository root. The build writes the lock artifact and the push-only proof prefix to `workspace/build/` within this project. The replay command runs both fixture cases, with a separate lock and spend for each fixed statement. The previous Forth entries reproduce their respective lock and witness hashes. [Release commands](../versions/v0.7.0/manifest.json) · [v0.6.0 entry](../forth/last-use-verifier.fth) · [v0.5.0 entry](../forth/compact-stack-verifier.fth) · [v0.4.0 entry](../forth/verifier.fth) · [v0.3.0 entry](../forth/compact-verifier.fth)

The fixture uses a test-only key and two statements. Both valid spends mined on Chronicle regtest. Both BSV Node and chain-gang rejected a valid proof for the other statement, a negated proof point, a G2 point outside the subgroup, a wrong sighash flag and a changed output with a stale signature. An isolated codegen test also compares the subgroup check against gnark without running a pairing. [Fixture](../versions/v0.1.0/fixture.json) · [Funded evidence](../versions/v0.7.0/measurements.json) · [Subgroup test](../../../src/fourthgraph/verification/runar/compact_groth16_test.go)

## Stack scheduling result

The compiler replaces two equal-depth moves with one pair operation. The wrap lock fell from 539,934 B to 505,179 B at the same 64 B reduction threshold. Across the two fixtures it makes 1,291 replacements with `OP_2OVER`, 809 with `OP_2SWAP`, and 9,485 with `OP_2ROT` per lock. Each replacement saves three bytes. The wrap witness prefix is 6,765 B and the combined stack payload peaks at 8,872 B. The measured script path, including the full unlock and both CompactSize prefixes, is 512,024 B. [Compiler pass](../../../src/fourthgraph/compiler/stack_schedule.py) · [v0.4.0 measurements](../versions/v0.4.0/measurements.json)

The v0.5.0 Forth entry selects a compiler pass that combines removals of stack items and shortens copy and rotation sequences at literal depths. The pass runs before deployment and spend signing. It preserves the final stack and required input depth of each window. The witness hashes and arithmetic schedules match v0.4.0. [Stack compaction](../../../src/fourthgraph/compiler/stack_peephole.py)

| Version | Fixture | Locking script | Witness prefix | Serialized script path | Deployment transaction | Spend transaction | Total |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| v0.5.0 | `wrap` | 492,007 B | 6,765 B | 498,852 B | 492,143 B | 6,934 B | 499,077 B |
| v0.5.0 | `other` | 492,005 B | 6,761 B | 498,847 B | 492,141 B | 6,931 B | 499,072 B |
| v0.6.0 | `wrap` | 470,781 B | 6,765 B | 477,627 B | 470,917 B | 6,935 B | 477,852 B |
| v0.6.0 | `other` | 470,779 B | 6,761 B | 477,620 B | 470,916 B | 6,930 B | 477,846 B |
| v0.7.0 | `wrap` | 464,397 B | 6,765 B | 471,242 B | 464,534 B | 6,934 B | **471,468 B** |
| v0.7.0 | `other` | 464,395 B | 6,761 B | 471,236 B | 464,531 B | 6,930 B | **471,461 B** |

Each v0.5.0 lock is 13,172 B smaller than its v0.4.0 counterpart. The table records regtest runs and counts the fully serialized deployment and one spend. Regtest funding transactions are separate. DER signature lengths can change the serialized script path and transaction totals across replays. Each release and fixture has fixed lock and proof witness-prefix digests. The combined stack payload peaks at 8,872 B for `wrap` and 8,870 B for `other`. [v0.5.0 measurements](../versions/v0.5.0/measurements.json)

In v0.6.0 the backend counts the remaining uses of each Fp2 operand in a Jacobian formula. It consumes the original slot on its last use and keeps borrowed affine coordinates available to subsequent rounds. The tracker binds returned coordinate names at their current stack positions. Both locks shrink by 21,226 B. The witness prefix hashes, arithmetic schedules and measured peak stack payloads match v0.5.0. [Compiler pass](../../../src/fourthgraph/verification/runar/forth_liveness.go) · [v0.6.0 measurements](../versions/v0.6.0/measurements.json)

In v0.7.0 the compiler renames the Fp12 result slots in place. Later arithmetic reads the slots by name at their existing positions. This saves 6,384 B in each lock and leaves the witness byte-for-byte identical. The optimized Forth entry enables this pass alongside the earlier stack optimizations. [Backend pass](../../../src/fourthgraph/verification/runar/forth_fp12_rename.patch) · [v0.7.0 measurements](../versions/v0.7.0/measurements.json)

## Optimization headroom

The v0.6.0 phase profile accounts for all 470,781 B of the `wrap` lock. The compiler adds stage information to the emitted operations. The resulting bytecode matches the published lock hash. Applying the same Script compaction pass again saves 0 B on either fixture. [Phase profile and Fp12 experiment](../versions/v0.6.0/optimization-profile.json)

From the repository root, run the profiler to regenerate and check both fixture reports.

```sh
PYTHONPATH=src:. python3 projects/groth16-bn254/reference/profile_phases.py \
  --runar workspace/runar --check \
  --output projects/groth16-bn254/workspace/build/phase-profile.json
```

| Phase | Lock bytes | Share |
| --- | ---: | ---: |
| Miller loop, including residue folds | 391,175 B | 83.1% |
| G2 subgroup check | 65,157 B | 13.8% |
| Other checks and setup | 14,449 B | 3.1% |

Fp12 squaring occupies 96,460 B within the Miller loop. Variable-line sparse multiplication occupies 95,460 B, and the fixed-line block occupies 108,438 B, including the signed point setup before variable-line additions. These sizes give the scale of the work for a compiler pass that specializes Fp12 arithmetic or combines line multiplications. The entire `wrap` witness prefix is 6,765 B, including 5,675 B for slopes.

From the v0.7.0 `wrap` total, reaching 450,000 B requires another 21,468 B. That is about 5.5% of the measured v0.6.0 Miller code. Reaching 400,000 B requires 71,468 B, about 18.3% of that code. Both figures are target budgets. Each new arithmetic lowering needs a separate bytecode build and regtest replay. [Current measured transactions](../versions/v0.7.0/measurements.json)

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
| 4thGraph v0.5.0, same fixture and era | 5 | 492,007 B | 6,837 B | 498,852 B |
| 4thGraph v0.6.0, same fixture and era | 5 | 470,781 B | 6,838 B | 477,627 B |
| 4thGraph v0.7.0, same fixture and era | 5 | 464,397 B | 6,837 B | 471,242 B |
| sCrypt factorization tutorial, public BSV testnet | 1 | 1,515,332 B | 264 B | 1,515,604 B |

The two historical 4thGraph runs use the same key, statement, and proof. v0.2.0 saves 702,307 B of locking script, or 46.1%. Both have the same 31,056 B witness prefix and hash. The one-byte difference in unlocking size comes from the owner's DER signature. The path includes both scripts and their CompactSize lengths. [v0.2.0 measurements](../versions/v0.2.0/measurements.json)

The sCrypt tutorial uses a separate verification key and a single fixed public input. Its unlocking script comes from the tutorial's published spend. These bytes describe the public example. The benchmark with nChain uses BLS12-381. [sCrypt tutorial](https://docs.scrypt.io/bsv-docs/tutorials/zkp/) · [BLS12-381 verification](../../groth16-bls12-381/docs/verification.en.md)
