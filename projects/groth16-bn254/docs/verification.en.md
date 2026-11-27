# BN254 Groth16 verification

[简体中文](verification.zh-CN.md) · [Project](../README.md)

## Forth wiring and arithmetic

The verifier entry builds a lock from the owner guard, the deployment-selected public scalars, and `bn254-compact-fixed-pairing`. The compiler computes the MSM point \(L\), absorbs its Miller factor with \(-\gamma\) into the \(\alpha,-\beta\) factor, and precomputes the lines for \(-\delta\). The proof supplies \(A,B,C\), the variable Miller slopes for \(B\), and the residue witness. The verifier uses the fixed factors for the chosen statement. [Verifier entry](../forth/compact-verifier.fth) · [Statement module](../forth/statement.fth) · [Typed BN254 linker](../../../src/fourthgraph/verification/groth16_bn254.py)

The Go adapter applies the extension through an overlay on the pinned Rúnar checkout. The precomputed lines keep the legacy field representatives and Frobenius corrections so the verifier and witness builder use the same Miller product. The G2 check validates the twist equation before evaluating \([6u^2]B=\psi(B)\) in Jacobian coordinates. It requires nonzero \(Z\) and compares the affine image by cross multiplication. A degenerate addition or doubling leaves \(Z=0\) through the rest of the chain and fails. The residue equations still check the inverse and the final pairing product. [Go adapter](../../../src/fourthgraph/verification/groth16_bn254_adapter.go) · [Compiler extension](../../../src/fourthgraph/verification/runar/compact_groth16.go)

The owner guard verifies a BIP143 ALL signature over the actual spend. The replay uses the authorization preparation function shared with the preimage constructor to obtain the signing digest. For `wrap` the preimage is 540,095 B. The signer receives the digest and the unlocking script contains the proof witness and signature, with zero preimage bytes. Construction of an explicit preimage witness is useful when Script must inspect transaction fields, such as in a covenant. [Shared preimage constructor](../../../src/fourthgraph/workflow/preimage_constructor.py)

## Build and replay

Follow the project setup instructions and run the v0.3.0 build and replay commands from the repository root. The build writes the lock artifact and the push-only proof prefix to `workspace/build/` within this project. The replay defaults to `wrap`. Pass `--fixture-case other` to compile a lock for the other statement and replay its proof. The v0.2.0 entry reproduces the historical lock and witness hashes. [Release commands](../versions/v0.3.0/manifest.json) · [v0.2.0 entry](../forth/fixed-verifier.fth)

The fixture uses a test-only key and two statements. Both valid spends mined on Chronicle regtest. Both BSV Node and chain-gang rejected a valid proof for the other statement, a negated proof point, a G2 point outside the subgroup, a wrong sighash flag and a changed output with a stale signature. An isolated codegen test also compares the subgroup check against gnark without running a pairing. [Fixture](../versions/v0.1.0/fixture.json) · [Funded evidence](../versions/v0.3.0/measurements.json) · [Subgroup test](../../../src/fourthgraph/verification/runar/compact_groth16_test.go)

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
| sCrypt factorization tutorial, public BSV testnet | 1 | 1,515,332 B | 264 B | 1,515,604 B |

The two historical 4thGraph runs use the same key, statement, and proof. v0.2.0 saves 702,307 B of locking script, or 46.1%. Both have the same 31,056 B witness prefix and hash. The one-byte difference in unlocking size comes from the owner's DER signature. The path includes both scripts and their CompactSize lengths. [v0.2.0 measurements](../versions/v0.2.0/measurements.json)

The sCrypt tutorial uses a separate verification key and a single fixed public input. Its unlocking script comes from the tutorial's published spend. These bytes describe the public example. The benchmark with nChain uses BLS12-381. [sCrypt tutorial](https://docs.scrypt.io/bsv-docs/tutorials/zkp/) · [BLS12-381 verification](../../groth16-bls12-381/docs/verification.en.md)
