# BN254 Groth16 verification

[简体中文](verification.zh-CN.md) · [Project](../README.md)

## Forth wiring and arithmetic

The verifier entry builds a lock with three typed steps. The owner guard checks the real spend signature using BIP143 ALL. The statement module loads the five deployment-selected public scalars. The final word sends those scalars to Rúnar as `pinnedPublicInputs`, folding all five scalar multiplications into the MSM's initial point during compilation. The emitted predicate checks each witness scalar and the prepared MSM point before verifying the pairing. [Verifier entry](../forth/fixed-verifier.fth) · [Statement module](../forth/statement.fth) · [Typed BN254 linker](../../../src/fourthgraph/verification/groth16_bn254.py)

The Go adapter delegates BN254 group and field code generation to the pinned Rúnar compiler. Its witness builder supplies the proof and arithmetic hints in the same format as v0.1.0. Rúnar emits the on-chain point checks, Miller loop, and residue checks. [Go adapter](../../../src/fourthgraph/verification/groth16_bn254_adapter.go) · [Pinned Rúnar compiler](https://github.com/icellan/runar/blob/dbcc4269f8e0895c4738cf86948b05b7d62a2010/compilers/go/compiler/groth16_wa.go)

## Build and replay

Follow the project setup instructions and run the v0.2.0 build and replay commands from the repository root. The build writes the lock artifact and the push-only proof prefix to `workspace/build/` within this project. The application appends the owner's signature over the actual spend. This backend targets Chronicle. The v0.1.0 entry is available for reproducing the baseline. [Release commands](../versions/v0.2.0/manifest.json) · [Baseline entry](../verifier.fth)

The fixture contains a local test verification key and two proofs for different statements under that key. Funded replay deploys the same lock as the standalone build. Both BSV Node and chain-gang accept the proof for the pinned statement and reject the other valid proof, a negated proof point, a wrong sighash flag, and a changed output with a stale signature. The valid spend mines on regtest. [Test fixture](../versions/v0.1.0/fixture.json) · [Native evidence](../versions/v0.2.0/measurements.json)

## BN254 size comparison

| Implementation and case | Public inputs | Locking script | Unlocking script | Serialized script path |
| --- | ---: | ---: | ---: | ---: |
| 4thGraph v0.1.0, Chronicle regtest | 5 | 1,524,095 B | 31,128 B | 1,555,231 B |
| 4thGraph v0.2.0, same fixture and era | 5 | 821,788 B | 31,129 B | 852,925 B |
| sCrypt factorization tutorial, public BSV testnet | 1 | 1,515,332 B | 264 B | 1,515,604 B |

The two 4thGraph runs use the same key, statement, and proof. v0.2.0 saves 702,307 B of locking script, or 46.1%. Both have the same 31,056 B witness prefix and hash. The one-byte difference in unlocking size comes from the owner's DER signature. The path includes both scripts and their CompactSize lengths. [Measurements](../versions/v0.2.0/measurements.json)

The sCrypt tutorial uses a separate verification key and a single fixed public input. Its unlocking script comes from the tutorial's published spend. These bytes describe the public example. The benchmark with nChain uses BLS12-381. [sCrypt tutorial](https://docs.scrypt.io/bsv-docs/tutorials/zkp/) · [BLS12-381 verification](../../groth16-bls12-381/docs/verification.en.md)
