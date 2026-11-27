# BN254 Groth16 verification

[简体中文](verification.zh-CN.md) · [Project](../README.md)

## Forth wiring and arithmetic

The [verifier entry](../verifier.fth) builds a lock with three typed steps. The owner guard checks the real spend signature using BIP143 ALL. The [statement module](../forth/statement.fth) loads the five deployment-selected public scalars. The final word sends this statement to Rúnar and links the generated proof predicate after the owner guard. The backend enforces the pinned public scalars and the MSM that binds them to the pairing. [Typed BN254 linker](../../../src/fourthgraph/verification/groth16_bn254.py)

The [Go adapter](../../../src/fourthgraph/verification/groth16_bn254_adapter.go) delegates BN254 group and field code generation to the pinned Rúnar compiler and uses its witness builder for the proof and arithmetic hints. The Forth source describes the authorization and statement flow. Rúnar emits the on-chain point checks, MSM, Miller loop, and residue checks as one predicate. [Pinned Rúnar compiler](https://github.com/icellan/runar/blob/dbcc4269f8e0895c4738cf86948b05b7d62a2010/compilers/go/compiler/groth16_wa.go)

## Build and replay

Follow the project setup instructions and run the v0.1.0 build and replay commands from the repository root. The build writes the lock artifact and the push-only proof prefix to `workspace/build/` within this project. The application appends the owner's signature over the actual spend. This backend targets Chronicle. [Release commands](../versions/v0.1.0/manifest.json)

The checked-in fixture contains a local test verification key and two proofs for different statements under that key. The funded replay mines the proof for the pinned statement and rejects the other valid proof, a negated proof point, a wrong sighash flag, and a changed output with a stale signature. [Test fixture](../versions/v0.1.0/fixture.json) · [Native evidence](../versions/v0.1.0/measurements.json)
