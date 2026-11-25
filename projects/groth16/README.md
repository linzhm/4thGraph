# Groth16 on BSV

This reference implements plain BLS12-381 Groth16 proving and verification. The Python prover consumes a standard snarkjs `.zkey` and `.wtns`. It uses Metal for number-theoretic transforms and arkworks for curve operations. The Script verifier consumes a proof and the ordered public inputs committed by the spending transaction.

[Python setup and proof formats](docs/toolchain.md) · [BSV SPV Token](../spv-token/README.md)
