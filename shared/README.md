# Shared development infrastructure

- `script.py`: dependency-free Script byte encoder and literal-block assembler. Migration tests reconstruct the existing R1 program byte for byte.
- `transaction.py`: BSV transaction serialization, ForkID BIP143 and Chronicle OTDA preimages. Each project chooses its scriptCode and signing algorithm.
- `pushtx.py`: fixed-r authorization checks and native transaction binding shared by the hash-based signature templates.
- `wots_sha2_script.py`: addressed WOTS+ SHA-256 endpoint reconstruction for the WOTS+ and XMSS templates.
- `spend_authorization.py`: shared ForkID and OTDA preimage selection and witness encoding for WOTS+ and SLH-DSA.
- `chain_gang.py`: complete-input checks with explicit spend, activation and UTXO creation heights. See the [Chronicle regression snapshot](chronicle-regression.md) for the pin and results.
- `evaluate.py`: local development evaluator for the generated opcode subset. It does not implement consensus flags, resource limits or network activation. Use a native CHECKSIG callback for signature opcodes.
- `verify_node.sh`: BSV Node 1.2.3 download/checksum verification and temporary regtest RPC validation. Run from a project's reference directory with its unittest module name. Projects retain their own chain-gang tests.
- `verify_node_apple.sh`: isolated BSV Node 1.2.3 through Apple Container. Each project's launcher chooses its RPC port and test module.
- `test_layout.py`: project-resource links and unchanged R1 template vectors.

Cryptographic parameters, identity policy, witness format and authorization coverage belong to each project. This directory is not a new consensus engine.
