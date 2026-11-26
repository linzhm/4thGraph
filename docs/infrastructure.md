# Shared development infrastructure

- `script.py`: dependency-free Script byte encoder and literal-block assembler. Migration tests reconstruct the existing R1 program byte for byte.
- `transaction.py`: BSV transaction serialization, BIP143 and Chronicle OTDA preimages. Each project chooses its scriptCode and signing algorithm.
- `pushtx.py`: fixed-r authorization checks and native transaction binding shared by the hash-based signature templates.
- `evaluate.py`: local development evaluator for the generated opcode subset. It does not implement consensus flags, resource limits or network activation. Use a native CHECKSIG callback for signature opcodes.
- `verify_node.sh`: BSV Node 1.2.3 download, verification against a repository-pinned SHA-256 digest, and temporary regtest RPC validation. Run from a project's reference directory with its unittest module name. Set `REGTEST_RPC_PORT` to a free port per concurrent run, for example `REGTEST_RPC_PORT=18461 bash verify.sh` for a project's Linux launcher. The default is `18443`. The launcher exports the matching loopback `REGTEST_URL` and cookie for the tests. Projects retain their own chain-gang tests.
- `verify_node_apple.sh`: isolated BSV Node 1.2.3 through Apple Container. Each project's launcher chooses its RPC port and test module.
- `test_layout.py`: project-resource links and unchanged R1 template vectors.

- `spend_authorization.py` selects the BIP143 or OTDA preimage and encodes the witness for ML-DSA-44.
- `chain_gang.py` verifies complete inputs at explicit Chronicle heights. The [regression record](chronicle-regression.md) includes the dependency pin and results.

Reusable Python modules live in [the 4thGraph package](../src/fourthgraph). Cryptographic parameters, identity policy, witness format and authorization coverage belong to each project. This directory is not a new consensus engine.

- [Signed transaction benchmark](benchmark.md) and [简体中文](benchmark.zh-CN.md) describe
  the cross-project cost, acceptance, and funded regtest reports.
