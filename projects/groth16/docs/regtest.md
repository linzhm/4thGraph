# Groth16 issuance and regtest replay

The fixture issues exactly 1,024 token units from a single issuance outpoint. The token output encodes the issuance outpoint, uint64 quantity and compressed secp256k1 owner key. Satoshi amounts are separate carrier values and fees. The signed chain is issuance to Alice, split into 640 for Alice and 384 for Bob, then merged into 1,024 for Alice. Split and merge use the compact verifier at input zero and shared guard at input one.

Use Circom 2.2.3, Node.js, Python 3.12 or newer, ecdsa 0.19.1, and the project's configured chain-gang build. The runner compiles the BLS12-381 R1CS, runs the WASM witness generator for the actual transaction digest, and proves the resulting two-constraint circuit. The bundled Python prover reads the compiler artifacts directly and uses public test-only Groth16 setup and randomness. It is an interoperability fixture with publicly known toxic waste and must never secure assets. The runner exports proof, verification key and public signal JSON and reimports them through the project adapter before building each witness.

Run the offline chain-gang regression from the repository root:

```sh
PYTHONPATH=.:projects/groth16/reference python3 projects/groth16/reference/regtest_mint.py \
  --out /tmp/groth16-mint-offline
```

For real block acceptance, use a dedicated BSV Node regtest with txindex enabled, a local authenticated RPC endpoint and Chronicle active. Use a new output directory. The runner mines mature test coins, broadcasts the funding and accepted transactions, checks block inclusion, and requires a node rejection of each invalid spend while its inputs are still unspent.

```sh
PYTHONPATH=.:projects/groth16/reference python3 projects/groth16/reference/regtest_mint.py \
  --out /tmp/groth16-mint-live \
  --rpc-url http://127.0.0.1:18443 --cookie /path/to/regtest/.cookie
```

Each run writes the R1CS, WASM, witness files, proof JSON, raw transaction hex and a result report. The transaction checks reject the wrong owner, a valid proof for a different statement, reordered outputs with the original witness, and a missing proof. The reference relation separately rejects minting 1,025 units and increasing the split output to 385. Those two amount rules remain outside the arithmetic circuit. The merge verifies the actual split proof once through the host recursion interface for its two consumed outputs. The circuit itself does not verify that parent proof.
