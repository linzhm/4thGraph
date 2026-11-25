# Proving and Script integration

The initial integration uses Circom 2.2.3 with the BLS12-381 scalar field, snarkjs for the Groth16 setup, proving and export, and the project verifier for Script generation and execution. The artifact boundary consists of a verification key, proof and ordered public signals. The adapter accepts affine snarkjs JSON or the compressed BLS12-381 export tested in the checked-in external vector. It validates fields, curve identifiers, point encodings and subgroup membership.

Run the arithmetic smoke circuit with Circom, Node.js, snarkjs and OpenSSL installed:

```sh
bash projects/groth16/reference/prove_smoke.sh
```

The script generates a test-only setup and witness, proves and checks the statement in snarkjs, then exports a wallet descriptor and a matched pair of Script hex files. Keep production ceremony material and private witnesses out of source control. The Script export in this smoke path fixes the supplied public signals.

For the cross-tool execution check, use the project's chain-gang requirements and run:

```sh
PYTHONPATH=.:projects/groth16/reference python3 -m unittest -v test_snarkjs
```

The external vector is a proof produced with Circom and a Cardano-compatible snarkjs build. The project imports and accepts it in a full BSV input in chain-gang, and rejects the same proof when the public signals are reordered. Circom compiled the local smoke circuit and its WASM generated the witness. Fresh snarkjs proof generation was blocked in the development environment because snarkjs was absent and the package registry could not be resolved. [External vector source](https://github.com/cardano-scaling/snarkjs-circom-aiken/tree/main/test-vectors/groth16) · [Circom proving guide](https://docs.circom.io/getting-started/proving-circuits/)

## Python prover with Metal transforms

[`python_prover.py`](../reference/python_prover.py) accepts a plain BLS12-381 Groth16 snarkjs `.zkey` and its matching `.wtns`. Use a proving key from the intended circuit and ceremony. Python reads the artifacts, builds the quotient and assembles a freshly randomized proof. `wgpu-py` executes forward and inverse NTTs on Metal. The `py-arkworks-bls12381` wheel performs curve operations and verifies the pairing equation before export. The proof command runs without Go, Node.js, Chrome or a Rust toolchain. Circuit compilation, ceremony and witness generation happen before this command.

From the repository root, with Python 3.14 on Apple Silicon and an existing `ZKEY` and `WTNS`:

```sh
shader=$(mktemp)
curl -fsSL https://raw.githubusercontent.com/Consensys/gnark/v0.16.5/backend/accelerated/webgpu/shaders/curves/bls12_381/fr_ntt.wgsl -o "$shader"
WGPU_BACKEND_TYPE=Metal uv run --no-project --python 3.14 \
  --with 'wgpu==0.33.0' --with 'py-arkworks-bls12381==0.5.0' \
  python projects/groth16/reference/python_prover.py \
  --ntt-shader "$shader" --zkey "$ZKEY" --wtns "$WTNS" --out proof-artifact.json
```

The command checks the [gnark WGSL](https://github.com/Consensys/gnark/blob/v0.16.5/backend/accelerated/webgpu/shaders/curves/bls12_381/fr_ntt.wgsl) fingerprint. The output contains `key`, `proof` and ordered `public_signals` for [`snarkjs_adapter.load_artifacts`](../reference/snarkjs_adapter.py). The proof points use compressed hexadecimal encoding. To verify the same proof with the snarkjs CLI, encode those points in its affine-coordinate JSON format.

BSV SPV Token uses this same prover. Its witness adapter either evaluates the compiled Circom WASM in Python with Wasmtime or solves the lifecycle circuit's offline assignment artifact. Both adapters write a standard `.wtns`. The BSV spending script uses the verification key encoded in the corresponding `.zkey`. See the [BSV SPV Token proving workflow](../../spv-token/docs/python-proving.md).

## Recursive MIMO integration

The transaction verifier uses the same key and proof objects. Its Script derives the two public signals from the payment. The prover must produce them in the same order. For a recursive prover, the outer proof verifies the inner recursive proof, authenticates the same ordered payment commitment, and targets this BLS12-381 Groth16 interface. Choosing a recursion backend and implementing that wrapper remain separate engineering steps.

The transfer relation should sum all inputs and outputs of the asset and verify each distinct parent proof once, with a separate check for each consumed outpoint. For the initial public-amount token format this removes protocol-level one-to-one assignments. Amount and owner commitments would additionally require range and conservation checks on private openings.

The executable reference relation in `recursive_transfer.py` checks a one-time issuance anchor and an initial supply, authenticates each actual token prevout, verifies each distinct prior transfer through a pinned proof callback, and reuses the existing transfer conservation checks. Its test oracle exercises one verification for two outputs of the same prior transaction. It rejects a missing proof, a proof for changed parent outputs, a duplicate input and inflation. This reference relation defines constraints for the future recursive circuit. The callback in the tests stands in for in-circuit cryptographic proof verification.

## Configurable MIMO fragment

The Circom template `MimoRelation(maxInputs, maxOutputs)` compiles independently selected input and output capacities. A single capacity accepts smaller transfers through zero padding. Actual output order is preserved. The consumed token outpoint projection is sorted by its 36 wire bytes, split into two 144-bit limbs, and constrained to increase strictly across active slots. This checks uniqueness with one adjacent comparison per slot. It does not prescribe the order of the actual BSV transaction inputs. The complete circuit must authenticate the projection against the actual input positions.

Each amount is range-constrained to uint64 and the nonzero total is bounded by uint64. The fragment exposes input and output totals for isolated tests. The integrated circuit must couple the verified slot lists to the two digest limbs supplied by the existing Script and verify all required predecessor proofs. The totals in this fragment are test inputs to the arithmetic circuit.

Circom and Node.js tests compile and generate witnesses for capacities 16/16, 32/32, 64/64, 256/256 and 16/32. They reject a duplicate outpoint, unordered input, oversize amount and inflation. The reference recursive relation also exercises a 16-to-32 transfer with two prior proofs for sixteen distinct input outpoints. The 16/16, 32/32 and 64/64 builds have 11,411, 23,059 and 46,355 R1CS constraints respectively. These counts cover the arithmetic and uniqueness fragment.

```sh
PYTHONPATH=.:projects/groth16/reference python3 -m unittest -v test_mimo_circuit test_recursive_transfer
```

The 16/16 MIMO regression also uses the compiled R1CS and its actual WASM witness to generate a Groth16 test proof for a 1,024-unit input and outputs of 640 and 384 units. The fixed-statement Script verifier accepts this proof for the public totals (1024, 1024). Supplying 385 instead of 384 directly to the witness generator fails the conservation constraints. This uses the public test-only setup. The proof covers the MIMO arithmetic relation over the supplied projection. Transaction digest binding and in-circuit ancestry verification are still required before connecting this proof to the dynamic transaction verifier.

The compact transaction commitment is also executable in Circom. The fixture derives the two public limbs from a 192-byte ForkID preimage and its 36-byte issuance outpoint, generates a proof from its compiled witness, and verifies it in the host verifier. Altering a hashOutputs byte while retaining the old public limbs fails witness generation. The gadget does not yet constrain serialized outputs or their token interpretation to hashOutputs. It compiles to 224,158 R1CS constraints in the isolated profile.
