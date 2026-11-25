# BLS12-381 Groth16 toolchain

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
