# Goldilocks SHA-256 FRI proof profile

[简体中文](spec.zh-CN.md) · [Project](../README.md) · [Shared protocol](../../plonky3-stark-verifier/docs/spec.en.md)

The BSV output locks to the public statement `(a, b, result)`. It checks the 16-row Fibonacci AIR and the two-adic FRI proof using the same four binary folds, 128-point LDE and 64 queries as the BabyBear profile. Anyone who supplies a valid proof for that public statement can spend the output. This is a transparent, fixed-AIR demonstration with public seeds and result. [Shared AIR, transcript and FRI checks](../../plonky3-stark-verifier/docs/spec.en.md#verification)

## Goldilocks parameters

| Component | Goldilocks value |
| --- | --- |
| Prime | `2^64 - 2^32 + 1` |
| Base field generator | `7` |
| Extension | Basis `1, u` with `u² = 7` |
| Encoding | Eight unsigned little-endian bytes per canonical base coefficient |
| Initial transcript | ASCII `4thgraph/fibonacci-stark/v1/goldilocks` |
| Quotient | One chunk with two claimed extension openings and two base coefficients per queried row |

The lock checks that every supplied coefficient is below the prime before accepting. Both Merkle leaves and the transcript use canonical bytes, including values whose high bit is set. The wrapping fixture starts from `p - 2` and `p - 1`. The packet follows the shared layout with the Goldilocks coefficient widths. For `(0, 1, 987)`, the selected native proof, lock and unlock are 71,984 B, 137,656 B and 73,013 B respectively. [Packet layout](../../plonky3-stark-verifier/docs/spec.en.md#packet) · [Replay receipt](../versions/v0.2.0/replay.json)

## Generate and compile Forth

From the repository root, use the Python toolchain to generate the complete verifier and compile it separately.

```sh
project=projects/goldilocks-stark-verifier
out="$project/workspace/forth"
PYTHONPATH=src:. python "$project/reference/verify.py" generate --output "$out"
PYTHONPATH=src:. python -m fourthgraph.workflow.protocol script-build \
  "$out/verifier.fth" --entry stark-lock --output "$out/lock.bin"
```

Pass three public field elements with `generate --public SEED_A SEED_B RESULT` to emit a different fixed statement. Run `compare` for the four lowering plans and `build --plan baseline --output "$project/workspace/baseline"` to reproduce the v0.1.0 lock bytes. Use a separate output directory when the statement, plan, or proof changes. Commands verify that any existing artifacts and reports match before reusing a directory. When the directory contains only a binary lock or witness, run `generate` in a fresh directory. [Generated verifier](../versions/v0.2.0/verifier.fth) · [Optimization rounds](../../../docs/optimization-paths.md#stark-verifier-iteration)

## Regenerate an upstream proof

From the repository root with Rust 1.95 and Python 3.11 or newer, run the shared native prover and verify the result with the Goldilocks Script. The prover invokes Plonky3 0.5.3 native verification before exporting the proof.

```sh
project=projects/goldilocks-stark-verifier
out="$project/workspace/native"
mkdir -p "$out"
CARGO_TARGET_DIR="$project/workspace/target" cargo run --locked \
  --manifest-path projects/plonky3-stark-verifier/reference/prover/Cargo.toml \
  -- goldilocks 0 1 "$out/demo.proof"
PYTHONPATH=src:. python "$project/reference/verify.py" verify \
  --public 0 1 987 --proof "$out/demo.proof" --output "$out"
```

The project overview gives the fixture build and funded regtest commands. The recorded rejection cases include a shifted AIR with the same public values, a valid proof for a different statement, corrupted Merkle openings and malformed witness packets. [Project overview](../README.md) · [Native prover source](../../plonky3-stark-verifier/reference/prover/src/main.rs) · [Fixture statements](../versions/v0.1.0/statements.json)
