# Plonky3 SHA-256 FRI proof profile

[简体中文](spec.zh-CN.md) · [Project](../README.md) · [Goldilocks profile](../../goldilocks-stark-verifier/docs/spec.en.md)

## Statement

The lock embeds three public field elements `(a, b, result)`. The AIR has two columns and 16 rows. The first row is `(a, b)`. Each transition sends `(L, R)` to `(R, L + R)` modulo the field prime. The right column of the last row equals `result`. Anyone who supplies a valid proof for the embedded statement can spend the output. The profile is a transparent, fixed-AIR demonstration with public seeds and result.

The base field is BabyBear with prime `2^31 - 2^27 + 1`. The challenge extension has basis `1, u, u², u³` and `u⁴ = 11`. Each canonical base coefficient is four unsigned little-endian bytes. The fixed profile uses a 128-point LDE, one quotient chunk, four binary FRI rounds, 64 queries sampled with replacement and a constant final polynomial. Both grinding parameters are zero. The prover uses the Plonky3 0.5.3 uni-STARK and two-adic FRI APIs with these parameters. [Pinned prover](../reference/prover/Cargo.toml) · [Source](../reference/prover/src/main.rs)

## Verification

- Merkle leaves are `SHA256(00 || row)` and internal nodes are `SHA256(01 || left || right)` with one-byte hexadecimal tags. Each commitment is a single root. Paths are ordered from leaf to root.
- The Fiat–Shamir state begins with ASCII `4thgraph/fibonacci-stark/v1/babybear`. Absorb `(4, 4, 0)` as field elements, the trace root and the three public values, then sample AIR challenge `alpha`. Absorb the quotient root, sample `zeta`, absorb the opened values, and sample PCS challenge `rho`. Absorb each FRI root in turn and sample its fold challenge. Absorb the final constant and four base field ones for the binary schedule before sampling query indices.
- Each squeeze computes `SHA256(02 || pending)` and replaces `pending` with that digest. An extension challenge uses one squeeze per coefficient and reduces the unsigned little-endian digest modulo the field prime. A query uses the low seven bits of the first digest byte.
- Script checks the five AIR constraints in Plonky3 order using Horner folding with `alpha`. It checks the quotient identity at `zeta` after clearing boundary denominators and verifies `zeta^16 - 1 != 0`. The trace openings are at `zeta` and `omega * zeta`, where `omega` generates the 16-point subgroup. The quotient opening is at `zeta` and its basis coefficients recompose the extension value.
- For each sampled index, Script authenticates both PCS rows at bit-reversed coset point `x`. It combines the opening differences in increasing powers of `rho` and checks the supplied reciprocal by multiplying it by `(zeta - x) * (omega * zeta - x)` and comparing to one. The resulting DEEP evaluation starts FRI. Script authenticates each ordered pair at its round root, folds `(v + s)/2 + beta * (v - s)/(2 * t)`, where `t` is the subgroup point for the current value `v` and `s` is its sibling, then squares the point for the next round. The last fold must equal the final constant.

[Script lowering](../../../src/fourthgraph/verification/stark/script.py) · [Transcript and codec](../../../src/fourthgraph/verification/stark/proof.py) · [Forth fragments](../../../src/fourthgraph/stdlib/stark-sha256.fth)

## Packet

The native export has a fixed layout for this Plonky3 configuration. All extension elements serialize in basis order. The Script witness pushes a single byte packet. It has the same layout with one checked reciprocal inserted before each query.

| Order | Contents |
| --- | --- |
| Header | Trace and quotient roots, four FRI roots, two local and two next trace openings, four quotient openings, one final constant |
| Each PCS query | Two base trace coefficients and seven sibling digests, four base quotient coefficients and seven sibling digests |
| Each FRI query | For each round, one extension-field sibling and a path of six, five, four or three digests in round order |

The selected native proof, lock and unlock are 71,504 B, 292,315 B and 72,533 B respectively. The 64 extension reciprocals add 1,024 B, and the Script push header adds 5 B. The build and replay commands are available from the [project overview](../README.md). [Replay receipt](../versions/v0.2.0/replay.json)

## Generate and compile Forth

From the repository root, use the Python toolchain to generate the complete verifier and compile it separately.

```sh
project=projects/plonky3-stark-verifier
out="$project/workspace/forth"
PYTHONPATH=src:. python "$project/reference/verify.py" generate --output "$out"
PYTHONPATH=src:. python -m fourthgraph.workflow.protocol script-build \
  "$out/verifier.fth" --entry stark-lock --output "$out/lock.bin"
```

Pass three public field elements with `generate --public SEED_A SEED_B RESULT` to emit a different fixed statement. Run `compare` for the four lowering plans and `build --plan baseline --output "$project/workspace/baseline"` to reproduce the v0.1.0 lock bytes. Use a separate output directory when the statement, plan, or proof changes. Commands verify that any existing artifacts and reports match before reusing a directory. When the directory contains only a binary lock or witness, run `generate` in a fresh directory. [Generated verifier](../versions/v0.2.0/verifier.fth) · [Optimization rounds](../../../docs/optimization-paths.md#stark-verifier-iteration)

## Regenerate an upstream proof

From the repository root with Rust 1.95 and Python 3.11 or newer, generate and natively verify the proof, then verify it using the emitted Script in the local evaluator. The native tool prints the three public values in order. Pass the expected public values from your application to the Script verifier.

```sh
project=projects/plonky3-stark-verifier
out="$project/workspace/native"
mkdir -p "$out"
CARGO_TARGET_DIR="$project/workspace/target" cargo run --locked \
  --manifest-path "$project/reference/prover/Cargo.toml" -- babybear 0 1 "$out/demo.proof"
PYTHONPATH=src:. python "$project/reference/verify.py" verify \
  --public 0 1 987 --proof "$out/demo.proof" --output "$out"
```

The native test flag `--test-shifted-air` generates a proof with the same public statement using a trace whose right column is shifted by one. The native standard verifier reaches the AIR quotient check and rejects it. The funded replay also checks rejection of this witness, swapped statements, malformed packets and corrupted openings. [Fixture statements](../versions/v0.1.0/statements.json) · [Funded replay receipt](../versions/v0.2.0/replay.json)
