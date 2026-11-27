# STARK counter verification

[简体中文](verification.zh-CN.md) · [Project](../README.md) · [Release manifest](../versions/v0.1.0/manifest.json)

## Statement and proof

The verifier takes two public `u32` values, `[current, next]`, and checks that 1,023 increments modulo 2³² take `current` to `next`. The Forth entry imports the same `advance` word used by Proof counter. The Rust AIR implements that word's semantics for this fixed trace shape. [Forth entry](../counter.fth) · [Shared counter word](../../proof-counter/counter.fth) · [AIR](../reference/src/counter.rs)

Winterfell 0.13.1 produces and verifies the STARK using its 128-bit prime field, BLAKE3-256 Merkle commitments and transcript, and FRI. The verifier fixes the two-column, 1,024-row trace shape and the exact proof options, including 40 queries, blowup 8, 16 grinding bits and FRI folding factor 8. The AIR and proof parameters are public and require no trusted setup. This public fixture has no trace masking. [Pinned dependency](../reference/Cargo.lock) · [Winterfell](https://docs.rs/winterfell/0.13.1/winterfell/)

Let `x` be the current state, `x'` the next state, `M = 2^32`, `d = x' - x - 1`, and `h = x - (M - 1)`. Each row carries `x` and an inverse hint `v`. The transition evaluates two constraints over the proof field.

```text
h * d = 0
M * (h * v - 1) = d
```

For `h ≠ 0`, these enforce `d = 0` and `h * v = 1`. For `h = 0`, they enforce `d = -M`, which produces zero on the next row. The verifier parses the public values as `u32` and constrains the first and final rows. The initial range and the transition rule therefore keep every state within `u32`.

## Build and replay

Run the build and verification commands in the release manifest from the repository root. The replay compiles the Forth word, evaluates the emitted arithmetic Script, and verifies each proof against the same statement. It checks the recorded proof and Script digests. [Build and verify commands](../versions/v0.1.0/manifest.json)

After building, generate and verify the wrap-at-end proof directly.

```sh
binary=projects/stark-counter/workspace/target/release/fourthgraph-stark-counter
proof=projects/stark-counter/workspace/wrap.proof
"$binary" prove 4294966273 "$proof"
"$binary" verify 4294966273 0 "$proof"
```

| Public input | Expected result | Serialized proof |
| ---: | ---: | ---: |
| 19 | 1,042 | 36,620 B |
| 4,294,966,272 | 4,294,967,295 | 34,806 B |
| 4,294,966,273 | 0 | 35,307 B |
| 4,294,967,295 | 1,022 | 36,232 B |

All four cases agree across Forth, Script and STARK verification. Rejection controls cover wrong endpoints, a proof reused for another valid counter statement, modified, truncated and extended proof bytes, and an out-of-range public input. The compiled arithmetic entry is 8,198 B. These sizes exclude the transaction assertion and transaction framing. The proof sizes describe the host format. [Replay evidence](../versions/v0.1.0/measurements.json)

## BSV integration

The reference verifier runs on the host. The Script in the differential run executes the counter relation directly in the development evaluator. Transaction enforcement requires an on-chain STARK predicate and the existing transaction assertion to run in the same spend.

1. The SHA-256 project fixes the hash profile and checks real trace openings via the compiler. Continue with on-chain transcript challenge derivation, AIR evaluations, FRI folds and degree bounds. [Winterfell SHA-256 STARK](../../stark-winterfell-sha256/docs/verification.en.md)
2. Use the same public stage interface as a direct Script backend. The lock authenticates the actual prevout with the existing secp256k1 BIP143 ALL preimage mechanism, checks the public `current` against the consumed state and `next` against the ordered successors, then checks the proof against that statement and the authenticated preimage binding. Required role signatures remain part of the lock.
3. Fund the lock and replay both correct and incorrect spends under the target BSV Node and chain-gang rules. Require rejection for proof substitution across outpoints, changed successor amount, changed output order, and bad transcript or FRI data. Compare serialized path bytes, stack peak, and verification cost before exposing an on-chain STARK candidate to CPN planning.

The BLAKE3 and SHA-256 profiles have separate proof fixtures. A zero-knowledge policy also needs a masking construction and a review of what the public statement discloses. [PELS transaction binding](../../../docs/pels-locks.md) · [SHA-256 trace openings](../../stark-winterfell-sha256/docs/verification.en.md#trace-openings-on-bsv)
