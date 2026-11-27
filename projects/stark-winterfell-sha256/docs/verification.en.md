# Winterfell SHA-256 STARK verification

[简体中文](verification.zh-CN.md) · [Project](../README.md) · [Release manifest](../versions/v0.2.0/manifest.json)

## Proof profile

The host uses Winterfell 0.13.1 with a fixed SHA-256 profile for its Merkle commitments, Fiat–Shamir transcript, and FRI. The proof checks that 1,023 increments modulo 2³² take the public `current` to the public `next`. The project reuses the BLAKE3 counter's Forth source, AIR and FRI parameters so both proof profiles can be compared on the same relation. This public AIR uses no trusted setup and has no witness masking. [Shared counter AIR](../../stark-counter/docs/verification.en.md#statement-and-proof) · [SHA-256 adapter](../reference/src/hash.rs)

The two binaries fix their own verifier profile at compile time. Both directions of cross-profile verification fail, even when the two proofs use the same statement. Winterfell's proof serialization is interpreted under the selected verifier configuration.

## SHA-256 input encodings

The first byte separates the hash operations. `||` concatenates byte strings. Field elements are serialized as canonical 16-byte little-endian values in the Winterfell f128 field. `LE64` encodes an unsigned 64-bit counter. Digests have exactly 32 bytes.

| Tag | SHA-256 input | Winterfell use |
| --- | --- | --- |
| `00` | `00 \|\| bytes` | Byte-string hashing |
| `01` | `01 \|\| element_0 \|\| …` | Field sequences, including trace leaves and the initial transcript seed |
| `02` | `02 \|\| left \|\| right` | Ordered Merkle parents and digest-pair reseeding |
| `03` | `03 \|\| digest_0 \|\| …` | A list of digests in protocol order |
| `04` | `04 \|\| seed \|\| LE64(counter)` | Random-coin sampling and grinding |

The Forth words use native `OP_SHA256`. The trace-row word accepts a 32-byte encoding of two field elements. The digest-list word takes an ordered, already parsed list. The parent and seed-counter words check operand widths. The later complete verifier must parse and range-check field elements before passing their encodings to these words. [Forth words](../hashes.fth) · [Shared vectors](../versions/v0.1.0/hash-vectors.txt)

## Replay

Run the build and verify commands in the project README. The four fixed public statements cover an ordinary input, the maximum result without wraparound, and wraparound on the first or last increment. Verification checks pinned sizes and hashes and rejects wrong statements, substitutions and malformed proof bytes. [Proof replay](../versions/v0.1.0/measurements.json)

To generate and verify the last-step wraparound proof individually.

```sh
binary=projects/stark-winterfell-sha256/workspace/target/release/fourthgraph-stark-sha256
proof=projects/stark-winterfell-sha256/workspace/wrap.proof
"$binary" prove 4294966273 "$proof"
"$binary" verify 4294966273 0 "$proof"
```

| Case | SHA-256 proof |
| --- | ---: |
| Ordinary | 34,924 B |
| Ends at maximum | 35,885 B |
| Wraps at last step | 35,977 B |
| Wraps at first step | 36,719 B |

The independent Script replay verifies five digest vectors and twelve malformed or changed inputs with synthetic previous outputs. All native replay and comparison commands require the chain-gang commit in `tools/requirements-chronicle.txt`. Run from the repository root in that environment. [Dependency pin](../../../tools/requirements-chronicle.txt) · [Native replay evidence](../versions/v0.1.0/hash-checks.json)

```sh
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  python3 projects/stark-winterfell-sha256/reference/hash_replay.py --native --check
```

## Trace openings on BSV

After verifying the full proof on the host, `trace-opening CURRENT NEXT QUERY PROOF` records the positions drawn by Winterfell's verifier. `QUERY` selects an ordinal in the sorted, deduplicated positions. The command expands the main trace's original batched opening and verifies the resulting path against the proof's committed trace root.

`opening.fth` hashes the two-element row and calls `merkle-sha256-root #13 02`. The compiler fixes the depth and tag, checks the digest, packet and position once, and consumes the unread suffix as it folds the ordered siblings. It skips splitting and dividing the index at the last level. The application lock fixes the expected root with `--bind-bytes`.

The 8,192-leaf trace commitment uses 13 siblings or 416 raw path bytes. The three measured opening locks are 368 B. Their unlocking scripts are 454–455 B and the development evaluator measures a 483–484 B peak across both stacks. BSV Node and chain-gang accept the three openings and reject 27 mutations using synthetic previous outputs, including altered rows, reordered siblings, bad lengths, and wrong or noncanonical positions. [Opening lock](../opening.fth) · [Compiler syntax](../../../docs/language/syntax.en.md#33-bounded-sha-256-merkle-paths) · [Dual-engine measurements](../versions/v0.2.0/opening-checks.json)

```sh
binary=projects/stark-winterfell-sha256/workspace/target/release/fourthgraph-stark-sha256
"$binary" trace-opening 4294966273 0 0 projects/stark-winterfell-sha256/workspace/wrap.proof

PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  python3 projects/stark-winterfell-sha256/reference/opening_replay.py --binary "$binary" --native --check
```

## Opening lock comparison

The baseline uses the checked v0.1.0 parent hash within the same depth-13 opening lock. Replacing only that block at each level reduces it from 19 B to 5 B. Both variants use the same proof, row, path, index and root. Each variant passed three valid openings and rejected 27 mutations on both native engines. [Benchmark driver](../reference/compare_openings.py) · [Versioned results](../versions/v0.2.0/opening-comparison.json)

| Metric | Checked parent baseline | Specialized parent |
| --- | ---: | ---: |
| Lock | 550 B | 368 B |
| Serialized lock and unlocking fields | 1,010–1,011 B | 828–829 B |
| Unlocking script | 454–455 B | 454–455 B |
| Peak payload across both stacks in the development evaluator | 483–484 B | 483–484 B |

The 182 B reduction saves 33.1% of the lock bytes and 18.0% of the two serialized script fields, including their CompactSize prefixes. Each opening has 201 paired samples with alternating execution order. The median paired saving was 4.1–6.8 µs for chain-gang, including parsing, and 21.8–42.4 µs for BSV Node's `verifyscript` RPC on this run. The timing uses synthetic previous outputs. Proof generation and full STARK verification stay on the host.

After building the release binary, run from the repository root with the same native dependencies as the opening replay.

```sh
binary=projects/stark-winterfell-sha256/workspace/target/release/fourthgraph-stark-sha256
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  python3 projects/stark-winterfell-sha256/reference/compare_openings.py --binary "$binary"
```

The replay writes fresh measurements to `projects/stark-winterfell-sha256/workspace/build/opening-comparison.json`.

## Transaction verification

The opening lock checks membership at the supplied position under the expected root. A complete Script verifier must derive the position from the on-chain transcript and verify AIR and FRI. For a transaction-bound application, the secp256k1 preimage assertion then binds the public state and outputs to the actual spend. [Transaction binding in PELS locks](../../../docs/pels-locks.md)
