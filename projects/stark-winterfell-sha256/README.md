<!-- Generated from manifest.yaml with Copier. -->

# Winterfell SHA-256 STARK v0.2.0

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md) · [Versions](versions/index.json)

## Developer resources

Build and verify a transparent STARK with SHA-256 commitments and a SHA-256 Fiat–Shamir transcript. Compile and replay the hash layer and a real Winterfell trace opening on BSV.

[Algorithm and execution](#algorithm-and-execution) · [Reproduce the checks](#reproduce-the-checks)

| Entry point | Purpose |
| --- | --- |
| `fourthgraph-stark-sha256` | Prove and verify the public counter using the pinned Winterfell SHA-256 profile. |
| `hashes.fth` | Compile the tagged SHA-256 operations, including trace rows, ordered Merkle parents and transcript counters. |
| `verify-trace-opening` | Compile the depth-13 trace-opening lock with the expected root fixed at build time. |

## Algorithm and execution

Both proof profiles use the same counter AIR, public inputs and FRI parameters. This project's host verifier fixes SHA-256 at build time for both Winterfell Merkle commitments and its random coin. [Hash encoding and integration](docs/verification.en.md)

## Reproduce the checks

Run from the repository root with Rust 1.87 or later and Python 3.11 or later. Cargo uses the checked-in lockfile.

```sh
cargo build --release --locked --manifest-path projects/stark-winterfell-sha256/reference/Cargo.toml --target-dir projects/stark-winterfell-sha256/workspace/target
cargo test --release --locked --manifest-path projects/stark-winterfell-sha256/reference/Cargo.toml --target-dir projects/stark-winterfell-sha256/workspace/target
PYTHONPATH=src:. python3 projects/stark-counter/reference/replay.py \
  --binary projects/stark-winterfell-sha256/workspace/target/release/fourthgraph-stark-sha256 \
  --measurements projects/stark-winterfell-sha256/versions/v0.1.0/measurements.json \
  --output projects/stark-winterfell-sha256/workspace/build/replay.json --check
PYTHONPATH=src:. python3 projects/stark-winterfell-sha256/reference/hash_replay.py --check
PYTHONPATH=src:. python3 projects/stark-winterfell-sha256/reference/opening_replay.py \
  --binary projects/stark-winterfell-sha256/workspace/target/release/fourthgraph-stark-sha256 --check
```

Four public proofs and 16 proof rejection cases replay against the shared counter. The Rust tests exercise both directions of cross-profile rejection. BSV Node and chain-gang independently check all five compiled hash primitives. [Proof sizes](versions/v0.1.0/measurements.json) · [Native Script evidence](versions/v0.1.0/hash-checks.json)

v0.2.0 extracts trace queries and opens them against the actual proof commitments. A 368 B lock verifies each 13-level path. Both BSV engines accept the three openings and reject 27 mutations. [Opening replay](versions/v0.2.0/opening-checks.json)

The controlled comparison reduces the opening lock from 550 B to 368 B. [Method and reproduction](docs/verification.en.md#opening-lock-comparison) · [Versioned benchmark](versions/v0.2.0/opening-comparison.json)
