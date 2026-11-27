<!-- Generated from manifest.yaml with Copier. -->

# STARK counter v0.1.0

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md) · [Versions](versions/index.json)

## Developer resources

Generate and verify a transparent STARK for a public counter, then compare it with 4thGraph's compiled Script.

[Algorithm and execution](#algorithm-and-execution) · [Reproduce the checks](#reproduce-the-checks) · [Measurements data](versions/v0.1.0/measurements.json)

| Entry point | Purpose |
| --- | --- |
| `counter-block` | Compile a block of 1,023 increments using the proof counter's typed u32 Forth word. |
| `fourthgraph-stark-counter` | Generate a proof with Winterfell or verify it against an explicitly supplied start and result. |

## Algorithm and execution

The proof commits to a 1,024-row AIR trace and uses FRI. Both endpoints are public. The two AIR constraints enforce u32 wraparound, including a wrap on the first or last step. [Verification design](docs/verification.en.md)

## Reproduce the checks

Run from the repository root with Rust 1.87 or later and Python 3.11 or later. Cargo uses the checked-in lockfile.

```sh
cargo build --release --locked --manifest-path projects/stark-counter/reference/Cargo.toml --target-dir projects/stark-counter/workspace/target
PYTHONPATH=src:. python3 projects/stark-counter/reference/replay.py --binary projects/stark-counter/workspace/target/release/fourthgraph-stark-counter --check
```

The replay verifies four proofs against the Forth and Script results and checks 16 rejection cases. The proofs in this release are verified by the host. [Fixture and proof sizes](versions/v0.1.0/measurements.json)
