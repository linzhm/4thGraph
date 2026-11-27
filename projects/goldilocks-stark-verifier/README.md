<!-- Generated from manifest.yaml with Copier. -->

# Goldilocks + SHA-256 FRI STARK verifier v0.2.0

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md) · [Versions](versions/index.json)

## Developer resources

Verify a 16-row Fibonacci AIR over Goldilocks and its quadratic extension using a BSV Script lock.

[Protocol](docs/spec.en.md) · [Algorithm and execution](#algorithm-and-execution) · [Reproduce the checks](#reproduce-the-checks) · [Measurements data](versions/v0.2.0/measurements.json)

| Entry point | Purpose |
| --- | --- |
| `stark-lock` | Compile the generated Forth source to a BSV Script lock. [Generated verifier](versions/v0.2.0/verifier.fth) |
| `reference/verify.py` | Generate Forth, build a lock and witness, compare lowering plans, or replay recorded cases. |

## Algorithm and execution

The verifier decodes unsigned 64-bit coefficients with modulus `2^64 - 2^32 + 1`. The lock derives challenges, authenticates all Merkle openings, and checks 64 binary FRI folding paths and the AIR quotient. [Profile and packet layout](docs/spec.en.md)

The Goldilocks project uses the common Plonky3 0.5.3 prover and Script backend. Its quadratic extension, canonical encoding and transcript domain are specific to Goldilocks. [Native prover](../plonky3-stark-verifier/reference/prover/src/main.rs)

## Reproduce the checks

From the repository root, use Python 3.11 or later. The regtest command requires the pinned chain-gang binding and `ecdsa`.

`python -m pip install ecdsa -r tools/requirements-chronicle.txt`

```sh
PYTHONPATH=src:. python projects/goldilocks-stark-verifier/reference/verify.py generate --plan affine
bash tools/verify_node.sh --profile long-script -- python projects/goldilocks-stark-verifier/reference/verify.py replay --plan affine
```

Run `PYTHONPATH=src:. python projects/goldilocks-stark-verifier/reference/verify.py check` for the local Script fixtures. Funded replay mined the valid spend and rejected 12 controls, including a different AIR with the same public statement. [Regtest receipt](versions/v0.2.0/replay.json)

## Script sizes

For the public statement `(0, 1, 987)`, the lock is **137,656 B** and the unlock is **73,013 B**. The exported proof alone is 71,984 B. [Replay measurements](versions/v0.2.0/replay.json) · [Lock](versions/v0.2.0/lock.bin) · [Unlock](versions/v0.1.0/unlock.bin)

## Developer and wallet integration

`generate` writes a complete `verifier.fth` from the public inputs in Python. Compile it independently with `4thgraph script-build`. Use `compare` to replay all four compiler plans with the same witness. [Forth build and compiler options](docs/spec.en.md#generate-and-compile-forth)
