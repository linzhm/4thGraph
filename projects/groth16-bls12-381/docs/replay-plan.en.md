# Groth16 v0.9.0 replay baseline

[简体中文](replay-plan.zh-CN.md) · [Verifier guide](verification.en.md)

The baseline uses the v0.9.0 selected high-level Forth source with the compact `affine-inline` layout. It pins call-site Fp2 selection, the accumulator–Frobenius-first residue product, and signed radix-4 MSM with doubling-slope tables. The plan records the exact lock, build artifact and both witnesses for the five bounded public inputs in this fixture. [Replay plan](../versions/v0.9.0/replay-plan.json) · [Selection evidence](../versions/v0.9.0/measurements.json)

| Script era | Lock | Witness per case | Serialized lock and witness |
| --- | ---: | ---: | ---: |
| Genesis | 253,510 B | 9,378 B | 262,896 B |
| Chronicle | 252,605 B | 9,378 B | 261,991 B |

The serialized total includes CompactSize. The funded report separately records deployment and spend bytes, including framing and the funding signature.

Build from the repository root with Python 3.11 or later. The check applies the recorded plan directly and checks the hashes before writing artifacts.

```sh
PYTHONPATH=src:. python3 projects/groth16-bls12-381/reference/replay_plan.py
PYTHONPATH=src:. python3 projects/groth16-bls12-381/reference/replay_plan.py --script-era chronicle
```

Funded replay uses the existing BSV Node and chain-gang runner with the same plan. Both proofs must spend, and swapped statements and G1 points outside the subgroup must fail. The wrapper checks that the funded transactions contain the pinned lock and witnesses. Install the replay dependencies from the verifier guide and run each command on its own isolated regtest. [Dependencies](../README.md#reproduce-the-checks)

```sh
REGTEST_CHRONICLE_HEIGHT=1000 bash tools/verify_node.sh --profile raised -- \
  python3 projects/groth16-bls12-381/reference/replay_plan.py --funded

REGTEST_CHRONICLE_HEIGHT=2 bash tools/verify_node.sh --profile raised -- \
  python3 projects/groth16-bls12-381/reference/replay_plan.py --script-era chronicle --funded
```

The artifacts are written under `projects/groth16-bls12-381/workspace/build/pinned-v0.9.0/`, with a directory for each Script era. Funded runs also write `replay.json` with the plan digest.
