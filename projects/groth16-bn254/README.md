<!-- Generated from manifest.yaml with Copier. -->

# BN254 Groth16 verifier v0.7.0

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md) · [Versions](versions/index.json)

## Developer resources

Compile an owner-authorized BN254 Groth16 verifier from typed Forth. On Chronicle regtest, deployment plus one spend fits under 472,000 B for both fixed-statement fixtures.

[Algorithm and execution](#algorithm-and-execution) · [Reproduce the checks](#reproduce-the-checks) · [Complete transactions and stack measurements](#complete-transactions-and-stack-measurements) · [Measurements data](versions/v0.7.0/measurements.json)

| Entry point | Purpose |
| --- | --- |
| `verify-bn254-proof` | Compile the complete fixed-statement verifier from the typed Forth modules. |

## Algorithm and execution

The Forth entry assembles the point checks, Jacobian G2 subgroup check, Miller loop and residue assertion. The compiler precomputes the MSM for the five fixed public inputs and combines it with fixed pairing terms. A different public statement requires recompilation. [Forth entry](forth/optimized-verifier.fth) · [Verification guide](docs/verification.en.md)

The v0.7.0 entry enables last-use scheduling for Jacobian operands, Script stack compaction and in-place rebinding of Fp12 results. The backend tracks the new names at the existing stack positions and emits no moves for the rename. Both locks shrink by 6,384 B compared with v0.6.0. [Compiler optimization](../../src/fourthgraph/verification/runar/forth_fp12_rename.patch)

## Reproduce the checks

Run from the repository root with Python 3.11 or later, Go 1.26.6, and the pinned Rúnar checkout at `workspace/runar`. Funded replay also needs the Chronicle chain-gang binding and BSV Node.

```sh
git clone https://github.com/icellan/runar.git workspace/runar
git -C workspace/runar checkout --detach dbcc4269f8e0895c4738cf86948b05b7d62a2010
python3 -m pip install ecdsa -r tools/requirements-chronicle.txt
```

```sh
bash projects/groth16-bn254/reference/build.sh workspace/runar \
  projects/groth16-bn254/forth/optimized-verifier.fth
for fixture_case in wrap other; do
  REGTEST_CHRONICLE_HEIGHT=2 bash tools/verify_node.sh --profile long-script -- \
    python3 -m fourthgraph.replay.groth16_bn254 --runar workspace/runar \
    --verifier-source projects/groth16-bn254/forth/optimized-verifier.fth \
    --fixture projects/groth16-bn254/versions/v0.1.0/fixture.json \
    --fixture-case "$fixture_case" \
    --output "projects/groth16-bn254/workspace/build/replay-v0.7.0-${fixture_case}.json" || exit $?
done
```

The build writes the lock and proof witness prefix to the project’s `workspace/build/`. The replay writes one JSON report per fixture.

## Complete transactions and stack measurements

| Fixture | Locking script | Witness prefix | Deployment transaction | Spend transaction | Total | Stack payload peak |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `wrap` | 464,397 B | 6,765 B | 464,534 B | 6,934 B | **471,468 B** | 8,872 B |
| `other` | 464,395 B | 6,761 B | 464,531 B | 6,930 B | **471,461 B** | 8,870 B |

Both valid spends mined. BSV Node and chain-gang rejected all ten negative cases. The witness prefix hashes match v0.6.0. [Funded replay measurements](versions/v0.7.0/measurements.json)

The v0.6.0 size profile assigns 83.1% of the lock to the Miller loop and 13.8% to the G2 subgroup check. The verification guide shows the remaining savings required for the 450,000 B and 400,000 B targets. [Optimization headroom](docs/verification.en.md#optimization-headroom) · [Phase measurements](versions/v0.6.0/optimization-profile.json)
