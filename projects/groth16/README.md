# Groth16 on BSV

This experiment generates BLS12-381 Groth16 verification scripts and a wallet descriptor for each fixed verification key and public statement. The script validates affine proof points, prime-order subgroup membership, auxiliary field arithmetic, and the Groth16 pairing equation. The public inputs are fixed when the output is created, allowing the public-input multiscalar multiplication and two pairings to be prepared off chain.

- [Verifier design and optimization](docs/verifier.md)
- [Wallet recognition and acceptance](docs/wallet.md)
- [Reproducible two-input vector](template/vector.json)

| Experiment | Locking script | Unlocking script | Combined | chain-gang median |
|---|---:|---:|---:|---:|
| `groth16/alpha` · affine baseline | 263,591 B | 20,960 B | 284,551 B | 21.86 ms |
| `groth16/beta` · projective G1, shared constants | 247,941 B | 7,640 B | **255,581 B** | 23.38 ms |
| `groth16/gamma` · projective G1 and G2, shared constants | 261,602 B | **980 B** | 262,582 B | 25.57 ms |

This branch defaults to alpha. Beta minimizes combined script bytes on this vector. Gamma minimizes the bytes handed over when the output is already funded. Alpha reproduces the original fused, joined-line scripts. The vector generator also includes the two earlier Miller-loop benchmarks. Timings are the median of 20 warmed complete-input checks per profile on the development Mac with chain-gang `d442b55`.

The generated output expresses a proof predicate. Use the research setup and fixture only for testing. A payment template needs an explicit owner or destination constraint, and a token protocol needs to bind its public statement to the actual inputs and outputs.

## Run the checks

From the repository root with Python 3.12 or later:

```sh
export PYTHONPATH=".:projects/groth16/reference"
python3 -m unittest -v test_groth16.ReferenceTests
python3 projects/groth16/reference/vector.py --experiment alpha --scripts-out /tmp/groth16-vector
```

For the complete-input regression matrix and a median timing per profile, install the chain-gang build in [shared requirements](../../shared/requirements-chronicle.txt).

```sh
python3 -m unittest -v test_groth16.ChainGangTests
python3 projects/groth16/reference/vector.py --benchmark 20
```

The node test uses the repository's isolated Apple Container harness and its pinned BSV Node image. Use an unused local port.

```sh
bash shared/verify_node_apple.sh groth16 18464 test_groth16.NodeTests
```

The development evaluator passed the 35-case matrix. Chain-gang passed all 105 complete-input checks across pre-Chronicle and post-Chronicle output and spend contexts. BSV Node 1.2.3 remains unverified because Apple Container was unavailable under the workspace permissions.
