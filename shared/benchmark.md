# Signed transaction benchmark

[简体中文](benchmark.zh-CN.md)

The benchmark runs each project's normal signing entry point with synthetic,
deterministic test keys. It replays complete signed transactions through the
project's pinned chain-gang build and BSV Node 1.2.3. The node uses a temporary,
peerless regtest with explicit prevouts and flags. The JSON records each
engine's verdict, transaction framing, txid and lock fingerprints. At 2×2 the
runner also checks that changing locktime after signing invalidates the
authorization.

## Run

Use Python 3.12. Create each project environment at
`$bench_env/<project>/bin/python`. Install the project's reference requirements
and `ecdsa==0.19.1`. WOTS+, ML-DSA-44 and the native baseline use
[the shared Chronicle pin](requirements-chronicle.txt) for this benchmark.
The native project's offline example uses the same pin.
ML-DSA-44 requires OpenSSL 3.5 or later. Configure `ML_DSA_OPENSSL` if needed.
For SM2, build the Rust signer and set its executable path in
`SM2_SIGNED_DATA_SIGNER`. See the
[SM2 reference guide](../projects/p2pkh-sm2/reference/README.md).

From the repository root, run:

```sh
bash shared/verify_node.sh -- python -m shared.benchmark \
  --venvs-dir "$bench_env" --output "$bench_results"
python -m unittest shared.test_benchmark shared.test_layout shared.test_verify_node
```

`--project` may be repeated to select projects. `--alternate-venvs-dir`
compares verdicts for the same signed workloads against the other pinned
chain-gang revision. Both revisions must be installed directly from their
commit so the runner can verify the package provenance. `--chain-only` and
`--bench-only` provide diagnostic reports with an incomplete acceptance status.

## Interpretation

The reports measure complete 2×2, 3×2 and 2×3 transactions under ForkID ALL
and Chronicle OTDA ALL. Deferred R1 requires a matching activation output for
every activation input. Its added-input measurement varies the activation
pair and keeps the sponsor input. Its added-output measurement uses a larger
sponsor input for the additional output. Fund and exit costs include both
transactions. One turnover adds a same-template payment. Deferred keeps the
activated R1 template during turnover.

Bytes include CompactSize fields, input/output framing and script data.
Native DER signature lengths vary with the signed transaction even with the
same number of inputs. A lifecycle fee estimate is the sum of each leg's
bytes multiplied by that leg's fee rate. Timings are local wall-clock
medians. They include the chain-gang Python adapter or the BSV Node HTTP
round trip. Stack figures model the successful path in the development
evaluator and count payload bytes rather than engine memory accounting.

The project suites provide their own acceptance domains and expected
results. The report captures test and subtest identifiers and checks for
missing, duplicated, skipped or failed observations. Classification uses the
existing fixture's assertions. For example, a node-only activation test points
to its own context, and SignedData tests exercise off-chain verification.

Lamport and WOTS+ benchmark callbacks use `durable_signer` to claim the
one-time key in SQLite before calling the signer. A callback failure keeps
the key consumed. Use the same durable database and public key identity across
formats. Restoring an older database requires retiring keys with uncertain use.

## Funded regtest measurements

The default and raised runs share Genesis/Chronicle activation heights and
explicit mandatory consensus settings. The raised profile adds the Script
RPC suite's size and validation-duration overrides. Run each profile on a
fresh peerless node and write a distinct report.

```sh
for profile in default raised; do
  bash shared/verify_node.sh --profile "$profile" -- \
    "$bench_env/ml-dsa/bin/python" -m shared.benchmark_admission ml-dsa \
    --output "$bench_results/$profile/ml-dsa.json"
done
```

This test mines wallet funding, attempts admission and checks generated blocks
for each accepted transaction. Each outcome identifies the funding, activation
or exit phase. It measures local BSV Node behavior for a representative exit
under each mode. Mainnet and miner policy require their own evidence.

## Optimization regression matrix

Run the matrix from the repository root with the
[shared Chronicle pin](requirements-chronicle.txt), `ecdsa==0.19.1`,
`coincurve==21.0.0`, and `cryptography>=43` installed. OpenSSL 3.5 or newer
is required for the ML-DSA test signer.

```sh
python -m unittest -v shared.test_optimization_matrix
bash shared/verify_node.sh -- python -m unittest -v shared.test_optimization_matrix
```

If an existing installation reports the same package version but lacks
the Chronicle context API, refresh it with
`python -m pip install --force-reinstall --no-deps -r shared/requirements-chronicle.txt`.

The first command checks the installed chain-gang engine. The second also checks
per-input verdicts on BSV Node 1.2.3. For a single project, run
`python -m shared.test_optimization_matrix <project-directory-name>`.

The payment rows vary input and output counts, transaction versions, sighash
combinations, and previous-output indices across the benchmark templates. Each
row checks a signed spend and the expected effect of changing its locktime or
last output, or dropping one input witness. The 4thGraph rows check every counter build with several starting
states and fee policies, including rejected successor states and amounts.

The sponsored transaction matrix covers all 12 ForkID and Chronicle OTDA
sighash combinations for every payment template. It alternates transaction
versions and uses 252- and 253-byte change scripts to exercise both CompactSize
widths. Each row checks the original spend, changes to the paired and unpaired
outputs, an appended input, and a change to the sponsor's sequence. Deferred
activation must preserve its paired output even with SIGHASH_NONE. The counter
matrix also spends two successive outputs and rejects replay against the
original outpoint.
