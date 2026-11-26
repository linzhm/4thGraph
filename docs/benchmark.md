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
[the shared Chronicle pin](../tools/requirements-chronicle.txt) for this benchmark.
The native project's offline example uses the same pin.
ML-DSA-44 requires OpenSSL 3.5 or later. Configure `ML_DSA_OPENSSL` if needed.
For SM2, build the Rust signer and set its executable path in
`SM2_SIGNED_DATA_SIGNER`. See the
[SM2 reference guide](../projects/p2pkh-sm2/reference/README.md).

From the repository root, run:

```sh
export PYTHONPATH=src:.
bash tools/verify_node.sh -- python -m fourthgraph.benchmark.run \
  --venvs-dir "$bench_env" --output "$bench_results"
python -m unittest tests.test_benchmark tests.test_layout tests.test_verify_node
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
  bash tools/verify_node.sh --profile "$profile" -- \
    "$bench_env/ml-dsa/bin/python" -m fourthgraph.benchmark.admission ml-dsa \
    --output "$bench_results/$profile/ml-dsa.json"
done
```

This test mines wallet funding, attempts admission and checks generated blocks
for each accepted transaction. Each outcome identifies the funding, activation
or exit phase. It measures local BSV Node behavior for a representative exit
under each mode. Mainnet and miner policy require their own evidence.
