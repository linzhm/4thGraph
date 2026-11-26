# Signed transaction benchmark

[简体中文](benchmark.zh-CN.md)

The benchmark runs each project's normal signing entry point with synthetic,
deterministic test keys. It replays complete signed transactions through the
project's pinned chain-gang build and BSV Node 1.2.3. The node uses a temporary,
peerless regtest with explicit prevouts and flags. The JSON records each
engine's verdict, transaction framing, txid and lock fingerprints. At 2×2 the
runner also checks that changing locktime after signing invalidates the
authorization.

<a name="transaction-costs"></a>

## Compare transaction costs

P2PKH-R1's two-input, two-output ForkID ALL payments measure **119,934 B** in v0.1.0, **93,374 B** in v0.2.0, and **92,322 B** in the Forth v0.3.0 experiment. Deferred uses a **1,435 B** deposit lock and creates the **46,302 B** R1 v0.2.0 lock at activation. [R1 measurements](../projects/p2pkh-r1/README.md#complete-transactions-and-stack-measurements) · [Deferred measurements](../projects/p2pkh-r1-deferred/README.md)

The unified benchmark measured **260 complete transactions** across seven projects and 32 template and sighash combinations at commit `beeb4dd`. Additional mixed-output and paired `SINGLE` replays measured 88 transactions across 11 combinations. The Deferred v0.2.0 row uses the rerun at `9c5603d`. The R1 Forth v0.3.0 row comes from its funded regtest comparison. [R1 Forth replay](../projects/p2pkh-r1/README.md#forth-experiment)

| Project and measured version | Inputs × outputs | Prevout lock | ForkID ALL unlock | ForkID ALL tx | OTDA ALL tx | ForkID ALL peak stack payload |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Native P2PKH | 2 × 2 | 25 | 107 | 374 | 374 | 145 |
| P2PKH-R1 v0.2.0 | 2 × 2 | 46,302 | 326 | 93,374 | 101,250 | 3,479 |
| P2PKH-R1 Forth v0.3.0 experiment | 2 × 2 | 45,776 | 326 | 92,322 | 100,192 | 3,478 |
| P2PKH-R1-Deferred activation | 3 × 2 | 1,435 | 197 | 93,259 | 93,260 | 359 |
| P2PKH-SM2 v1.1.0 candidate | 2 × 2 | 144,925 | 291 | 290,554 | 316,018 | 4,147 |
| Lamport OTS, committed key | 2 × 2 | 7,746 | 16,549 | 48,708 | 79,616 | 16,707 |
| WOTS+, cached steps with reconstruction | 2 × 2 | 33,956 | 2,310 | 72,650 | 79,090 | 2,701 |
| Pure ML-DSA-44 | 2 × 2 | 926,412 | 2,588 | 1,858,122 | 5,563,725 | — |

All sizes are in bytes. Lock, unlock, and stack measurements use the first ForkID ALL input. Peak stack payload is the local evaluator's peak combined data size on the main and alternate stacks. Deferred activation includes a fee-sponsor input. ML-DSA-44 stack data is unavailable. Each project README has the per-input and per-output measurements, the cost of adding an input or output, and the lifecycle totals.

The OTDA ALL measurements for R1 v0.2.0 and cached-steps WOTS+ use explicit reconstruction.

The SM2 candidate uses locking template `1` from v1.0.0 and automatically selects a shorter OTDA unlocking script when available. In the measured OTDA ALL transaction, reconstruction reduces the unlock from 290,109 to 13,023 bytes per input. The complete transaction drops from 870,194 to 316,018 bytes, a 63.7% reduction. [SM2 reconstruction results](../projects/p2pkh-sm2/README.md#otda-constructor)

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
