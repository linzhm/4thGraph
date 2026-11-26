# BSV Script Lab

**Compile Forth to BSV Script with 4thGraph (4thG). Replay the transactions to measure what you built.**

BSV Script Lab builds tools for developing and testing BSV contracts. **4thGraph** is its Forth toolchain for compiling individual Script routines and planning multi-transaction workflows. The lab also provides wallet-ready locking templates, external-signer SDKs, and signed transaction vectors.

**[Try 4thG](#4thg-quickstart)** · [Project comparisons](#4thg-comparisons) · [Wallet SDK quickstart](shared/sdk/README.md#quickstart) · [Wallet projects](#project-index) · [Transaction costs](#transaction-costs) · [简体中文](README.zh-CN.md)

<a name="4thg-quickstart"></a>

## Try 4thG

Install Git and Python 3.12, then clone the `feat/4thgraph` branch. The compiler runs directly from the checkout with the Python standard library. You can compile the example below before setting up a node or installing any Python packages.

```sh
git clone --branch feat/4thgraph https://github.com/linzhm/bsv-script-lab.git
cd bsv-script-lab

cat > add-one.fth <<'FORTH'
bsv-effect: add-one u32 -- u32 ;
: add-one 1 cell>u32 u32+ ;
FORTH

PYTHONPATH=. python3 projects/4thgraph/protocol.py add-one.fth \
  --entry add-one --optimize safe
```

`bsv-effect:` declares that `add-one` consumes and returns one `u32`. The word adds one with 32-bit wraparound. The compiler prints JSON with `script_hex` equal to `8b05000000000197`, `script_bytes` equal to `8`, the stack signature, and source and build digests. Change the `1` and rerun to see how the output changes.

### Replay a full workflow

From the same checkout on Linux x86-64, install the replay dependencies. `pip` builds the pinned chain-gang package from Git, so have Rust/Cargo and a C toolchain available. The launcher uses `curl` to fetch and verify BSV Node 1.2.3, then funds the example on an isolated regtest network.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install ecdsa -r shared/requirements-chronicle.txt

project=projects/4thgraph
PYTHONPATH=. bash shared/verify_node.sh --profile default -- \
  python "$project/replay.py" --target both --optimize stack --samples 1 \
  --output "$project/build/quickstart-replay.json"

PYTHONPATH=. python "$project/decision_report.py" "$project/build/quickstart-replay.json" \
  --output-dir "$project/build/quickstart-decision"
```

Open `projects/4thgraph/build/quickstart-decision/decision-report.md` to see why a candidate was selected or excluded, transaction bytes for settlement and review, and the BSV Node and chain-gang results. [4thGraph guide](https://github.com/linzhm/bsv-script-lab/tree/feat/4thgraph/projects/4thgraph) · [Forth language reference](https://github.com/linzhm/bsv-script-lab/blob/feat/4thgraph/projects/4thgraph/language.md)

### What you can build

- **Script routines.** Compile a typed Forth word to Script, compare stack schedules, and inspect rewrites at their source locations.
- **Transaction workflows.** Declare inputs, signer roles, parallel work, and a join. 4thG can fuse the work into one spend or split it across UTXOs for independent submission. The bounded search compares supported transaction boundaries and witness layouts under the declared availability and authorization constraints. The host runner binds transaction templates to actual outpoints and prepares signing requests. [Parallel example](https://github.com/linzhm/bsv-script-lab/blob/feat/4thgraph/projects/4thgraph/example.fth) · [Gated example](https://github.com/linzhm/bsv-script-lab/blob/feat/4thgraph/projects/4thgraph/gated.fth)
- **Circuits.** A bounded circuit backend emits Circom for supported Forth words. The counter example checks that host evaluation, Script, and circuit constraints agree at wraparound and branch boundaries. [Circuit example](https://github.com/linzhm/bsv-script-lab/blob/feat/4thgraph/projects/4thgraph/proof/workflow.fth)

<a name="4thg-comparisons"></a>

## Projects built and compared with 4thG

| Project | What the comparison shows |
| --- | --- |
| P2PKH-R1 Forth v0.3.0 experiment | The Forth baseline reproduces the v0.2.0 lock byte for byte. The optimized lock goes from 46,302 to **45,776 B**, and the two-input, two-output ForkID ALL payment goes from 93,374 to **92,322 B**. The replay also covers OTDA and a build that uses sCrypt-compiled curve kernels. [Experiment and replay](https://github.com/linzhm/bsv-script-lab/tree/feat/4thgraph/projects/p2pkh-r1/experiments/forth) |
| BLS12-381 Groth16 verifier (in development) | Forth defines the verification stages for off-chain proofs with fixed, mixed, or spend-time public inputs. The comparison with nChain matches the public-input domain and the placement of precomputed pairing data. |
| CCTP transaction layouts (in development) | Compares the same Groth16 verification workload in a fused spend, an atomic two-input spend, and two serial spends. The comparison measures total transaction bytes and the slowest spend’s validation time. |

<a name="project-index"></a>

## Wallet projects

| Project | Use it to | Version | Wallet integration |
| --- | --- | --- | --- |
| [Native P2PK and P2PKH](projects/p2pk-p2pkh-baseline/README.md) | Establish a size and signing baseline with native secp256k1 scripts | v0.1 development | [Integration guide](projects/p2pk-p2pkh-baseline/docs/sdk.en.md#quickstart) |
| [P2PKH-R1](projects/p2pkh-r1/README.md) | Pay to a P-256 public-key hash using a fixed locking template | v0.2.0 development | [Integration guide](projects/p2pkh-r1/docs/sdk.en.md#quickstart) |
| [P2PKH-R1-Deferred](projects/p2pkh-r1-deferred/README.md) | Receive funds with a short lock and activate a standard R1 output later | v0.2.0 development | [Integration guide](projects/p2pkh-r1-deferred/docs/sdk.en.md#quickstart) |
| [P2PKH-SM2](projects/p2pkh-sm2/README.md) | Pay with SM2 signatures, accept GB/T 35275-2026 SignedData off-chain, and reconstruct eligible OTDA outputs | v1.1.0 candidate | [Integration guide](projects/p2pkh-sm2/docs/sdk.en.md#quickstart) |
| [Lamport OTS](projects/lamport-ots/README.md) | Evaluate SHA-256 one-time signatures with full-key and committed-key locks | v0.1 development | [Integration guide](projects/lamport-ots/docs/sdk.en.md#quickstart) |
| [WOTS+](projects/wots-plus/README.md) | Evaluate one-time signatures built from SHA-256 hash chains | v0.1 development | [Integration guide](projects/wots-plus/docs/sdk.en.md#quickstart) |
| [Pure ML-DSA-44](projects/ml-dsa/README.md) | Evaluate FIPS 204 pure-mode ML-DSA-44 signatures in Script | v0.1 development | [Integration guide](projects/ml-dsa/docs/sdk.en.md#quickstart) |

Start with native P2PKH to run your first payment. The projects share the same wallet calls in TypeScript, Rust, Go, and Python. Each project guide covers its signing request, template options, and local dependencies. [Wallet SDK quickstart](shared/sdk/README.md)

<a name="transaction-costs"></a>

## Compare transaction costs

P2PKH-R1 v0.2.0 reduced the two-input, two-output ForkID ALL benchmark from **119,934 to 93,374 bytes**. Deferred uses a **1,435-byte deposit lock** and creates the full **46,302-byte R1 lock** at activation. The right comparison includes both the bytes paid at each step and the number of steps in the wallet's flow. [R1 results](projects/p2pkh-r1/README.md) · [Deferred results](projects/p2pkh-r1-deferred/README.md)

The unified benchmark measured **260 complete transactions** across seven projects and 32 template and sighash combinations at commit `beeb4dd`. Additional mixed-output and paired `SINGLE` replays measured 88 transactions across 11 combinations. The Deferred v0.2.0 row uses the rerun at `9c5603d`.

| Project and measured version | Inputs × outputs | Prevout lock | ForkID ALL unlock | ForkID ALL tx | OTDA ALL tx | ForkID ALL peak stack payload |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Native P2PKH | 2 × 2 | 25 | 107 | 374 | 374 | 145 |
| P2PKH-R1 v0.2.0 | 2 × 2 | 46,302 | 326 | 93,374 | 101,250 | 3,479 |
| P2PKH-R1-Deferred activation | 3 × 2 | 1,435 | 197 | 93,259 | 93,260 | 359 |
| P2PKH-SM2 v1.1.0 candidate | 2 × 2 | 144,925 | 291 | 290,554 | 316,018 | 4,147 |
| Lamport OTS, committed key | 2 × 2 | 7,746 | 16,549 | 48,708 | 79,616 | 16,707 |
| WOTS+, cached steps with reconstruction | 2 × 2 | 33,956 | 2,310 | 72,650 | 79,090 | 2,701 |
| Pure ML-DSA-44 | 2 × 2 | 926,412 | 2,588 | 1,858,122 | 5,563,725 | — |

All sizes are in bytes. Lock, unlock, and stack measurements use the first ForkID ALL input. Peak stack payload is the local evaluator's peak combined data size on the main and alternate stacks. Deferred activation includes a fee-sponsor input. ML-DSA-44 stack data is unavailable. Each project README has the per-input and per-output measurements, the cost of adding an input or output, and the lifecycle totals.

The SM2 candidate uses locking template `1` from v1.0.0 and automatically selects a shorter OTDA unlocking script when available. In the measured OTDA ALL transaction, reconstruction reduces the unlock from 290,109 to 13,023 bytes per input. The complete transaction drops from 870,194 to 316,018 bytes, a 63.7% reduction. [SM2 reconstruction results](projects/p2pkh-sm2/README.md#otda-constructor)

## Reproduce the results

The benchmark guide shows how to replay signed transactions against BSV Node 1.2.3 and the pinned chain-gang version. Each project links its protocol specification, security analysis, acceptance cases, and SDK. [Benchmark guide](shared/benchmark.md)
