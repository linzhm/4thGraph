<h1 align="center">BSV Script Lab</h1>

<p align="center"><strong>Signature verification and transaction authorization in Bitcoin Script</strong></p>

<p align="center">
  <a href="README.zh-CN.md">简体中文</a> ·
  <a href="#project-index">Projects</a> ·
  <a href="#sighash-modes">Signature modes</a> ·
  <a href="#run-checks">Run the checks</a>
</p>

Generate locking scripts, replay signed spends from reproducible vectors, and compare exactly what each signature commits to.

---

<a name="project-index"></a>

## Projects

| Project | Version | What it explores | Start here |
|---|---|---|---|
| [P2PKH-R1](projects/p2pkh-r1/README.md) | v0.1 | P-256 ECDSA authorization for a public-key hash, with a single device signature for an ordinary payment | [Specification](projects/p2pkh-r1/docs/spec.en.md) · [TypeScript, Rust and Go SDK guide](projects/p2pkh-r1/docs/sdk.en.md) |
| [P2PKH-R1-Deferred](projects/p2pkh-r1-deferred/README.md) | v0.1 | A 1,435-byte funding lock that commits to an ordinary R1 output for later activation | [Format and reference checks](projects/p2pkh-r1-deferred/README.md) |
| [P2PKH-SM2](projects/p2pkh-sm2/README.md) | v1.0.0 | A payment template that verifies SM2 and computes SM3 with ZA in Script | [Specification](projects/p2pkh-sm2/docs/spec.en.md) · [Python reference](projects/p2pkh-sm2/reference/README.md) |
| [Lamport OTS](projects/lamport-ots/README.md) | v0.1 | Hash-based authorization using SHA-256. Each key is for one UTXO and one signature. | [Security model](projects/lamport-ots/docs/security.md) · [Validation record](projects/lamport-ots/docs/validation.md) |
| [WOTS+](projects/wots-plus/README.md) | v0.1 | SHA-256 hash-chain authorization with a 2,144-byte one-time signature | [Specification](projects/wots-plus/docs/spec.md) · [Verification](projects/wots-plus/README.md#run-the-checks) |
| [ML-DSA-44](projects/ml-dsa/README.md) | v0.1 | Pure FIPS 204 message verification and a transaction-bound payment template | [Implementation and measurements](projects/ml-dsa/README.md) |
| [Native P2PK and P2PKH](projects/p2pk-p2pkh-baseline/README.md) | v0.1 | Native signature locks and complete-input acceptance fixtures | [Acceptance matrix](projects/p2pk-p2pkh-baseline/reference/acceptance.md) |

Version v0.1 denotes a development baseline. Project guides describe optional templates and their validation scope.

<details>
<summary><strong>Compare script sizes</strong></summary>

These are script byte counts for the reference templates using ordinary ForkID `ALL` (`0x41`).

| Template | Locking script | Unlocking script |
|---|---:|---:|
| [P2PKH-R1](projects/p2pkh-r1/template/layout.json) | 59,582 B | 326 B |
| [P2PKH-SM2 v1.0.0](projects/p2pkh-sm2/template/layout.json) | 144,925 B | 291 B |
| [Lamport OTS](projects/lamport-ots/template/measurement.json) | 22,780 B | 8,357 B |
| [WOTS+](projects/wots-plus/docs/validation.md) | 42,266 B | 2,310 B |
| [ML-DSA-44](projects/ml-dsa/README.md#script-sizes) | 926,403 B | 2,588 B |

The Lamport locking script includes the public key. An ordinary OTDA unlocking script varies with the transaction data being signed.

</details>

<a name="sighash-modes"></a>

## Signature modes

The five reference payment templates support the twelve BIP143 ForkID and Chronicle OTDA combinations below. Select the mode per input. Ordinary payments default to `0x41`. Deferred R1 activation defaults to `0x43` and requires a same-index output in every mode.

| Output commitment | BIP143 ForkID | ForkID + ANYONECANPAY | Chronicle OTDA | OTDA + ANYONECANPAY |
|---|---|---|---|---|
| `ALL` · all outputs | `0x41` | `0xc1` | `0x61` | `0xe1` |
| `NONE` · no outputs | `0x42` | `0xc2` | `0x62` | `0xe2` |
| `SINGLE` · output at the input index, if present | `0x43` | `0xc3` | `0x63` | `0xe3` |

<details>
<summary><strong>P2PKH-SM2 v1.0.0 and unpaired SINGLE</strong></summary>

A transaction may carry ForkID and OTDA signatures on different inputs. If an OTDA `SINGLE` input has no corresponding output, the script checks a companion preimage that binds the SM2 authorization to the current input.

[SM2 transaction-binding rules](projects/p2pkh-sm2/docs/spec.en.md#transaction-scope-and-bytes) · [16 signing vectors](projects/p2pkh-sm2/template/sighash-modes.json)

</details>

<a name="run-checks"></a>

## Run the checks

From the repository root, check documentation links and rebuild the canonical R1 script bytes.

```sh
python3 -m unittest shared.test_layout -v
```

<details>
<summary><strong>P2PKH-R1 · Rebuild a lock and verify complete inputs</strong></summary>

Use Python 3.12, Git and Rust on Linux x86-64.

```sh
cd projects/p2pkh-r1/reference
python -m pip install -r requirements.txt
python generate_lock.py --owner-hash160 4ceab2c8be16c1d4c6b4147d39aa449c2d63f184
bash verify.sh
```

[Reference implementation and conformance setup](projects/p2pkh-r1/reference/README.md)

</details>

<details>
<summary><strong>P2PKH-SM2 · Standard vectors and OpenSSL interoperability</strong></summary>

Use Python 3.12+ and OpenSSL with SM2/SM3 support.

```sh
cd projects/p2pkh-sm2/reference
python3 -m pip install ecdsa==0.19.1
python3 -m unittest -v test_sm2
```

[Complete-input tests, Chronicle activation cases and validation scope](projects/p2pkh-sm2/reference/README.md)

</details>

<details>
<summary><strong>Lamport OTS · Reproduce the vectors and run the node check</strong></summary>

Run from the repository root in an activated Python environment.

```sh
python -m pip install -r projects/lamport-ots/reference/requirements.txt
python -m unittest discover -s projects/lamport-ots/reference -p test_lamport.py -v
```

Use `bash projects/lamport-ots/reference/verify.sh` on Linux x86-64 or `bash projects/lamport-ots/reference/verify_apple.sh` with Apple Container.

[Reference tools and measurements](projects/lamport-ots/reference/README.md)

</details>

Use each project's reference guide for node setup and validation scope. GitHub Actions workflows are started manually. [Verification runs](https://github.com/linzhm/bsv-script-lab/actions)

## Repository layout

Each project lives under `projects/<name>/` with its own specifications, reference implementation and vectors. P2PKH-R1 also provides TypeScript, Rust and Go SDKs. Script encoding, transaction serialization and the node launcher are in [`shared/`](shared/README.md).

## Cross-project benchmark

Compare signed transaction sizes, marginal input and output costs, and full
payment lifecycles across all seven projects. [Run the benchmark](shared/benchmark.md)
