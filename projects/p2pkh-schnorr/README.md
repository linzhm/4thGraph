<!-- Generated from manifest.yaml with Copier. -->

# P2PKH-Schnorr v0.17.0

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md) · [Versions](versions/index.json)

## Developer resources

**[Wallet SDK quickstart](docs/sdk.en.md#quickstart)** · [Unified wallet SDK](../../sdk/README.md#quickstart)

Create a BSV payment lock from the HASH160 of a BIP340 x-only public key. The key is 32 bytes, the owner hash is 20 bytes, and the external signer returns a 64-byte BIP340 signature. This is an experimental payment template. [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)

[Protocol](docs/spec.en.md) · [Algorithm and execution](#algorithm-and-execution) · [Reproduce the checks](#reproduce-the-checks) · [Complete transactions and stack measurements](#complete-transactions-and-stack-measurements) · [Measurements data](versions/v0.17.0/measurements.json)

| Entry point | Purpose |
| --- | --- |
| `bip340-verify ( script -- script )` | Build a detached verifier. At execution it accepts a byte message, public key x and y, a BIP340 signature, and the nonce point's y coordinate. |
| `schnorr-lock ( script bytes -- script )` | Build a payment lock from a 20-byte owner hash. The lock checks ownership, verifies the BIP340 signature, and binds the signed digest to the current input. |
| `schnorr-unlock` | Build the input script from the signed preimage, mode selector, signature, and public coordinate witnesses. |

## Use cases and trade-offs

The wallet defaults to the published v0.17.0 template. Use the SDK for receiving, spending and authenticating previous outputs. [Wallet SDK](docs/sdk.en.md#quickstart) · [Version index](versions/index.json)

Two participants can authorize the same lock through a BIP327 aggregate key. The external signer manages the signing session. [MuSig2 and native 2-of-2](docs/threshold-comparison.en.md)

The high-level 64-window Forth experiment records the current automatic build and constructor replay. [OTDA measurements](docs/high-level-forth.en.md#otda-constructor) · [Optimization history](docs/high-level-forth.en.md#optimization-history)

## Algorithm and execution

1. Parse the BIP340 signature as `r || s` and check the coordinate bounds, even ordinates, public-point equation, and scalar bound.
2. Hash the original `r`, x-only public key and message with the BIP340 tag, then reduce the hash modulo the group order to obtain `e`.
3. Evaluate `sG − eP` with 64 two-bit windows. Require a nonzero projective Z and compare both coordinates with the even nonce point.

The payment wrapper checks the public-key hash and binds the verified message to the actual input. The released verifier uses coordinate scaling, paired doubling and secp256k1 GLV. [Payment protocol and curve formulas](docs/spec.en.md) · [Forth payment source](reference/schnorr.fth)

<a name="secp256k1-arithmetic"></a>

Contracts performing secp256k1 point arithmetic in Script can reuse these curve kernels. [secp256k1 library](../../src/fourthgraph/stdlib/secp256k1.fth)

## Reproduce the checks

<a name="validate-the-baseline"></a>

Run from the repository root with Python 3.12. The SDK replay also uses Node.js 24, Go, and Rust/Cargo. The suites use public fixture keys and replay against pinned chain-gang and an isolated BSV Node regtest.

```sh
bash tools/setup-workspaces.sh
python3.12 -m venv projects/p2pkh-schnorr/workspace/p2pkh-schnorr
projects/p2pkh-schnorr/workspace/p2pkh-schnorr/bin/python -m pip install -r projects/p2pkh-schnorr/reference/requirements.txt
. projects/p2pkh-schnorr/workspace/p2pkh-schnorr/bin/activate
export SCRIPT_LAB_SDK_PYTHON="$VIRTUAL_ENV/bin/python"
```

```sh
PYTHONPATH=src:. python projects/p2pkh-schnorr/reference/generate_template.py --check
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- python -m unittest discover -s projects/p2pkh-schnorr/reference
```

```sh
PYTHONPATH="$PWD/tests" REGTEST_CHRONICLE_HEIGHT=5 \
  bash tools/verify_node.sh -- "$SCRIPT_LAB_SDK_PYTHON" -m unittest -v test_secp256k1_library
bash tools/verify_node.sh -- bash sdk/verify_wallet.sh p2pkh-schnorr
```

The acceptance suite checks all 19 official BIP340 verification vectors through libsecp256k1 and both Script engines, and regenerates eight signing vectors with public test data. Payment cases cover all 12 paired BIP143 and Chronicle OTDA sighash modes in transaction versions 1 and 2. They cover stale locktime, ALL/NONE/SINGLE output commitments, malformed coordinates, ownership, fee balance, and Chronicle activation. The verifier tests exercise both lookup tables and infinity. The curve tests compare scaled point operations and GLV rounding with independent references and replay correct and incorrect results in both engines. [Payment tests](reference/test_schnorr.py) · [Curve tests](../../tests/test_secp256k1_library.py)

The compiler experiment has its own commands and pinned benchmark receipts. [Forth build and replay](docs/high-level-forth.en.md#replay)

## Script sizes

| Component | v0.16.0 | v0.17.0 |
| --- | ---: | ---: |
| Detached BIP340 verifier | 21,705 B | 21,625 B |
| Complete payment lock | 22,515 B | 22,435 B |

The owner field starts at byte offset 189. The release record includes paired measurements on chain-gang and BSV Node for the detached verifier and both native P2PKH exit modes. The sCrypt report compares v0.6.0 with the legacy verifier and a separate BIP340 implementation using the same witness layout. [Layout and fingerprint](versions/v0.17.0/layout.json) · [Recorded measurements](versions/v0.17.0/measurements.json) · [sCrypt comparison](docs/scrypt-comparison.en.md)

## Developer and wallet integration

Use `createLock` with the x-only key or its HASH160. Verify the funding outpoint, amount and owner before approving the outputs and fee. Use `signPayment` for a single-input BIP143 ALL payment or `signInput` for a prepared transaction. The signer receives a 32-byte BIP340 message and returns a 64-byte signature. [SDK quickstart](docs/sdk.en.md#quickstart)

<a name="build-from-forth"></a>

Load `REQUIRE stdlib/bip340.fth` for the detached verifier. The reference payment code adds ownership and transaction binding. [Forth source](reference/schnorr.fth) · [Version index](versions/index.json)

## Complete transactions and stack measurements

<a name="measured-sizes"></a>

The v0.17.0 literal fixtures spend two Schnorr outputs and create two Schnorr outputs. BSV Node 1.2.3 and pinned chain-gang verify complete inputs with explicit prevouts. The development evaluator measures stack peaks for input zero. The main and alternate item peaks and combined payload peak are recorded independently. Transaction and payload sizes are in bytes. [Recorded measurements](versions/v0.17.0/measurements.json) · [Benchmark method](../../docs/benchmark.md)

| Mode | Inputs × outputs | Previous locks | Unlocks | New locks | Total | Main / alt items | Stack payload |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| BIP143 ALL (`0x41`) | 2 × 2 | 22,435 × 2 | 329 × 2 | 22,435 × 2 | 45,646 | 90 / 13 | 3,401 |
| Chronicle OTDA ALL (`0x61`) | 2 × 2 | 22,435 × 2 | 45,161 × 2 | 22,435 × 2 | 135,310 | 90 / 13 | 90,154 |

```sh
PYTHONPATH=src:. bash tools/verify_node.sh -- "$SCRIPT_LAB_SDK_PYTHON" -m fourthgraph.benchmark.run \
  --project p2pkh-schnorr --venvs-dir projects/p2pkh-schnorr/workspace --output projects/p2pkh-schnorr/workspace/build/benchmark
```

For the same v0.17.0 two-input, two-output OTDA ALL payment, the constructor reduces each unlock from 45,161 to 4,819 bytes and the transaction from 135,310 to 54,626 bytes. The reconstructed payment was mined on default-policy regtest. [Constructor comparison](docs/high-level-forth.en.md#otda-constructor)

Under BSV Node 1.2.3's default regtest policy, funding, turnover, and exit entered the mempool and were mined in both modes.

```sh
PYTHONPATH=src:. bash tools/verify_node.sh --profile default -- "$SCRIPT_LAB_SDK_PYTHON" -m fourthgraph.benchmark.admission \
  p2pkh-schnorr --template v0.17.0 --turnover --output projects/p2pkh-schnorr/workspace/build/admission.json
PYTHONPATH=src:. bash tools/verify_node.sh --profile default -- "$SCRIPT_LAB_SDK_PYTHON" -m fourthgraph.benchmark.admission \
  p2pkh-schnorr --template v0.17.0-reconstructed --turnover --output projects/p2pkh-schnorr/workspace/build/admission-reconstructed.json
```

## Marginal and lifecycle costs

Each added-input or added-output cell gives the change from 2 × 2 in **total bytes (new output locks / input unlocks / other serialization)**. Previous locks are counted in the transaction that funds the UTXO. Both lifecycle totals include native P2PKH funding and exit. One turnover adds a payment between Schnorr outputs.

| Mode | Added-input shape | Added-input bytes | Added-output shape | Added-output bytes | Fund and exit | One turnover |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| BIP143 ALL (`0x41`) | 3 × 2 | 372 (0 / 329 / 43) | 2 × 3 | 22,446 (22,435 / 0 / 11) | 45,872 | 91,518 |
| Chronicle OTDA ALL (`0x61`) | 3 × 2 | 45,327 (0 / 45,284 / 43) | 2 × 3 | 67,346 (22,435 / 44,896 / 15) | 45,886 | 181,195 |

[Unified benchmark and reproduction](../../docs/benchmark.md) · [Native 2-of-2 lifecycle comparison](docs/threshold-comparison.en.md)
