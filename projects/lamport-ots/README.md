<!-- Generated from manifest.yaml with Copier. -->

# Lamport OTS (SHA-256) v0.1.0

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md) · [Versions](versions/index.json)

## Developer resources

**[Wallet SDK quickstart](docs/sdk.en.md#quickstart)** · [Unified wallet SDK](../../sdk/README.md#quickstart)

Lamport OTS uses SHA-256 commitments to independently generated secrets to authorize a BSV input. The fixed-weight research candidate reduces the committed proof from 16,384 to 11,264 bytes and the raw signature from 8,192 to 4,096 bytes. [Signature design](docs/subset.en.md) · [Protocol](docs/spec.md)

[Protocol](docs/developer.en.md) · [Algorithm and execution](#algorithm-and-execution) · [Reproduce the checks](#reproduce-the-checks) · [Complete transactions and stack measurements](#complete-transactions-and-stack-measurements) · [Measurements data](versions/v0.1.0/measurements.json)

| Entry point | Purpose |
| --- | --- |
| `locking_script` | Build the full-key or committed-key payment lock from the selected key representation. |
| `subset_locking_script` | Build the fixed-weight candidate lock from the corresponding ordered public key. |
| `sign_spend` | Bind a selected input to the transaction and call an external one-time signer. |

## Algorithm and execution

The opt-in **v0.2.0 candidate** uses a 6,525-byte lock and an 871-byte OTDA reconstruction program pinned in the version catalog. [v0.2.0 manifest](versions/v0.2.0/manifest.json) · [Measurements](versions/v0.2.0/measurements.json)

The full-key lock embeds the ordered Lamport public key. A committed-key lock stores its SHA-256 digest and checks the full key supplied at spend time. The transaction binding checks the current input. [Protocol](docs/spec.md)

The opt-in fixed-weight candidate maps each digest byte to four of eleven slots. Changing the digest requires a previously unopened slot. The scheme uses its own key format and one independently generated key per output. [Signature format and security](docs/subset.en.md)

## Reproduce the checks

Use the project’s pinned Python environment from the repository root.

```sh
python3.12 -m venv projects/lamport-ots/workspace/venv
. projects/lamport-ots/workspace/venv/bin/activate
python -m pip install -r projects/lamport-ots/reference/requirements.txt
```

```sh
PYTHONPATH=src:. python projects/lamport-ots/reference/measure.py --benchmark
bash projects/lamport-ots/reference/verify.sh
```

### Run

The full-key and commitment payment builds start from [payment-lock.fth](forth/payment-lock.fth). The compact commitment layouts also compile [the committed verifier](forth/committed-verifier.fth) or [the fixed-weight verifier](forth/subset-verifier.fth).

From the repository root, use an isolated Python 3.12 environment. The vectors use public test keys.

```sh
python -m unittest discover -s projects/lamport-ots/reference -p test_lamport.py -v
python -m unittest discover -s projects/lamport-ots/reference -p test_acceptance.py -v
python projects/lamport-ots/reference/measure.py --committed-costs
```

Run `bash projects/lamport-ots/reference/verify_apple.sh` on macOS with Apple Container, or `bash projects/lamport-ots/reference/verify.sh` for the Linux BSV Node replay. [Validation receipts](docs/validation.md) · [Original ALL vector](versions/v0.1.0/vector.json) · [Universal sighash vectors](versions/v0.1.0/universal-vectors.json) · [v0.1.0 measurements](versions/v0.1.0/measurements.json)

The funded regtest replay confirmed mempool admission and mining for funding, one turnover and exit for both Forth profiles under BIP143 ALL and Chronicle OTDA ALL. It also replayed the same lifecycle with reconstruction enabled on the compact profile. [Funded results and reproduction](docs/validation.md#funded-regtest)

The fixed-weight candidate completed direct exits and one-turnover flows under BIP143 ALL and Chronicle OTDA ALL. All ten transactions entered the default-policy regtest node's mempool and were mined. [Dual-engine and funded results](docs/validation.md#fixed-weight-candidate-replay)

## Developer and wallet integration

### Build a payment

Use a fresh key per output, including change. Keep the full ordered public key and have the external signer durably consume the key before releasing the first signature. Verify the funding outpoint, amount, script and required confirmations before signing. Retain the original signed transaction for rebroadcast and treat an uncertain signing state as consumed. [Wallet SDK quickstart](docs/sdk.en.md#quickstart) · [Developer guide](docs/developer.en.md) · [Security and recovery](docs/security.md)

## Complete transactions and stack measurements

<a name="committed-key-candidate"></a>

<a name="marginal-and-lifecycle-costs"></a>

### Choose a payment profile

The sizes below use ordinary BIP143 ALL (`0x41`) and Chronicle OTDA ALL (`0x61`). A 2×2 payment spends two outputs and creates two fresh outputs of the same profile. All sizes are in bytes.

| Profile | Output lock | BIP143 ALL unlock per input | BIP143 ALL 2×2 | OTDA ALL 2×2 |
| --- | ---: | ---: | ---: | ---: |
| `full-key` (default) | 22,780 | 8,357 | 62,392 | 153,436 |
| `committed-key` | 7,746 | 16,549 | 48,708 | 79,616 |
| `committed-key-forth` (experimental) | 7,042 | 16,549 | 47,300 | 75,392 |
| `committed-key-forth-compact` (experimental) | 6,830 | 16,549 | 46,876 | 74,120 |
| `committed-key-forth-v0.2.0` (candidate) | 6,525 | 16,549 | 46,266 | 72,290 |
| `committed-key-forth-subset` (research) | 8,003 | 11,429 | 38,982 | 70,918 |

Full-key inputs cost less to spend into ordinary outputs. The classic committed profiles store SHA-256 of the ordered public key and use an additional 8,192 bytes per input to reconstruct it. Shorter output locks also reduce OTDA ALL preimages, which serialize the outputs into each input's signing preimage. [Marginal and lifecycle costs](docs/optimization.md#transaction-and-lifecycle-costs)

For version-2 Chronicle spends, opt-in OTDA reconstruction reduces the compact profile's OTDA ALL 2×2 payment from **74,120 to 48,830 bytes** when both outputs use that profile. [Reconstruction and wallet options](docs/optimization.md#otda-unlocking-reconstruction)

With both outputs using v0.2.0, OTDA reconstruction brings the same payment shape to **48,106 bytes**. [v0.2.0 design](docs/optimization.md#version-020-candidate)

The fixed-weight candidate measures **41,920 bytes** with reconstructed OTDA ALL 2×2. A two-input direct exit to native P2PKH saves **10,240 bytes** in either ALL mode versus v0.2.0. [Fixed-weight costs](docs/optimization.md#fixed-weight-candidate)

The reference supports all twelve BIP143 and OTDA ALL, NONE and SINGLE combinations with optional ANYONECANPAY. BIP143 ALL is the wallet default. The reference requires explicit approval for unpaired SINGLE, which commits to zero outputs. The legacy two-push BIP143 ALL profile remains spendable. The detached digest verifier is for tests only because the same proof can authorize a different transaction. [Wire and Script specification](docs/spec.md) · [Acceptance domain](docs/acceptance.md)
