# Lamport OTS (SHA-256)

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md) · [Versions](versions/index.json)

Lamport OTS binds an 8,192-byte one-time signature to a BSV transaction input. The v0.1.0 development baseline includes full-key and committed-key payment locks. The Forth experiments reduce the committed-key lock from 7,746 to 7,042 bytes, then to 6,830 bytes with a compact transaction binding. [Protocol](docs/spec.md) · [Forth design and measurements](docs/optimization.md)

<a name="committed-key-candidate"></a>
<a name="complete-transactions-and-stack-measurements"></a>
<a name="marginal-and-lifecycle-costs"></a>

## Choose a payment profile

The sizes below use ordinary BIP143 ALL (`0x41`) and Chronicle OTDA ALL (`0x61`). A 2×2 payment spends two outputs and creates two fresh outputs of the same profile. All sizes are in bytes.

| Profile | Output lock | BIP143 ALL unlock per input | BIP143 ALL 2×2 | OTDA ALL 2×2 |
| --- | ---: | ---: | ---: | ---: |
| `full-key` (default) | 22,780 | 8,357 | 62,392 | 153,436 |
| `committed-key` | 7,746 | 16,549 | 48,708 | 79,616 |
| `committed-key-forth` (experimental) | 7,042 | 16,549 | 47,300 | 75,392 |
| `committed-key-forth-compact` (experimental) | 6,830 | 16,549 | 46,876 | 74,120 |

Full-key inputs cost less to spend into ordinary outputs. The committed profiles store SHA-256 of the ordered public key and use an additional 8,192 bytes per input to reconstruct it. Shorter output locks also reduce OTDA ALL preimages, which serialize the outputs into each input's signing preimage. [Marginal and lifecycle costs](docs/optimization.md#transaction-and-lifecycle-costs)

For version-2 Chronicle spends, opt-in OTDA reconstruction reduces the compact profile's OTDA ALL 2×2 payment from **74,120 to 48,830 bytes** when both outputs use that profile. [Reconstruction and wallet options](docs/optimization.md#otda-unlocking-reconstruction)

The reference supports all twelve BIP143 and OTDA ALL, NONE and SINGLE combinations with optional ANYONECANPAY. BIP143 ALL is the wallet default. The reference requires explicit approval for unpaired SINGLE, which commits to zero outputs. The legacy two-push BIP143 ALL profile remains spendable. The detached digest verifier is for tests only because the same proof can authorize a different transaction. [Wire and Script specification](docs/spec.md) · [Acceptance domain](docs/acceptance.md)

## Build a payment

Use a fresh key per output, including change. Keep the full ordered public key and have the external signer durably consume the key before releasing the first signature. Verify the funding outpoint, amount, script and required confirmations before signing. Retain the original signed transaction for rebroadcast and treat an uncertain signing state as consumed. [Wallet SDK quickstart](docs/sdk.en.md#quickstart) · [Developer guide](docs/developer.en.md) · [Security and recovery](docs/security.md)

## Run

From the repository root, use an isolated Python 3.12 environment. The vectors use public test keys.

```sh
python3.12 -m venv projects/lamport-ots/workspace/venv
. projects/lamport-ots/workspace/venv/bin/activate
python -m pip install -r projects/lamport-ots/reference/requirements.txt
python -m unittest discover -s projects/lamport-ots/reference -p test_lamport.py -v
python -m unittest discover -s projects/lamport-ots/reference -p test_acceptance.py -v
python projects/lamport-ots/reference/measure.py --committed-costs
```

Run `bash projects/lamport-ots/reference/verify_apple.sh` on macOS with Apple Container, or `bash projects/lamport-ots/reference/verify.sh` for the Linux BSV Node replay. [Validation receipts](docs/validation.md) · [Original ALL vector](versions/v0.1.0/vector.json) · [Universal sighash vectors](versions/v0.1.0/universal-vectors.json) · [v0.1.0 measurements](versions/v0.1.0/measurements.json)

The funded regtest replay confirmed mempool admission and mining for funding, one turnover and exit for both Forth profiles under BIP143 ALL and Chronicle OTDA ALL. It also replayed the same lifecycle with reconstruction enabled on the compact profile. [Funded results and reproduction](docs/validation.md#funded-regtest)
