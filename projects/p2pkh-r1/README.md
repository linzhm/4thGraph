# P2PKH-R1 v0.2.0

[简体中文](README.zh-CN.md) · [BSV Script Lab](../../README.md)

P2PKH-R1 locks a BSV output to the HASH160 of the recipient's uncompressed secp256r1 (P-256) public key. The payer fills a 20-byte owner field. On spend, the wallet supplies the public key and one verified 64-byte `r || s` signature for the selected input.

## Current template

v0.2.0 is the current development version. Its [46,302-byte fixed lock](template/v0.2.0/template.hex) and [binary layout](template/v0.2.0/layout.json) define the format for new outputs. The 59,582-byte [v0.1.0 lock](template/template.hex) remains recognized and spendable. Both use the same owner field at offsets 208 through 227 and support all twelve ForkID and Chronicle OTDA sighash combinations. The wallet verifies the fixed bytes of the actual prevout to identify its template.

Ordinary payments use ForkID ALL (`0x41`) and a 326-byte unlock. The v0.2.0 two-input, two-output fixture is 93,374 bytes, compared with 119,934 bytes for v0.1.0. OTDA is available after Chronicle activation. On version 2 transactions, the reference wallet can reconstruct recognized outputs for OTDA ALL and same-index outputs for paired SINGLE. An unpaired SINGLE uses the companion path.

## Wallet integration

Use the [TypeScript, Rust and Go SDK guide](docs/sdk.en.md) for receiving and ordinary ForkID ALL payments. The [Python reference wallet](reference/README.md) supports selecting a sighash per input, including mixed spends and Chronicle OTDA. Authenticate the funding outpoint, amount and script before asking an external signer to approve the intended outputs and fee.

```sh
cd projects/p2pkh-r1/reference
python -m pip install -r requirements.txt
python generate_lock.py --owner-hash160 "${R1_OWNER_HASH160:?Set the recipient HASH160}"
bash verify.sh
```

See the [protocol specification](docs/spec.en.md), [acceptance matrix](reference/acceptance.md), and [payment vector](template/v0.2.0/spend-all.json). Fixture keys are public test data. Independent review and physical-device validation remain open.
