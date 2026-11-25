# P2PKH-R1 developer guide

[简体中文](developer.zh-CN.md) · [Project overview](../README.md)

P-256 wallet payments. New outputs use the fixed v0.2.0 lock. Existing UTXOs retain the script and template version with which they were funded.

[Protocol specification](#protocol) · [Security analysis](#security) · [Validation and measurements](#validation) · [SDK and reference interfaces](#sdk)

<a name="protocol"></a>

## Protocol specification

The payer fills the 20-byte HASH160 of the recipient's validated, uncompressed P-256 public key at offsets `[208, 228)`. The spender supplies the public key and a signature over the current input's authorization. ForkID and Chronicle OTDA each support ALL, NONE and SINGLE, with optional ANYONECANPAY. On a Chronicle version 2 transaction, the wallet can rebuild eligible outputs in an OTDA unlock and reproduce the original signing preimage.

Use the fixed-byte fingerprints to identify v0.2.0 and v0.1.0. The older output's lock determines the spend rules. [Protocol and sighash specification](spec.en.md) · [v0.2.0 layout](../template/v0.2.0/layout.json) · [v0.1.0 layout](../template/layout.json)

<a name="security"></a>

## Security analysis

Before signing, authenticate the funding outpoint, amount, owner and full script. Approve the output commitments of the selected sighash, and store the signing history durably where the reference wallet requires it. The signing service controls key custody and nonce safety. If a parent txid changes before confirmation, recover the confirmed outpoint and rebuild the child before requesting authorization. Check confirmation depth according to the application's policy.

Treat the documented dual-engine results as evidence for the tested contexts. Physical devices, independent review and deployment policy have their own acceptance scope. [Chronicle execution and recovery](chronicle.md) · [Reference signing preflight](../reference/wallet.py)

<a name="validation"></a>

## Validation and measurements

The node fixture crosses twelve modes, two transaction versions, paired and unpaired outputs, three rule contexts and nine authorization cases. This gives 1,296 rows per template. The independent engine covers the declared Chronicle subset. Ordinary ForkID ALL uses a 326-byte unlock. The v0.2.0 two-input, two-output payment measures 93,374 bytes, compared with 119,934 for v0.1.0. The project README links measured templates and the reference report explains the OTDA witness costs.

From the repository root, install the pinned [reference requirements](../reference/requirements.txt) and run `bash projects/p2pkh-r1/reference/verify.sh`. [Acceptance matrix](../reference/acceptance.md) · [v0.2.0 payment vector](../template/v0.2.0/spend-all.json) · [Reference measurements](../reference/README.md)

<a name="sdk"></a>

## SDK and reference interfaces

The TypeScript, Rust and Go source SDKs recognize the raw lock, fill the owner slot and construct ordinary single-input ForkID ALL payments. Use the message-signing callback for a device that applies SHA-256 internally and the digest-signing callback for a device that signs an already computed digest. Both return 64-byte `r || s`. Use the Python `sign_spend` interface for prepared inputs with per-input sighash selection. Broadcasting, UTXO discovery and transaction approval belong to the integrating wallet.

[SDK guide and test commands](sdk.en.md) · [Python reference](../reference/README.md)
