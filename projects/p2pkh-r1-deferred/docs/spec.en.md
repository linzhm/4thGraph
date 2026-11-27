# P2PKH-R1-Deferred payment script

Developer RFC · [简体中文](spec.zh-CN.md)

## Funding and activation

Recognize and activate an existing short lock with the R1 version it originally committed to. v0.1.0 funding activates to its v0.1.0 target. [v0.1.0 R1 template](../../p2pkh-r1/versions/v0.1.0/template.hex)

For a value `v` and recipient identifier `h`, construct the v0.2.0 R1 script `S(h)`. Use `h = HASH160(Q)` where `Q` is the recipient's 65-byte uncompressed X9.63 P-256 key. The short lock carries `h`, `SHA256(S(h))`, the value, and `HASH256(TxOut(v, S(h)))`. The serialized output consists of the eight-byte little-endian value, CompactSize script length, and script bytes. `HASH256` is double SHA-256.

A wallet can find candidate outputs by `h`. To accept a payment, it reconstructs the complete short lock using the actual output value and canonical target template, compares every byte, and matches the expected key hash and payment amount. The node enforces the complete output commitment. The wallet checks that the key hash and script fingerprint correctly describe that commitment. Funding and activation can be constructed from `h`. The recipient supplies `Q` when spending the activated R1 output. Reusing `h` makes funding outputs linkable.

## Binary layout

Offsets for v0.3.0 are zero-based half-open ranges from the first locking opcode.

| Field | Range | Encoding |
|---|---|---|
| Owner key hash | `[1, 21)` | `HASH160(04 || X_BE32 || Y_BE32)` |
| Target script fingerprint | `[22, 54)` | `SHA256(S(h))` |
| Input value | `[116, 124)` | Eight-byte little-endian value |
| Target output commitment | `[143, 175)` | Nonzero `HASH256` of the complete `TxOut` |

The locking script is **1,085 bytes** and its complete `TxOut` is **1,096 bytes**. Zeroing the four mutable fields produces the fixed-byte SHA-256 fingerprint `a3f7b7d7d82895e8c7e7f69f1253fb8e200e22badbec5c02a5c7a51b6ff2a958`. Wallets also recognize and activate earlier assembly locks, including the 1,435-byte hash-only format and the 1,480-byte format that embeds `Q`. [v0.3.0 canonical bytes](../versions/v0.3.0/template.hex) · [v0.3.0 layout and vectors](../versions/v0.3.0/layout.json) · [v0.2.0 layout](../versions/v0.2.0/layout.json)

## Spending the short lock

Activation input `i` creates the committed equal-value output at index `i`. Both paths use a PUSHTX signature constructed inside the lock and native signature verification to bind a BIP143 SINGLE preimage. The lock checks the input value and `hashOutputs` and rejects the zero hash for a missing paired output.

| Selected mode | Unlocking script | Verification |
|---|---|---|
| BIP143 SINGLE `0x43`, `0xc3` | Push the 158-byte preimage for **160 bytes** total | Serialized scriptCode `01 ac` |
| Ten other modes | Push `typeByte || HASH256(selectedPreimage)`, then the 161-byte BIP143 SINGLE preimage for **197 bytes** total | Check the output under serialized scriptCode `04 ad 68 ab ac`, then check the selected digest with `01 ac`. The `ANYONECANPAY` bits must agree |

Genesis supports the six BIP143 modes. Chronicle enables six additional OTDA modes on the same locking template. An output at the input index is mandatory in every mode, including OTDA SINGLE `0x63` and `0xe3`. [Activation vectors](../versions/v0.3.0/sighash-modes.json) · [Forth source](../forth/deferred-activation.fth)

Arrange each activation input at the index of its corresponding output, append fee inputs and change, and construct preimages after finalizing the transaction. Any party can fund and activate an output. The wallet tracks the confirmed activation outpoint. The recipient then uses the existing external R1 signer for the ordinary R1 spend. [P2PKH-R1 specification](../../p2pkh-r1/docs/spec.en.md)

Relative to direct funding, each activated payment adds a funding `TxOut` of 1,096 bytes and an activation input of 201 or 238 bytes. Transaction-wide framing, fee inputs and change are additional. Relay and miner policy require separate measurements.
