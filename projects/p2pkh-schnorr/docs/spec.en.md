# P2PKH-Schnorr payment format

[简体中文](spec.zh-CN.md) · [Project overview](../README.md)

The owner field is HASH160 of the 32-byte BIP340 x-only public key. The rest of the file is fixed. Fill the owner slot identified in the manifest when creating a receive output. When recognizing an output, compare its length and all fixed bytes before taking the owner hash. [Frozen template](../template/template.hex) · [Layout](../template/layout.json)

The wallet builds the BSV sighash preimage for the current input. The external signer receives SHA256d of that preimage as the 32-byte BIP340 message and returns the standard signature bytes. The lock verifies the signature and binds the same message to the current input with the shared PUSHTX mechanism. ForkID ALL is the wallet default. A wallet must supply trusted Chronicle activation context for OTDA and a same-index output for SINGLE. [Binding implementation](../../../shared/pushtx.py)

| Unlock stack item | Encoding |
| --- | --- |
| Signing preimage | The chosen BSV sighash preimage with the template's scriptCode |
| Packed witness | Public x (32 bytes), even public y (32 bytes), BIP340 signature (64 bytes), even nonce y (32 bytes) |
| Mode selector | Script number 0 for the ordinary payment path |

The wallet derives both extra ordinates from public data after signing. They are unsigned, big-endian field elements. Script checks the field bounds, even parity, and public-point equation. The checker calculates the tagged challenge over r, public x, and the message. It evaluates sG − eP, rejects infinity, and compares both projective coordinates with the finite even nonce point using field congruences. This verifies the nonce coordinates without executing a square root or field inversion inside Script. [BIP340 verification](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) · [Complete addition formulas](https://eprint.iacr.org/2015/1060)

The detached verifier consumes message, public x, public y, signature, and nonce y. Use it for conformance tests. Use the fixed payment template to lock a UTXO. The copied official CSV fixture is pinned to the Bitcoin BIPs commit below. [Official test vectors](https://github.com/bitcoin/bips/blob/200f9b26fe0a2f235a2af8b30c4be9f12f6bc9cb/bip-0340/test-vectors.csv)
