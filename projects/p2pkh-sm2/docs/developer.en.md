# P2PKH-SM2 developer guide

[简体中文](developer.zh-CN.md) · [Project overview](../README.md)

The v1.0.0 payment lock binds an SM2 signature to the current BSV input. The GB/T 35275-2026 adapter runs off chain.

[Protocol specification](#protocol) · [Security analysis](#security) · [Validation and measurements](#validation) · [SDK and reference interfaces](#sdk)

<a name="protocol"></a>

## Protocol specification

The lock uses HASH160 of the recipient's 65-byte uncompressed SM2 public key. It computes ZA with the template's fixed user ID, verifies the SM2 signature and binds it to the spending transaction. It supports the twelve ForkID and Chronicle OTDA types with the documented companion path for unpaired SINGLE. The SignedData payment adapter accepts one direct signer, with `SignedData.version = 1` and `SignerInfo.version = 2`, and extracts the raw signature for the Script witness.

[Payment specification](spec.en.md) · [Canonical layout](../template/layout.json) · [GB/T 35275-2026](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=28A18B702BDC318803E598F5E502E2CC)

<a name="security"></a>

## Security analysis

Validate and pin the expected SM2 public key, user ID and DER issuer-and-serial identifier before requesting a signature. Authenticate the funding output and confirm the intended transaction, amounts, output order and fee. Attached content must match the message the wallet approved. Use the general SignedData verifier for supported attribute and multisigner signatures. Certificate trust and revocation assessment depend on application trust anchors, policies and evidence.

[Wallet signature and trust boundary](../reference/README.md#signeddata-payment-interop) · [SignedData acceptance and PKI scope](../reference/signed-data-acceptance.md)

<a name="validation"></a>

## Validation and measurements

The release lock is 144,925 bytes and the ordinary ForkID unlock is 291 bytes. The two-input, two-output benchmark measures 290,554 bytes under ForkID ALL and 870,194 under OTDA ALL, where each input carries the serialized outputs. The acceptance record separates the payment adapter, general verification, PKI evaluation and the historical Annex A.1 replay.

Use Python 3.12, OpenSSL with SM2/SM3 and Rust. Install the pinned [requirements](../reference/requirements.txt) and run `bash projects/p2pkh-sm2/reference/verify.sh`. [Standard and payment vectors](../template/) · [Node replay](../reference/README.md) · [Project measurements](../README.md#complete-transactions-and-stack-measurements)

<a name="sdk"></a>

## SDK and reference interfaces

Follow the [unified SM2 wallet guide](../sdk/README.md) to create or recognize the lock and sign a transaction. Connect a signer that accepts the supplied message and SM2 user ID, and choose raw signature or DER SignedData. The Rust and Python command-line providers are public fixture signers.

[Reference wallet](../reference/p2pkh_sm2.py) · [SignedData adapter and example](../reference/README.md#signeddata-payment-interop) · [Rust test signer](../reference/interop/rust-signer/README.md) · [Python test signer](../reference/interop/python-signer/README.md)
