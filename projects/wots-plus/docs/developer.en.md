# WOTS+ developer guide

[简体中文](developer.zh-CN.md) · [Project overview](../README.md)

A SHA-256 one-time signature bound to a BSV transaction input, with optional stack caching and OTDA output reconstruction.

[Protocol specification](#protocol) · [Security analysis](#security) · [Validation and measurements](#validation) · [SDK and reference interfaces](#sdk)

<a name="protocol"></a>

## Protocol specification

The verifier uses the RFC 8391 `WOTSP-SHA2_256` chains with a BSV-specific 64-byte public key and 2,144-byte signature. The transaction-bound lock checks both the hash-chain proof and the selected input's authorization. It supports the twelve ForkID and Chronicle OTDA modes. Cached-step outputs can be reconstructed inside an eligible version 2 OTDA ALL or paired SINGLE witness.

[Wire and Script specification](spec.md) · [RFC 8391](https://www.rfc-editor.org/rfc/rfc8391) · [Cached-step artifact layout](../template/cached-steps-layout.json)

<a name="security"></a>

## Security analysis

Allocate and consume one key per UTXO. The signer must persist consumption before releasing the signature, including concurrent requests and failures after signing. Retain the signed transaction for safe retries. Use a fresh key for change and retire keys with uncertain state after a backup restore. Use the transaction-bound template when receiving funds.

Verify the funding outpoint and intended outputs before authorizing a signing mode. Select functional unlocking only in a supported Chronicle context. The [payment rules](spec.md#payment-authorization) cover unpaired SINGLE and [one-time key lifecycle](spec.md#key-lifecycle-and-validation-scope) covers persistence and scope.

<a name="validation"></a>

## Validation and measurements

The payment suite defines 1,230 rows per measured layout and checks all 67 signature-chain positions in complete inputs. The cached-step lock is 33,956 bytes. The OTDA ALL 2×2 example falls from 208,406 to 79,090 bytes with reconstruction. Paired SINGLE falls from 140,473 to 78,921 bytes while its measured two-stack payload peak stays at 70,280 bytes.

Install the pinned [requirements](../reference/requirements.txt) and run `bash projects/wots-plus/reference/verify.sh`. The [validation record](validation.md) includes BSV Node, chain-gang and the separate Lean checks. [Payment vectors](../template/vectors.json) · [Project cost analysis](../README.md)

<a name="sdk"></a>

## SDK and reference interfaces

[TypeScript, Rust, Go and Python source SDKs](../sdk/README.md)

Use the Python reference `locking_script` to create a payment output and `sign_payment` or `sign_spend` to assemble a signed input. The external callback receives a 32-byte digest and returns a 2,144-byte signature. The reference wallet's `compress_otda=True` option selects an eligible compact witness. The signing service handles key consumption and the integrating wallet approves and broadcasts the transaction.

[Payment source](../reference/payment.py) · [One-time signer interface](../reference/wots.py) · [Durable benchmark signer](../../../shared/one_time_signer.py)
