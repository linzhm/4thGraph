# Lamport OTS developer guide

[简体中文](developer.zh-CN.md) · [Project overview](../README.md)

A SHA-256 one-time signature bound to a BSV transaction input. The full-key and committed-key formats have different input and output costs.

[Protocol specification](#protocol) · [Security analysis](#security) · [Validation and measurements](#validation) · [SDK and reference interfaces](#sdk)

<a name="protocol"></a>

## Protocol specification

The ordered key has 256 pairs of commitments. A signature supplies the selected 32-byte secret for each digest bit, totaling 8,192 bytes. The full-key payment lock includes all public commitments. The smaller committed-key lock instead commits to the ordered public key and uses the missing hashes from the unlocking proof. Both bind the digest to the actual input in their documented payment formats.

[Wire and Script specification](spec.md) · [Template measurements](../template/measurement.json) · [Mode vectors](../template/universal-vectors.json)

<a name="security"></a>

## Security analysis

Reserve one fresh key for one UTXO, including change. Consume the key durably before returning the first signature. Restarts, backup restores and fee replacements must preserve that record. Rebroadcast the saved signed transaction for a retry. The wallet keeps the full ordered public key for the committed-key proof and checks the funding outpoint and confirmation before signing. Use the transaction-bound template for funds.

The default wallet rejects an unpaired SINGLE because it commits to no outputs. An explicit policy exception uses `allow_unpaired_single=True` on `sign_spend`. [Security model, recovery and limitations](security.md)

<a name="validation"></a>

## Validation and measurements

The acceptance matrix covers 408 authorization decisions for the declared payment domain. The full-key and committed-key ForkID ALL 2×2 fixtures are 62,392 and 48,708 bytes. The smaller funding lock shifts cost into spending. In the same fixture, a new input increases from 8,400 to 16,592 bytes while a new output drops from 22,791 to 7,757 bytes.

Install the pinned [requirements](../reference/requirements.txt) and run `bash projects/lamport-ots/reference/verify.sh`. [Acceptance domain](acceptance.md) · [Test and measurement record](validation.md) · [Project cost analysis](../README.md)

<a name="sdk"></a>

## SDK and reference interfaces

Integrate through the Python reference. Create a payment lock with `locking_script` or `committed_locking_script`, then call `sign_payment` or `sign_spend` with the authenticated funding and an external callback. The callback receives a 32-byte digest and returns the 8,192-byte raw signature. Integrators supply durable key storage, the spend policy and broadcasting.

[Reference developer workflow](../reference/README.md) · [Payment source](../reference/payment.py) · [Original funding and spend vector](../template/vector.json)
