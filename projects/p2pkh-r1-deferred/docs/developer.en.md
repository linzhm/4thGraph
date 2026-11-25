# P2PKH-R1-Deferred developer guide

[简体中文](developer.zh-CN.md) · [Project overview](../README.md)

A short funding output commits to creating an equal-value P2PKH-R1 output during activation. New funding targets R1 v0.2.0.

[Protocol specification](#protocol) · [Security analysis](#security) · [Validation and measurements](#validation) · [SDK and reference interfaces](#sdk)

<a name="protocol"></a>

## Protocol specification

The short lock carries the recipient hash, target script SHA-256, value and the HASH256 of the complete target output. The activation input requires the committed, equal-value output at the same index. The direct ForkID SINGLE witness is 160 bytes. The other ten sighash modes use a 197-byte two-check witness that also carries the selected mode's digest commitment. The full R1 target is serialized in the transaction output. Later spends use the ordinary R1 lock and signer.

A v0.1.0 short lock activates to its original v0.1.0 target. Recognize the funding bytes with their committed target version before construction. [Specification](spec.en.md) · [v0.2.0 layout](../template/v0.2.0/layout.json) · [Legacy layout](../template/layout.json)

<a name="security"></a>

## Security analysis

Anyone can arrange and fund activation. The mandatory output commitment controls where the full value goes, and the recipient's P-256 key controls later spending. Verify both target hashes, the actual funding value and the expected recipient hash. A sponsor approves and signs its own input. Fix matched input/output indices before preparing the transaction and track the confirmed activation outpoint.

For existing funding, derive the target from the authenticated commitment. Using a different R1 version for the same owner changes both target hashes. [Activation rules](spec.en.md#spending-the-short-lock) · [Consensus context](chronicle.md)

<a name="validation"></a>

## Validation and measurements

The matrix has 2,592 node cases across both target versions, both funding layouts and all twelve modes. A mixed-version batch also activates both matching targets. The short lock is 1,435 bytes. A three-input, two-output ForkID ALL activation measures 93,259 bytes in the v0.2.0 benchmark. An added activation pair includes a short-lock input and its required R1 output.

Install the pinned [requirements](../reference/requirements.txt) and run `bash projects/p2pkh-r1-deferred/reference/verify.sh test_deferred`. [Acceptance matrix](../reference/acceptance.md) · [Twelve-mode vectors](../template/v0.2.0/sighash-modes.json) · [Marginals and lifecycle](../README.md#measured-transaction-costs)

<a name="sdk"></a>

## SDK and reference interfaces

Use the [unified wallet API](sdk.en.md#unified-wallet-api) to create and recognize the amount-bearing short lock. Call `activate` on an assembled transaction that puts the originally committed R1 output at the input's index. Sign sponsor inputs separately and use the ordinary R1 wallet API for subsequent spends.

[SDK guide and test commands](sdk.en.md) · [Python reference](../reference/README.md)
