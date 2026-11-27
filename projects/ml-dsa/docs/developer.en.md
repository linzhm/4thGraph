# Pure ML-DSA-44 developer guide

[简体中文](developer.zh-CN.md) · [Project overview](../README.md)

FIPS 204 pure-mode signature verification, with a separate BSV payment wrapper that binds the authorization to a spending input.

[Protocol specification](#protocol) · [Security analysis](#security) · [Validation and measurements](#validation) · [SDK and reference interfaces](#sdk)

<a name="protocol"></a>

## Protocol specification

The public key is 1,312 bytes and the signature is 2,420 bytes. The detached verifier uses a caller-supplied message and the configured context. A payment signs the 32-byte transaction authorization as the message, using the empty context. The lock accounts for the FIPS 204 response bounds, hint encoding and Appendix C sampling budget, as well as BSV input binding.

[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) · [Verification and payment entry points](../README.md) · [Transaction authorization](../reference/payment.py)

<a name="security"></a>

## Security analysis

Bind the expected public key to the authenticated funding outpoint and regenerate its fixed-key lock for comparison. Keep the payment signer's context empty and pass the supplied 32-byte message to the pure-mode implementation. Keep production key management outside the fixture code. Signing-mode coverage and the chain's authorization binding are separate from FIPS signature conformance.

The large lock warrants explicit admission-policy verification in the intended environment. The present unified measurements use the documented script-test node profile. [Payment acceptance](../reference/payment-acceptance.md) · [Regtest admission method](../../../docs/benchmark.md#funded-regtest-measurements)

<a name="validation"></a>

## Validation and measurements

The payment acceptance domain has 640 rows. Cross-checks include 80 Wycheproof cases and 15 external NIST ACVP pure-mode vectors. The deterministic v0.9.0 lock is 272,993 bytes, and compiled sizes vary slightly by public key. A two-input, two-output OTDA ALL payment measures 1,643,154 bytes. The development evaluator lacks the comparison opcodes needed for ML-DSA stack measurements. [Script and transaction sizes](../README.md#script-sizes)

Use Python 3.12 and OpenSSL 3.5 or later. See the [project replay commands](../README.md#reproduce-the-checks), [deterministic fixture](../versions/v0.1.0/deterministic.json), and [payment matrix](../reference/payment-acceptance.md).

<a name="sdk"></a>

## SDK and reference interfaces

Follow the [unified ML-DSA wallet guide](sdk.en.md) to create outputs and sign a payment or a prepared input. The external signer applies Pure ML-DSA-44 to the requested 32-byte message with an empty context and returns the raw 2,420-byte signature.

[Wallet source](../reference/payment.py) · [Signature and fixture interfaces](../reference/mldsa.py) · [Script compiler](../reference/script.py)
