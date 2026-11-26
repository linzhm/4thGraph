# P2PKH-R1

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md)

P2PKH-R1 lets a BSV wallet use an existing P-256 signer. The output commits to the recipient's public-key HASH160. A spend supplies the uncompressed public key and a 64-byte ECDSA signature in `r || s` format.

**[Wallet SDK quickstart](docs/sdk.en.md#quickstart)** · [Protocol](docs/spec.en.md) · [Security](docs/developer.en.md#security) · [Verification](reference/acceptance.md)

<a name="version-history"></a>
<a name="complete-transactions-and-stack-measurements"></a>
<a name="forth-experiment"></a>

## Measured results

The reference wallet uses **v0.2.0** for new outputs and can spend existing v0.1.0 outputs. The Forth experiments reached **41,538 B** for the lock and **91,692 B** for an OTDA ALL payment, with different constructions winning each objective. Payment sizes use two R1 inputs and two R1 outputs.

| Template | Lock | BIP143 ALL payment | OTDA ALL payment |
| --- | ---: | ---: | ---: |
| Wallet default v0.2.0 | 46,302 B | 93,374 B | 101,250 B |
| Forth experiment, 4-bit split tables with affine `G` | **41,538 B** | **83,846 B** | 92,032 B |
| Forth experiment, 2-bit joint table | 42,378 B | 85,526 B | **91,692 B** |

Both experimental winners completed BIP143 ALL, OTDA ALL, and paired OTDA SINGLE payments on BSV Node regtest and passed independent chain-gang verification. [Build and replay](experiments/forth/README.md) · [Historical measurements](experiments/forth/history.md)

## Wallet integration

Use the unified SDK in TypeScript, Rust, Go, or Python. For an existing P-256 signer, confirm its digest interface and signature encoding, and persist nonce-reuse history across signing processes. [SDK guide](docs/sdk.en.md) · [Reference wallet](reference/README.md) · [Wallet template](template/v0.2.0/layout.json)

R1 creates the full lock at funding so the recipient can pay in one spend. Deferred R1 uses a smaller deposit lock and a separate activation transaction. [Deferred workflow](../p2pkh-r1-deferred/README.md)
