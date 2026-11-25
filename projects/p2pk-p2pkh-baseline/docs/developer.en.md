# Native P2PK and P2PKH developer guide

[简体中文](developer.zh-CN.md) · [Project overview](../README.md)

Reference fixtures for standard Script payments and native signature behavior across test contexts.

[Protocol specification](#protocol) · [Security analysis](#security) · [Validation and measurements](#validation) · [SDK and reference interfaces](#sdk)

<a name="protocol"></a>

## Protocol specification

P2PK embeds the compressed public key and spends with a signature. P2PKH embeds its 20-byte HASH160 and spends with a signature and the matching public key. The signature carries the sighash selector. These native locks are the baseline for cost and compatibility comparisons against the other projects.

[Wire examples and fixture contract](../README.md#fixture-contract) · [Signed fixtures](../template/baseline.json) · [Coverage rules](../reference/acceptance.md)

<a name="security"></a>

## Security analysis

Use a wallet's existing secp256k1 signer with an authenticated funding outpoint, value and lock. For P2PKH, match the supplied key hash to the recipient. Check which outputs and inputs the selected sighash commits to, and use the funding confirmation policy of the integrating application. The committed vectors use public test keys and synthetic prevouts.

[Native acceptance decisions](../reference/acceptance.md) · [Examples and scope](../README.md#node-cross-check)

<a name="validation"></a>

## Validation and measurements

The declared native coverage includes 2,880 combinations, 80 unpaired SINGLE mutation checks and 192 activation-boundary cases. In the ForkID ALL 2×2 fixture, P2PK measures 326 bytes and P2PKH measures 374 bytes. Moving from P2PK to P2PKH saves 10 bytes per output script and adds about 34 bytes per input witness, subject to DER signature length.

Run the [offline reproduction command](../README.md#run) or use the [unified benchmark](../../../shared/benchmark.md) with `--project p2pk-p2pkh-baseline`. The default fixture runner and acceptance suite use the same repository pin documented in the project README.

<a name="sdk"></a>

## SDK and reference interfaces

Use the [Python fixture generator](../reference/script_lab.py) as a serialization and verification example. An application uses its own wallet and native signing stack for real transactions. The [fixture JSON](../template/baseline.json) gives complete parent and spend bytes, scripts and expected results for comparing application output.

[Project run guide](../README.md#run) · [Pinned dependency guidance](../../../shared/benchmark.md)
