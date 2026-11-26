# 4thGraph Wallet SDK

[简体中文](README.zh-CN.md) · [4thGraph](../README.md)

Create and recognize BSV locking scripts, request a signature from your signer, and assemble signed transaction bytes. The TypeScript, Rust, Go, and Python clients all use the local Python bridge and payment templates from this checkout.

**[Run the offline example](#quickstart)** · [Integrate a wallet](docs/integration.md) · [API reference](docs/reference.md) · [Choose a signing scheme](#scheme-integrations)

<a name="quickstart"></a>

## Run the offline example

From the repository root, use Python 3.12 to create a local environment and sign a native P2PKH payment with a public test key.

```sh
python3.12 -m venv workspace/sdk-venv
workspace/sdk-venv/bin/python -m pip install -r projects/p2pk-p2pkh-baseline/reference/requirements-sdk.txt ecdsa==0.19.1
PYTHONPATH=src:. workspace/sdk-venv/bin/python -m sdk.examples.receive_and_pay
```

Expect template `p2pkh`, a 25-byte locking script, and a transaction ID. The example spends a synthetic output offline. [Example source](examples/receive_and_pay.py)

<a name="wallet-workflow"></a><a name="use-the-sdk-from-a-wallet-repository"></a><a name="prepared-payments"></a>

[Configure your language binding](docs/integration.md#bridge-setup) · [Sign a prepared transaction](docs/integration.md#prepared-payments)

<a name="scheme-integrations"></a>

## Choose a signing scheme

| Project | Signing request | Select this guide |
| --- | --- | --- |
| Native P2PK and P2PKH | secp256k1 digest, low-S DER | [Native SDK](../projects/p2pk-p2pkh-baseline/docs/sdk.en.md#quickstart) |
| P2PKH-R1 | P-256 digest or device-hashed message, 64-byte `r ∥ s` | [R1 SDK](../projects/p2pkh-r1/docs/sdk.en.md#quickstart) |
| P2PKH-R1-Deferred | Activation builds the unlocking script from the committed R1 output | [Deferred SDK](../projects/p2pkh-r1-deferred/docs/sdk.en.md#quickstart) |
| P2PKH-SM2 | SM2 message and user ID, 64-byte `r ∥ s` or DER SignedData | [SM2 SDK](../projects/p2pkh-sm2/docs/sdk.en.md#quickstart) |
| P2PKH-Schnorr | 32-byte BSV transaction message, 64-byte BIP340 signature | [Schnorr SDK](../projects/p2pkh-schnorr/docs/sdk.en.md#quickstart) |
| Lamport OTS | 32-byte digest, 8,192-byte signature | [Lamport SDK](../projects/lamport-ots/docs/sdk.en.md#quickstart) |
| WOTS+ | 32-byte digest, 2,144-byte signature | [WOTS+ SDK](../projects/wots-plus/docs/sdk.en.md#quickstart) |
| Pure ML-DSA-44 | 32-byte message with empty context, 2,420-byte signature | [ML-DSA SDK](../projects/ml-dsa/docs/sdk.en.md#quickstart) |

<a name="calls-and-data"></a><a name="调用与数据"></a><a name="one-time-signing"></a><a name="troubleshooting"></a><a name="replay-the-baseline"></a>

[Calls and data formats](docs/reference.md#calls-and-data) · [One-time signing](docs/reference.md#one-time-signing) · [Troubleshooting](docs/reference.md#troubleshooting) · [Replay across all four clients](docs/reference.md#replay)
