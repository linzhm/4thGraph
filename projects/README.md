# 4thGraph projects

[简体中文](README.zh-CN.md) · [4thGraph](../README.md) · [Documentation](../docs/README.md)

## Contracts and proofs

| Project | Build and verify |
| --- | --- |
| [PELS Counter](pels-counter/README.md) | Compile a state transition and replay an incrementing covenant |
| [Transaction workflows](workflow-examples/README.md) | Compare parallel, joined, and serial transaction plans, including Gforth input |
| [Proof counter](proof-counter/README.md) | Build a public state transition with Script, Circom, or a proof backend |

## Payments and signing schemes

| Project | Build and verify | Wallet integration |
| --- | --- | --- |
| [Native P2PK and P2PKH](p2pk-p2pkh-baseline/README.md) | Compile payment locks and replay baseline transactions | [secp256k1](p2pk-p2pkh-baseline/docs/sdk.en.md#quickstart) |
| [P2PKH-R1](p2pkh-r1/README.md) | Compare the reference P-256 lock with its Forth build | [P-256 device signer](p2pkh-r1/docs/sdk.en.md#quickstart) |
| [P2PKH-R1-Deferred](p2pkh-r1-deferred/README.md) | Activate a P-256 lock after funding | [Activation and payment](p2pkh-r1-deferred/docs/sdk.en.md#quickstart) |
| [P2PKH-Schnorr](p2pkh-schnorr/README.md) | Build and test a BIP340 lock | [BIP340 and MuSig2](p2pkh-schnorr/docs/sdk.en.md#quickstart) |
| [P2PKH-SM2](p2pkh-sm2/README.md) | Verify SM2 signatures and SignedData | [SM2 signer](p2pkh-sm2/docs/sdk.en.md#quickstart) |
| [Lamport OTS](lamport-ots/README.md) | Compare full-key and committed-key locks | [One-time signer](lamport-ots/docs/sdk.en.md#quickstart) |
| [WOTS+](wots-plus/README.md) | Compare Winternitz witness and lock layouts | [One-time signer](wots-plus/docs/sdk.en.md#quickstart) |
| [Pure ML-DSA-44](ml-dsa/README.md) | Replay a Pure ML-DSA-44 spend | [FIPS 204 signer](ml-dsa/docs/sdk.en.md#quickstart) |

## Project workspaces

Run `bash tools/setup-workspaces.sh` from the repository root to create Git-ignored build, cache, and log directories in each project’s `workspace/`. Keep reference implementations, fixed transaction vectors, and comparison experiments with the project. Store selected replay records there and link them from the showcase. [Install 4thGraph](../docs/install.md) · [Shared wallet SDK](../sdk/README.md) · [Showcase](../showcase/README.md)
