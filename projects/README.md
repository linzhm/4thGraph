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

Run `bash tools/setup-workspaces.sh` from the repository root to create Git-ignored build, cache, and log directories in each project’s `workspace/`. The project homepage leads to its protocol and integration guide. Reference code, build entry points and test runners live with the project. [Install 4thGraph](../docs/install.md) · [Shared wallet SDK](../sdk/README.md) · [Showcase](../showcase/README.md)

## Project README template

Generate the English and Chinese introductions with the shared template. The tool creates missing READMEs and preserves existing files. It uses the current version manifest for build and verify commands and adds links to available project docs and measurements.

```sh
python3 tools/project_readme.py my-project --title "My project" --title-zh "我的项目"
```

Fill the prompts with the project’s algorithm, entry points, reproducible commands and measured results. Adapt the measurement sections to the project. Run `python3 tools/project_readme.py my-project --check` to check that both files exist and that the prompts have been filled or removed. [English template](../tools/templates/project-readme/README.md.in) · [Chinese template](../tools/templates/project-readme/README.zh-CN.md.in) · [Filled Schnorr example](p2pkh-schnorr/README.md)

## Versioned project data

`versions/index.json` lists each project's versions in order. `current` selects the current version and `next` identifies the next round when its data is available. `sdk_default` records the wallet template version when the SDK uses a versioned selector.

Each `versions/vX.Y.Z/manifest.json` points to the previous version, lists its compiled artifacts, public fixtures and measurements, and gives the integration guide and commands to build and verify from the repository root. Artifact, fixture and evidence paths are relative to the version directory. Integration and optional `shared_data` paths are relative to the project. `shared_data` points to identical data in earlier versions. Optional `requires` names another project's exact version.

For the next round, use the current version as the comparison baseline. Save the selected lock, corresponding reconstruction, fixtures and replay results in the new version directory. Update the index and homepage when that round is selected. Projects use the repository's existing baseline as their first version when they have no prior version number. Run `PYTHONPATH=src:. python -m unittest discover -s tests -p test_layout.py` to check the version catalog and links. [P2PKH-R1 version index](p2pkh-r1/versions/index.json) · [v0.7.0 build and replay](p2pkh-r1/versions/v0.7.0/manifest.json)
