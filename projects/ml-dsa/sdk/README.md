# Pure ML-DSA-44 SDK

[简体中文](README.zh-CN.md) · [Developer guide](../docs/developer.en.md#sdk)

Create or recognize `pure-ml-dsa-44` from the expected 1,312-byte public key. The callback applies Pure ML-DSA-44 with an empty context directly to the supplied 32-byte message and returns a 2,420-byte signature. The SDK verifies it before assembling the payment.

| Language | Source and entry point |
|---|---|
| TypeScript | [index.ts](typescript/index.ts) · `createClient` |
| Rust | [Cargo.toml](rust/Cargo.toml) · `bsv_script_lab_mldsa_sdk::client` |
| Go | [go.mod](go/go.mod) · `New` |
| Python | [Client entry](python/__init__.py) · `create_client` |

[Common wallet workflow and configuration](../../../shared/sdk/README.md)

Activate the project reference environment and run `bash shared/verify_node.sh -- bash shared/sdk/verify.sh ml-dsa` from the repository root.
