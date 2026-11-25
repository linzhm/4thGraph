# WOTS+ SDK

[简体中文](README.zh-CN.md) · [Developer guide](../docs/developer.en.md#sdk)

Select `canonical`, `cached-constants` or `cached-steps`. The SDK recognizes the payment lock against the expected 64-byte public key. The callback returns one 2,144-byte signature over the supplied digest. Use a durable one-time key record. With Chronicle active and a version 2 transaction, `compressOtda` permits the reference wallet to select an eligible compact witness.

| Language | Source and entry point |
|---|---|
| TypeScript | [index.ts](typescript/index.ts) · `createClient` |
| Rust | [Cargo.toml](rust/Cargo.toml) · `bsv_script_lab_wots_sdk::client` |
| Go | [go.mod](go/go.mod) · `New` |
| Python | [Client entry](python/__init__.py) · `create_client` |

[Common wallet workflow and configuration](../../../shared/sdk/README.md)

Activate the project reference environment and run `bash shared/verify_node.sh -- bash shared/sdk/verify.sh wots-plus` from the repository root.
