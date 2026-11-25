# Lamport OTS SDK

[简体中文](README.zh-CN.md) · [Developer guide](../docs/developer.en.md#sdk)

Select `full-key` (default) or `committed-key`. Recognition requires the expected full ordered public key, including when reading the legacy lock. The callback receives a 32-byte digest and returns an 8,192-byte signature. Use a durable one-time key record and keep the signed transaction for retries. The SDK follows the reference policy requiring a paired output for SINGLE.

| Language | Source and entry point |
|---|---|
| TypeScript | [index.ts](typescript/index.ts) · `createClient` |
| Rust | [Cargo.toml](rust/Cargo.toml) · `bsv_script_lab_lamport_sdk::client` |
| Go | [go.mod](go/go.mod) · `New` |
| Python | [Client entry](python/__init__.py) · `create_client` |

[Common wallet workflow and configuration](../../../shared/sdk/README.md)

Activate the project reference environment and run `bash shared/verify_node.sh -- bash shared/sdk/verify.sh lamport-ots` from the repository root.
