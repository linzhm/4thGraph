# Native P2PK and P2PKH SDK

[简体中文](README.zh-CN.md) · [Developer guide](../docs/developer.en.md#sdk)

Create `p2pkh` outputs by default or select `p2pk`. Both use compressed secp256k1 public keys. `lockForOwner` creates P2PKH from HASH160. The callback receives a 32-byte digest and returns a low-S DER signature. The SDK adds the sighash byte. SINGLE requires a same-index output in the SDK.

Install the [Python bridge dependencies](requirements.txt) with `python -m pip install -r projects/p2pk-p2pkh-baseline/sdk/requirements.txt`.

| Language | Source and entry point |
|---|---|
| TypeScript | [index.ts](typescript/index.ts) · `createClient` |
| Rust | [Cargo.toml](rust/Cargo.toml) · `bsv_script_lab_native_sdk::client` |
| Go | [go.mod](go/go.mod) · `New` |
| Python | [Client entry](python/__init__.py) · `create_client` |

[Common wallet workflow and configuration](../../../shared/sdk/README.md)

Activate the project reference environment and run `bash shared/verify_node.sh -- bash shared/sdk/verify.sh p2pk-p2pkh-baseline` from the repository root.
