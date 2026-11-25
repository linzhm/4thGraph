# P2PKH-SM2 SDK

[简体中文](README.zh-CN.md) · [Developer guide](../docs/developer.en.md#sdk)

The v1.0.0 lock accepts a 65-byte uncompressed SM2 key or a 20-byte owner hash. The callback receives the 32-byte transaction message and the template SM2 user ID. By default it returns the raw 64-byte SM2 signature. Set `signerIdentifier` to the pinned DER issuer-and-serial hex to use a GB/T 35275-2026 SignedData provider instead.

Install the [Python bridge dependencies](requirements.txt) with `python -m pip install -r projects/p2pkh-sm2/sdk/requirements.txt`.

| Language | Source and entry point |
|---|---|
| TypeScript | [index.ts](typescript/index.ts) · `createClient` |
| Rust | [Cargo.toml](rust/Cargo.toml) · `bsv_script_lab_sm2_sdk::client` |
| Go | [go.mod](go/go.mod) · `New` |
| Python | [Client entry](python/__init__.py) · `create_client` |

[Common wallet workflow and configuration](../../../shared/sdk/README.md)

After Chronicle activates, set `compressOtda` in TypeScript, `CompressOTDA` in Go, or `compress_otda` in Rust and Python, together with the corresponding Chronicle activation option. This applies to version-2 OTDA ALL and paired SINGLE spends and works with raw signature and SignedData callbacks. The SDK uses the constructor when reconstruction is shorter. [Eligibility and measured costs](../README.md#otda-constructor)

Activate the project reference environment and run `bash shared/verify_node.sh -- bash shared/sdk/verify.sh p2pkh-sm2` from the repository root.
