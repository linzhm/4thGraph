# Lamport OTS SDK

[English](README.md) · [项目开发指南](../docs/developer.zh-CN.md#sdk)

可选默认的 `full-key` 或 `committed-key`。识别时提供预期的完整有序公钥，旧锁也按该公钥核对。回调接收 32 字节摘要，返回 8,192 字节签名。调用方须持久化一次性密钥占用记录，并保存已签交易以便重播。SDK 沿用参考钱包策略，SINGLE 要求配对输出。

| 语言 | 源码与入口 |
|---|---|
| TypeScript | [index.ts](typescript/index.ts) · `createClient` |
| Rust | [Cargo.toml](rust/Cargo.toml) · `bsv_script_lab_lamport_sdk::client` |
| Go | [go.mod](go/go.mod) · `New` |
| Python | [客户端入口](python/__init__.py) · `create_client` |

[共用钱包工作流与配置](../../../shared/sdk/README.zh-CN.md)

在仓库根目录设置项目参考环境后运行 `bash shared/verify_node.sh -- bash shared/sdk/verify.sh lamport-ots`。
