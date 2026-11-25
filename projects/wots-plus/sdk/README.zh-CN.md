# WOTS+ SDK

[English](README.md) · [项目开发指南](../docs/developer.zh-CN.md#sdk)

可选 `canonical`、`cached-constants` 或 `cached-steps`。根据预期的 64 字节公钥核对付款锁，签名器对传入摘要返回一份 2,144 字节签名。调用方须持久保存一次性密钥占用记录。Chronicle 已激活且交易版本为 2 时，可用 `compressOtda` 让参考钱包为符合条件的输入选择紧凑解锁。

| 语言 | 源码与入口 |
|---|---|
| TypeScript | [index.ts](typescript/index.ts) · `createClient` |
| Rust | [Cargo.toml](rust/Cargo.toml) · `bsv_script_lab_wots_sdk::client` |
| Go | [go.mod](go/go.mod) · `New` |
| Python | [客户端入口](python/__init__.py) · `create_client` |

[共用钱包工作流与配置](../../../shared/sdk/README.zh-CN.md)

在仓库根目录设置项目参考环境后运行 `bash shared/verify_node.sh -- bash shared/sdk/verify.sh wots-plus`。
