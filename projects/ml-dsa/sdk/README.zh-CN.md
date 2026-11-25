# 纯模式 ML-DSA-44 SDK

[English](README.md) · [项目开发指南](../docs/developer.zh-CN.md#sdk)

通过预期的 1,312 字节公钥创建或识别 `pure-ml-dsa-44`。对传入的 32 字节消息直接使用空上下文的 Pure ML-DSA-44 签名，回调返回 2,420 字节签名。SDK 先核验签名再组装付款。

| 语言 | 源码与入口 |
|---|---|
| TypeScript | [index.ts](typescript/index.ts) · `createClient` |
| Rust | [Cargo.toml](rust/Cargo.toml) · `bsv_script_lab_mldsa_sdk::client` |
| Go | [go.mod](go/go.mod) · `New` |
| Python | [客户端入口](python/__init__.py) · `create_client` |

[共用钱包工作流与配置](../../../shared/sdk/README.zh-CN.md)

在仓库根目录设置项目参考环境后运行 `bash shared/verify_node.sh -- bash shared/sdk/verify.sh ml-dsa`。
