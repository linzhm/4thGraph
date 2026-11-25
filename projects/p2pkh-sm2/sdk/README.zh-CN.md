# P2PKH-SM2 SDK

[English](README.md) · [项目开发指南](../docs/developer.zh-CN.md#sdk)

v1.0.0 锁以 65 字节未压缩 SM2 公钥或 20 字节收款哈希创建。回调接收 32 字节交易消息和模板规定的 SM2 用户标识，默认返回 64 字节原始签名。使用 GB/T 35275-2026 SignedData 提供方时，将 `signerIdentifier` 设为固定的 DER 颁发者与序列号十六进制字节。

先安装[本地调用依赖](requirements.txt)，在仓库根目录运行 `python -m pip install -r projects/p2pkh-sm2/sdk/requirements.txt`。

| 语言 | 源码与入口 |
|---|---|
| TypeScript | [index.ts](typescript/index.ts) · `createClient` |
| Rust | [Cargo.toml](rust/Cargo.toml) · `bsv_script_lab_sm2_sdk::client` |
| Go | [go.mod](go/go.mod) · `New` |
| Python | [客户端入口](python/__init__.py) · `create_client` |

[共用钱包工作流与配置](../../../shared/sdk/README.zh-CN.md)

Chronicle 激活后，可用 TypeScript 的 `compressOtda`、Go 的 `CompressOTDA`、Rust 和 Python 的 `compress_otda` 启用重建，同时把对应的 Chronicle 激活参数设为真。适用于版本 2 的 OTDA ALL 和配对 SINGLE，支持原始签名和 SignedData 回调。SDK 会在重建更短时选用构造器。[适用条件与实测成本](../README.zh-CN.md#otda-constructor)

在仓库根目录设置项目参考环境后运行 `bash shared/verify_node.sh -- bash shared/sdk/verify.sh p2pkh-sm2`。
