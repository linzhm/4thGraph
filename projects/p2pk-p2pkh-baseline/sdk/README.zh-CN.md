# 原生 P2PK 与 P2PKH SDK

[English](README.md) · [项目开发指南](../docs/developer.zh-CN.md#sdk)

默认创建 `p2pkh`，也可选 `p2pk`。使用压缩 secp256k1 公钥。通过 `lockForOwner` 可直接填入 HASH160 创建 P2PKH。回调接收 32 字节摘要并返回低 S 的 DER 签名，SDK 添加签名类型字节。SDK 的 SINGLE 要求同索引输出存在。

先安装[本地调用依赖](requirements.txt)，在仓库根目录运行 `python -m pip install -r projects/p2pk-p2pkh-baseline/sdk/requirements.txt`。

| 语言 | 源码与入口 |
|---|---|
| TypeScript | [index.ts](typescript/index.ts) · `createClient` |
| Rust | [Cargo.toml](rust/Cargo.toml) · `bsv_script_lab_native_sdk::client` |
| Go | [go.mod](go/go.mod) · `New` |
| Python | [客户端入口](python/__init__.py) · `create_client` |

[共用钱包工作流与配置](../../../shared/sdk/README.zh-CN.md)

在仓库根目录设置项目参考环境后运行 `bash shared/verify_node.sh -- bash shared/sdk/verify.sh p2pk-p2pkh-baseline`。
