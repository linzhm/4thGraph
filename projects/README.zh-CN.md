# 4thGraph 项目

[English](README.md) · [4thGraph](../README.zh-CN.md) · [文档](../docs/README.zh-CN.md)

## 合约与证明

| 项目 | 构建与验证 |
| --- | --- |
| [PELS 计数器](pels-counter/README.zh-CN.md) | 编译状态转换并复放逐笔递增的合约 |
| [交易工作流](workflow-examples/README.zh-CN.md) | 比较并行、汇合和串行的交易计划，包含 Gforth 示例 |
| [证明计数器](proof-counter/README.zh-CN.md) | 用 Script、Circom 或证明后端构建同一个公开状态转换 |

## 付款与签名方案

| 项目 | 构建与验证 | 钱包接入 |
| --- | --- | --- |
| [原生 P2PK 与 P2PKH](p2pk-p2pkh-baseline/README.zh-CN.md) | 构建付款锁并复放基准交易 | [secp256k1](p2pk-p2pkh-baseline/docs/sdk.zh-CN.md#quickstart) |
| [P2PKH-R1](p2pkh-r1/README.zh-CN.md) | 对照 P-256 参考锁与 Forth 编译版 | [P-256 设备签名器](p2pkh-r1/docs/sdk.zh-CN.md#quickstart) |
| [P2PKH-R1-Deferred](p2pkh-r1-deferred/README.zh-CN.md) | 在入金之后启用 P-256 锁 | [启用与付款](p2pkh-r1-deferred/docs/sdk.zh-CN.md#quickstart) |
| [P2PKH-Schnorr](p2pkh-schnorr/README.zh-CN.md) | 构建并测试 BIP340 锁 | [BIP340 与 MuSig2](p2pkh-schnorr/docs/sdk.zh-CN.md#quickstart) |
| [P2PKH-SM2](p2pkh-sm2/README.zh-CN.md) | 验证 SM2 签名和 SignedData | [SM2 签名器](p2pkh-sm2/docs/sdk.zh-CN.md#quickstart) |
| [Lamport OTS](lamport-ots/README.zh-CN.md) | 比较完整公钥锁和公钥承诺锁 | [一次性签名器](lamport-ots/docs/sdk.zh-CN.md#quickstart) |
| [WOTS+](wots-plus/README.zh-CN.md) | 对照 Winternitz 见证与锁定模板 | [一次性签名器](wots-plus/docs/sdk.zh-CN.md#quickstart) |
| [纯模式 ML-DSA-44](ml-dsa/README.zh-CN.md) | 复放纯模式 ML-DSA-44 花费 | [FIPS 204 签名器](ml-dsa/docs/sdk.zh-CN.md#quickstart) |

## 项目工作区

从仓库根目录执行 `bash tools/setup-workspaces.sh`，在每个项目的 `workspace/` 下创建 Git 忽略的构建、缓存和日志目录。参考实现、固定交易向量和对照实验放在对应项目。选取可复现的记录随项目保存，并从成果页链接。[安装 4thGraph](../docs/install.md) · [共享钱包 SDK](../sdk/README.zh-CN.md) · [项目成果](../showcase/README.md)
