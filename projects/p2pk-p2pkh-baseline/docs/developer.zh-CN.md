# 原生 P2PK 与 P2PKH 开发指南

[English](developer.en.md) · [项目概览](../README.zh-CN.md)

原生脚本付款基准，用统一口径核对其他签名锁的成本和签名覆盖范围。

[协议规范](#protocol) · [安全分析](#security) · [验证与测量](#validation) · [SDK 与参考接口](#sdk)

<a name="protocol"></a>

## 协议规范

P2PK 把压缩公钥写在锁里，花费时提供签名。P2PKH 在锁里放公钥的 20 字节 HASH160，花费时提供签名和能匹配哈希的公钥。签名携带签名类型字节。项目向量给出了完整父交易、花费交易以及锁定和解锁脚本。

[线格式示例与用例约定（英文）](../README.md#fixture-contract) · [可重放向量](../template/baseline.json) · [签名覆盖规则（英文）](../reference/acceptance.md)

<a name="security"></a>

## 安全分析

钱包通过可信链视图核对入金 outpoint、金额和脚本，再用现有 secp256k1 签名器授权花费。P2PKH 须核对公钥与收款哈希一致。按所选签名类型核对哪些输入输出已承诺，并执行应用的确认策略。附带交易使用合成上一输出和公开测试密钥，适用于本地验证。

[原生验收判定（英文）](../reference/acceptance.md) · [节点重放范围（英文）](../README.md#node-cross-check)

<a name="validation"></a>

## 验证与测量

验收域声明 2,880 种组合，另有 80 项无配对 SINGLE 变更以及 192 项激活边界测试。两进两出的 ForkID ALL 样本中，P2PK 为 326 字节，P2PKH 为 374 字节。P2PKH 每个输出锁少 10 字节，但每个输入多约 34 字节，实际值随 DER 签名长度变化。

按[项目命令](../README.zh-CN.md#复现与验收)重放离线向量，或在[统一入口](../../../docs/benchmark.zh-CN.md)用 `--project p2pk-p2pkh-baseline`。离线生成器和验收测试使用仓库统一的 Chronicle 依赖。

<a name="sdk"></a>

## SDK 与参考接口

从[统一 P2PKH 接入示例](sdk.zh-CN.md)开始，创建锁定脚本、识别入金输出，再将 secp256k1 签名器接入 `signPayment`。在同一客户端切换到 P2PK 模板即可运行另一组原生对照。

[Python 夹具源码](../reference/script_lab.py)提供序列化和验签示例。实际集成使用原有钱包签名接口。[向量 JSON](../template/baseline.json)可用来逐项校验生成的父交易、花费交易和脚本。

[复现命令](../README.zh-CN.md#复现与验收) · [统一依赖与运行口径](../../../docs/benchmark.zh-CN.md)
