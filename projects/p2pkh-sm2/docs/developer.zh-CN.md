# P2PKH-SM2 开发指南

[English](developer.en.md) · [项目概览](../README.zh-CN.md)

v1.0.0 付款锁将 SM2 签名绑定到当前 BSV 输入。GB/T 35275-2026 的 SignedData 适配在链下进行。

[协议规范](#protocol) · [安全分析](#security) · [验证与测量](#validation) · [SDK 与参考接口](#sdk)

<a name="protocol"></a>

## 协议规范

锁定脚本按收款人的 65 字节未压缩 SM2 公钥的 HASH160 构造。脚本以模板规定的用户标识计算 ZA，验证 SM2 签名并绑定实际花费，支持 ForkID 与 Chronicle OTDA 的十二种签名类型。无配对 SINGLE 用伴随验签。付款适配器接受单个签名者的直接签名，要求 `SignedData.version = 1`、`SignerInfo.version = 2`，并把原始签名交给钱包构造解锁。

[付款协议](spec.zh-CN.md) · [规范模板布局](../template/layout.json) · [GB/T 35275-2026](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=28A18B702BDC318803E598F5E502E2CC)

<a name="security"></a>

## 安全分析

钱包通过可信配置固定签名公钥、用户标识及完整的 DER 颁发者与序列号，核验入金 outpoint 和将要签署的金额、输出及费用。附带原文时要与已批准消息一致。支持的属性签名和多签名者封装由通用验签入口处理。证书信任、吊销评估以及开放类型的模式需要应用提供相应策略和证据。

[签名者信任边界](../reference/README.zh-CN.md#signeddata-付款接入) · [SignedData 与 PKI 验收](../reference/signed-data-acceptance.zh-CN.md)

<a name="validation"></a>

## 验证与测量

正式版锁为 144,925 字节，普通 ForkID 解锁为 291 字节。两进两出在 ForkID ALL 下为 290,554 字节，在 OTDA ALL 下为 870,194 字节，区别主要来自每个输入携带的输出原文。国标验收分别列出付款、通用验签、证书评估和附录 A.1 历史样例的依据。

使用 Python 3.12、支持 SM2/SM3 的 OpenSSL 和 Rust。安装[固定依赖](../reference/requirements.txt)，运行 `bash projects/p2pkh-sm2/reference/verify.sh`。 [标准向量](../template/sm2-standard.json) · [付款向量](../template/spend-all.json) · [节点重放](../reference/README.zh-CN.md) · [详细支出数据](../README.zh-CN.md)

<a name="sdk"></a>

## SDK 与参考接口

按[统一 SM2 钱包指南](sdk.zh-CN.md)生成或识别锁，再签署交易。签名器接收消息和 SM2 用户 ID，可返回原始签名或 DER SignedData。Rust 和 Python 命令行签名器用于公开夹具。

[参考钱包源码](../reference/p2pkh_sm2.py) · [SignedData 接入示例](../reference/README.zh-CN.md#signeddata-付款接入) · [Rust 测试签名器](../reference/interop/rust-signer/README.zh-CN.md) · [Python 测试签名器](../reference/interop/python-signer/README.zh-CN.md)
