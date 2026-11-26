# 纯模式 ML-DSA-44 开发指南

[English](developer.en.md) · [项目概览](../README.zh-CN.md)

按 FIPS 204 校验纯模式签名，并通过独立的 BSV 付款封装绑定当前花费输入。

[协议规范](#protocol) · [安全分析](#security) · [验证与测量](#validation) · [SDK 与参考接口](#sdk)

<a name="protocol"></a>

## 协议规范

公钥为 1,312 字节，签名为 2,420 字节。消息验签接受指定消息和上下文。付款模式将钱包给出的 32 字节授权数据直接作为纯模式消息，使用空上下文。锁检查 FIPS 204 的响应范围、提示值编码、附录 C 的采样上限，并验证 BSV 交易绑定。

[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) · [验签与付款入口](../README.zh-CN.md) · [授权实现](../reference/payment.py)

<a name="security"></a>

## 安全分析

钱包把预期公钥与可信的入金 outpoint 对应起来，由公钥重新生成锁定脚本并逐字节核对。付款签名器使用空上下文，直接处理传入的 32 字节消息。生产密钥由独立签名服务管理。FIPS 算法验签和 BSV 交易授权分别有验证证据。

锁定脚本体积较大，部署时在目标节点策略下核对入内存池及出块。现有统一测量使用文档声明的脚本测试配置。 [付款验收（英文）](../reference/payment-acceptance.md) · [已入金测试口径](../../../docs/benchmark.zh-CN.md#已入金节点验证)

<a name="validation"></a>

## 验证与测量

付款验收域包含 640 项，并复放 80 条 Wycheproof 和 15 条 NIST ACVP 外部纯模式向量。v0.2.0 付款锁的确定性样本为 586,981 字节，固定公钥内容会使编译大小略有变化。两进两出的 OTDA ALL 样本为 3,527,082 字节。开发求值器缺少所需的比较指令，暂无栈峰值。[脚本和交易大小](../README.zh-CN.md#脚本大小)

使用 Python 3.12 和 OpenSSL 3.5 或以上版本。 [项目验证命令](../README.zh-CN.md#复现方法) · [确定性向量](../versions/v0.1.0/deterministic.json) · [付款矩阵（英文）](../reference/payment-acceptance.md)

<a name="sdk"></a>

## SDK 与参考接口

按[统一 ML-DSA 钱包指南](sdk.zh-CN.md)生成输出、签署普通付款或指定输入。外部签名器以空上下文对请求中的 32 字节消息执行纯模式 ML-DSA-44，返回 2,420 字节原始签名。

[钱包接口](../reference/payment.py) · [签名接口与测试向量生成](../reference/mldsa.py) · [脚本编译器](../reference/script.py)
