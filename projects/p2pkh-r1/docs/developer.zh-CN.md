# P2PKH-R1 开发指南

[English](developer.en.md) · [项目概览](../README.zh-CN.md)

面向 P-256 钱包的付款锁。新建输出用 v0.2.0 固定模板，已有 UTXO 按各自的锁定脚本和原版本花费。

[协议规范](#protocol) · [安全分析](#security) · [验证与测量](#validation) · [SDK 与参考接口](#sdk)

<a name="protocol"></a>

## 协议规范

付款人将收款人未压缩 P-256 公钥的 20 字节 HASH160 写入锁定脚本的 `[208, 228)`。花费者提供公钥，并对当前输入的授权签名。BIP143 与 Chronicle OTDA 均支持 ALL、NONE、SINGLE，可组合 ANYONECANPAY。支持 Chronicle 功能解锁的版本 2 交易，可以在解锁时重建符合条件的输出，按原字节恢复签名原文。

通过固定字节指纹区分 v0.2.0 和 v0.1.0。钱包按实际上一输出选择验签路径。 [协议与签名覆盖范围](spec.zh-CN.md) · [v0.2.0 布局](../versions/v0.2.0/layout.json) · [v0.1.0 布局](../versions/v0.1.0/layout.json)

<a name="security"></a>

## 安全分析

签名前认证 outpoint、金额、收款人和完整锁定脚本，按所选签名类型核对授权范围。使用参考钱包时持久保存签名历史，由签名服务负责私钥和签名随机数。父交易确认前若交易 ID 改变，应从可信链视图恢复确认后的 outpoint，重建子交易再签。确认深度由钱包按业务确定。

双引擎结果覆盖已声明的规则上下文。硬件签名器、独立评审和实际部署策略各自验收。 [Chronicle 执行与恢复](chronicle.md) · [钱包签名前检查](../reference/wallet.py)

<a name="validation"></a>

## 验证与测量

验收覆盖 12 种签名类型、两种交易版本、配对与无配对、三种规则上下文和九类授权情况，每份锁共 1,296 项。独立引擎核对声明的 Chronicle 子集。普通 BIP143 ALL 的解锁是 326 字节。两进两出整笔交易从 v0.1.0 的 119,934 字节降到 v0.2.0 的 93,374 字节。

在仓库根目录安装[参考实现依赖](../reference/requirements.txt)，运行 `bash projects/p2pkh-r1/reference/verify.sh`。 [验收矩阵](../reference/acceptance.md) · [v0.2.0 付款向量](../versions/v0.2.0/spend-all.json) · [基准结果](../reference/README.md)

<a name="sdk"></a>

## SDK 与参考接口

[统一钱包接口](sdk.zh-CN.md#统一钱包接口)在 TypeScript、Rust、Go 和 Python 中提供生成锁、识别、普通付款和逐输入签名。P-256 签名器返回 64 字节 `r ∥ s`。设备内部执行一次 SHA-256 时使用 `signMessage`，钱包进程共用持久签名历史。

[SDK 与测试命令](sdk.zh-CN.md) · [Python 参考实现](../reference/README.md)
