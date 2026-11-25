# WOTS+ 开发指南

[English](developer.en.md) · [项目概览](../README.zh-CN.md)

将基于 SHA-256 的一次性签名绑定到 BSV 输入，支持缓存步骤模板和可选的 OTDA 输出重建。

[协议规范](#protocol) · [安全分析](#security) · [验证与测量](#validation) · [SDK 与参考接口](#sdk)

<a name="protocol"></a>

## 协议规范

采用 RFC 8391 的 `WOTSP-SHA2_256` 哈希链，项目付款格式使用 64 字节公钥和 2,144 字节签名。锁同时验证哈希链证明及所选输入的交易授权，支持 ForkID 和 Chronicle OTDA 的十二种签名类型。在符合条件的版本 2 交易中，缓存步骤输出可以在 OTDA ALL 或配对 SINGLE 解锁内重建。

[线格式与脚本规范（英文）](spec.md) · [RFC 8391](https://www.rfc-editor.org/rfc/rfc8391) · [缓存步骤布局](../template/cached-steps-layout.json)

<a name="security"></a>

## 安全分析

每组密钥只用于一个 UTXO。即使交易未广播或确认失败，也要在返回签名之前持久化消耗记录。并发签名须共享同一份记录。保存签过的交易以便原样重播。找零使用新密钥，恢复备份后停用使用状态不明的密钥，实际付款使用交易绑定模板。

钱包签名前检查可信上一输出和所选模式承诺的输出范围。确认支持 Chronicle 功能解锁后才启用可执行解锁。 [付款授权（英文）](spec.md#payment-authorization) · [密钥生命周期（英文）](spec.md#key-lifecycle-and-validation-scope)

<a name="validation"></a>

## 验证与测量

付款验收对每个布局定义 1,230 项判定，并在完整输入中覆盖全部 67 条签名链。缓存步骤锁占 33,956 字节。OTDA ALL 两进两出从 208,406 降至 79,090 字节；配对 SINGLE 从 140,473 降到 78,921 字节。配对样本执行时的两栈载荷峰值均是 70,280 字节。

安装[固定依赖](../reference/requirements.txt)，运行 `bash projects/wots-plus/reference/verify.sh`。 [BSV Node、chain-gang 与 Lean 验证记录（英文）](validation.md) · [付款向量](../template/vectors.json) · [项目详细测量](../README.zh-CN.md)

<a name="sdk"></a>

## SDK 与参考接口

Python 参考接口以 `locking_script` 构造钱包收款锁。用 `sign_payment` 完成单输入付款，或者通过 `sign_spend` 给已构造的交易签一个输入。回调收 32 字节摘要，返回 2,144 字节原始签名。`compress_otda=True` 可选择符合条件的紧凑解锁。密钥消费记录由签名器维护，交易审批和广播由钱包完成。

[付款接口](../reference/payment.py) · [一次性签名接口](../reference/wots.py) · [基准持久签名器](../../../shared/one_time_signer.py)
