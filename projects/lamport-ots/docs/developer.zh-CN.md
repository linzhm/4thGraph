# Lamport OTS 开发指南

[English](developer.en.md) · [项目概览](../README.zh-CN.md)

将 SHA-256 一次性签名绑定到 BSV 当前输入。全公钥和公钥承诺格式分别优化不同阶段的成本。

[协议规范](#protocol) · [安全分析](#security) · [验证与测量](#validation) · [SDK 与参考接口](#sdk)

<a name="protocol"></a>

## 协议规范

有序公钥包含 256 对承诺。签名为摘要每一位公开所选的 32 字节秘密值，总计 8,192 字节。全公钥付款锁携带全部公开承诺。公钥承诺候选锁只保存有序公钥的承诺，解锁时另提供每对中另一侧的哈希，用以还原并校验有序公钥。两种付款格式都把摘要绑定到交易输入。

[线格式与脚本规范（英文）](spec.md) · [测量清单](../template/measurement.json) · [签名模式向量](../template/universal-vectors.json)

<a name="security"></a>

## 安全分析

每个 UTXO 单独分配密钥，找零也使用新密钥。签名释放前持久记录密钥消耗。重启、恢复备份、调整手续费时均要保留这一记录；重试时重播原已签交易。公钥承诺格式需要钱包保有完整有序公钥。入金验真和确认数由钱包核对，实际资金使用交易绑定的模板。

默认钱包会拒绝无配对 SINGLE，因为它不承诺输出。只有显式策略例外才在 `sign_spend` 传入 `allow_unpaired_single=True`。 [安全模型、恢复与限制（英文）](security.md)

<a name="validation"></a>

## 验证与测量

已声明的通用付款验收域包含 408 项判定。ForkID ALL 两进两出时，整笔交易由全公钥格式的 62,392 字节降到公钥承诺格式的 48,708 字节。新增输入成本由 8,400 升到 16,592 字节，新增输出由 22,791 降到 7,757 字节。钱包可按入金和花费的交易结构分别预算。

安装[固定依赖](../reference/requirements.txt)，运行 `bash projects/lamport-ots/reference/verify.sh`。 [验收范围（英文）](acceptance.md) · [验证与测量记录（英文）](validation.md) · [项目详细分析](../README.zh-CN.md)

<a name="sdk"></a>

## SDK 与参考接口

按[统一 Lamport 钱包指南](sdk.zh-CN.md)生成完整公钥或承诺公钥输出，并接入外部签名器。签名器对请求中的摘要返回 8,192 字节原始签名。钱包需要持久记录密钥消耗，找零使用新密钥。

[参考使用说明（英文）](../reference/README.md) · [付款接口](../reference/payment.py) · [原始入金和花费向量](../template/vector.json)
