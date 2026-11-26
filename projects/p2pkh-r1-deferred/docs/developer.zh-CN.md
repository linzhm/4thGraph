# P2PKH-R1-Deferred 开发指南

[English](developer.en.md) · [项目概览](../README.zh-CN.md)

入金用短锁，启用时生成等额的普通 R1 输出。新建入金默认承诺 R1 v0.2.0。

[协议规范](#protocol) · [安全分析](#security) · [验证与测量](#validation) · [SDK 与参考接口](#sdk)

<a name="protocol"></a>

## 协议规范

短锁包含收款哈希、目标脚本 SHA-256、金额和目标序列化输出的 HASH256。每个启用输入在同索引创建原先承诺的等额输出。BIP143 SINGLE 直接分支的解锁为 160 字节，其余十种类型使用 197 字节的双检查解锁，另带所选模式的摘要。完整 R1 锁位于实际交易输出里，后续花费走普通 R1 钱包。

v0.1.0 短锁继续启用为原先承诺的 v0.1.0 目标。 [协议规范](spec.zh-CN.md) · [v0.2.0 布局](../versions/v0.2.0/layout.json) · [历史布局](../versions/v0.1.0/layout.json)

<a name="security"></a>

## 安全分析

第三方可以安排启用并支付费用。节点约束启用资金只到承诺的等额输出，随后由收款人的 P-256 密钥授权花费。钱包按实际金额和预期收款人重建短锁，核对两项承诺。赞助方审批、签署自己的手续费输入。签名前排好输入输出配对，启用后记录已确认的 outpoint。

同一个收款哈希填入另一版本会改变目标承诺，花费旧短锁时按原承诺选择版本。 [启用规则](spec.zh-CN.md#花费短锁) · [Chronicle 规则](chronicle.md)

<a name="validation"></a>

## 验证与测量

新版验收在两个目标版本、两种入金格式和全部 12 种签名类型上运行，共 2,592 个节点判定用例，还重放了新旧短锁同笔启用。短锁为 1,435 字节。新版三进两出的 BIP143 ALL 启用样本为 93,259 字节。新增一对启用同时多一个短锁输入和承诺目标输出。

从仓库根目录安装[固定依赖](../reference/requirements.txt)，运行 `bash projects/p2pkh-r1-deferred/reference/verify.sh test_deferred`。 [验收矩阵](../reference/acceptance.md) · [十二种模式向量](../versions/v0.2.0/sighash-modes.json) · [生命周期与边际测量](../README.zh-CN.md#实测交易成本)

<a name="sdk"></a>

## SDK 与参考接口

用[统一钱包接口](sdk.zh-CN.md#统一钱包接口)生成并识别包含金额的短锁。将原承诺的 R1 输出放在与输入相同的位置，再对组装好的交易调用 `activate`。赞助输入单独签署，后续付款用普通 R1 钱包接口。

[SDK 与测试命令](sdk.zh-CN.md) · [Python 参考实现](../reference/README.md)
