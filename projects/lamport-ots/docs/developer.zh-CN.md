# Lamport OTS 开发指南

[English](developer.en.md) · [项目概览](../README.zh-CN.md)

<a name="protocol"></a>

## 协议规范

经典模板的 16,384 字节有序公钥含 256 对 SHA-256 承诺。签名器对摘要每一位公开一个 32 字节秘密值。全公钥锁逐项验证被选中的承诺。公钥承诺锁从证明还原完整有序公钥，再校验其 SHA-256。付款锁按指定 sighash 将摘要绑定到花费输入。[线格式和原生交易绑定（英文）](spec.md)

<a name="optimization"></a>

## Forth 优化

`forth_committed_locking_script(public_key)` 编译带类型的 Forth 重建片段。每个摘要字节使用八个位掩码决定公钥对的顺序。位判断比较的是字节值，即使最高位掩码为 `80`，传给分支的也是规范布尔值。该模板沿用原有的证明布局和交易模式，SDK 可用 `committed-key-forth` 显式选择。[栈状态与字节拆解（英文）](optimization.md) · [Forth 源码](../forth/committed-verifier.fth)

相较原承诺模板，每个输出锁减少 704 字节。BIP143 ALL 的解锁尺寸相同，OTDA ALL 的解锁会随同笔交易的输出一起缩短。相较全公钥模板，每个 Forth 承诺输出节省 15,738 字节，每个普通 BIP143 输入多 8,192 字节。在费率及其他编码相同的前提下，输出数除以输入数超过约 0.521 时，Forth 承诺模板占用的交易字节更少。入金和花费费率不同时，按两阶段分别计费。[边际及生命周期测量（英文）](optimization.md#transaction-and-lifecycle-costs)

第二轮的 `committed-key-forth-compact` 沿用同一重建片段，并压缩固定 r 交易绑定。锁进一步降至 6,830 字节，主栈峰值从 8 项升至 32 项，备用栈峰值从 34 项降至 5 项。[交易绑定优化（英文）](optimization.md#compact-transaction-binding)

## 固定重量候选

`committed-key-forth-subset` 把每个摘要字节映射到 11 个槽位中的 4 个。每个秘密值独立生成，承诺保留完整 SHA-256。原始签名为 4,096 字节，花费证明为 11,264 字节。不同摘要至少需要一个尚未公开的槽位。创建输出时使用候选格式的新密钥。[协议与一次性密钥管理](subset.zh-CN.md) · [退出和周转尺寸（英文）](optimization.md#fixed-weight-candidate)

<a name="security"></a>

## 签名与恢复

每个输出使用新密钥，释放签名前持久记录密钥已消耗。签署子交易前确认入金 outpoint，并确保备份恢复和并发请求遵守同一份状态。临时故障时重播原已签交易。入金 outpoint 变动会改变签名摘要。无配对 SINGLE 不承诺输出，参考 API 要求显式传入 `allow_unpaired_single=True`。[威胁模型与恢复步骤（英文）](security.md)

<a name="validation"></a>

## 验证与基准

408 项判定覆盖各付款模板的全部签名模式。公钥承诺模板另外检查每个证明块和 Chronicle 激活边界。复现时使用独立的 BSV Node 和固定版本的 chain-gang。v0.1.0 向量保存在原版本目录。[验收范围（英文）](acceptance.md) · [验证记录（英文）](validation.md) · [原版向量](../versions/v0.1.0/universal-vectors.json)

<a name="sdk"></a>

## 钱包与参考 API

使用 `WalletClient` 创建和识别锁，并接入外部签名器。回调接收 32 字节摘要，按请求的算法返回 8,192 字节经典签名或 4,096 字节固定重量签名。Python 参考接口 `sign_spend` 在调用签名器前按入金交易核对已准备的输入。[SDK 快速上手](sdk.zh-CN.md#quickstart) · [参考接口用法（英文）](../reference/README.md)
