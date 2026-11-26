# P2PKH-R1

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md)

P2PKH-R1 让 BSV 钱包接入已有的 P‑256 签名器。输出锁定到收款公钥的 HASH160，花费时提供未压缩公钥和 64 字节的 ECDSA 签名 `r || s`。

**[钱包 SDK 快速上手](docs/sdk.zh-CN.md#quickstart)** · [协议规范](docs/spec.zh-CN.md) · [安全分析](docs/developer.zh-CN.md#security) · [验收记录](reference/acceptance.md)

<a name="version-history"></a>
<a name="完整交易与栈测量"></a>
<a name="forth-探索版"></a>

## 实测结果

参考钱包用 **v0.2.0** 创建新输出，也能花费已有的 v0.1.0 输出。Forth 实验的最短锁为 **41,538 B**，最小 OTDA ALL 付款为 **91,692 B**，两个结果来自不同构造。表中付款均为两进两出。

| 模板 | 完整锁 | BIP143 ALL 付款 | OTDA ALL 付款 |
| --- | ---: | ---: | ---: |
| 钱包默认模板 v0.2.0 | 46,302 B | 93,374 B | 101,250 B |
| Forth 实验，4 位分表，特化固定生成元 `G` | **41,538 B** | **83,846 B** | 92,032 B |
| Forth 实验，2 位联合表 | 42,378 B | 85,526 B | **91,692 B** |

两个优胜实验方案都完成了 BIP143 ALL、OTDA ALL 和配对 OTDA SINGLE 付款，在 BSV Node regtest 入块，并通过 chain-gang 独立验证。 [构建与复现](experiments/forth/README.md) · [历史基准](experiments/forth/history.md)

## 钱包接入

统一 SDK 支持 TypeScript、Rust、Go 和 Python。接入已有 P‑256 签名器时，核对设备的摘要接口和签名编码，并跨签名进程持久保存随机数重复检测记录。 [SDK 指南](docs/sdk.zh-CN.md) · [参考钱包](reference/README.md) · [钱包模板](template/v0.2.0/layout.json)

R1 在入金时创建完整付款锁，收款人可用一次花费付款。Deferred R1 用较小的入金锁，并在独立的交易中启用。 [Deferred 流程](../p2pkh-r1-deferred/README.zh-CN.md)
