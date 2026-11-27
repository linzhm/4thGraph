# MuSig2 与原生 2-of-2 多签

[English](threshold-comparison.en.md) · [项目首页](../README.zh-CN.md) · [钱包接入](sdk.zh-CN.md#integrate-musig2)

现有 P2PKH-Schnorr 模板可以花费由两方 MuSig2 共同控制的 UTXO。入金时，钱包按约定的顺序用两把独立的压缩公钥计算 BIP327 聚合公钥，再把聚合公钥横坐标的 HASH160 填入固定模板。花费时，两方各自审批当前输入的 32 字节交易签名摘要，先交换公有 nonce，再各自签出部分签名。协调器核验两份部分签名，聚合成标准的 64 字节 BIP340 签名。现有钱包接口接收这条签名并生成坐标见证。链上可见聚合公钥和聚合签名，参与者的公钥列表与人数留在链下。原生 `CHECKMULTISIG` 在锁里直接公开两把公钥。[BIP327](https://github.com/bitcoin/bips/blob/4f9567fd60021cb7dea032250ab241cd68d9ff91/bip-0327.mediawiki) · [两方签名夹具](../reference/musig2_fixture.py)

## 整笔交易和全生命周期

两套方案均要求两位参与者签名。对照采用同样的输入输出布局、金额和签名模式。2×2 场景创建两个同类型的受保护输出。新增输入以 3×2 减 2×2 测得，新增输出以 2×3 减 2×2 测得。全生命周期从一笔普通 P2PKH 入金交易开始，最后退回两个普通 P2PKH 输出。“一次周转”在两者之间插入一笔 2×2 同类型转账。

| 方案 | ALL 模式 | 单个锁 | 2×2 解锁见证，每输入 | 2×2 交易 | 新增输入 | 新增输出 | 入金与退出 | 含一次周转 | 首输入栈载荷峰值 |
| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| MuSig2 v0.16.0 | BIP143 | 22,515 | 329 / 329 | 45,806 | 372 | 22,526 | 46,032 | 91,837 | 3,404 |
| 原生 2-of-2 | BIP143 | 71 | 146 / 147 | 545 | 186 | 80 | 771 | 1,313 | 211 |
| MuSig2 v0.16.0 | Chronicle OTDA | 22,515 | 45,321 / 45,321 | 135,790 | 45,487 | 67,586 | 46,046 | 181,836 | 90,474 |
| 原生 2-of-2 | Chronicle OTDA | 71 | 145 / 146 | 543 | 187 | 81 | 769 | 1,314 | 210 |

以上均以字节计。统一费率为 1 聪/字节时，整笔交易或生命周期的字节数也就是对应的手续费聪数。原生 ECDSA 签名的 DER 长度随签名变化，所以实测边际可能包含几个见证字节的变化。栈载荷是主栈与备用栈的元素数据总量，原生方案在执行 `CHECKMULTISIG` 前达到峰值。MuSig2 的栈载荷来自开发求值器。两者均省略引擎内部的内存开销。[测量实现](../reference/compare_threshold.py) · [统一测量口径](../../../docs/benchmark.zh-CN.md)

在两进两出的夹具中，chain-gang 中位耗时在 BIP143 下为 MuSig2 **6.93 ms**、原生多签 **0.39 ms**，在 OTDA 下分别为 **5.61 ms** 和 **0.39 ms**。BSV Node 本地 RPC 的中位耗时在 BIP143 下分别为 **21.22 ms** 和 **0.70 ms**，在 OTDA 下分别为 **36.34 ms** 和 **0.71 ms**。每组预热一次后测量 15 次，耗时包含输入准备和验证。Node 测量还包含本地 RPC 开销。

OTDA ALL 的大头是当前模板把所承诺的完整输出字节放入每份预映像。只有退出、且新输出是普通 P2PKH 时，MuSig2 的两个 OTDA 解锁见证各为 336 字节。原生 `CHECKMULTISIG` 由节点直接从交易构造签名摘要，因此解锁见证只包含 dummy 项和两条签名。

## 链下签名成本和验收

MuSig2 每个输入需要两轮依赖的签名消息。两方各生成 66 字节公有 nonce 和 32 字节部分签名，合计 **196 字节**。原生多签只需独立签名并收集结果，本次每个输入的两条 DER 签名及签名模式字节合计 **142–144 字节**。这些数字统计签名材料。交易分发、协调器转发、设备审批和网络开销依部署另计。多个输入的各轮可以并行收集。两套方案都需要两位参与者才能完成。同一笔交易的原生 ECDSA 签名可独立收集，MuSig2 中断后开新会话需要重新生成 nonce 和部分签名。[BIP327](https://github.com/bitcoin/bips/blob/4f9567fd60021cb7dea032250ab241cd68d9ff91/bip-0327.mediawiki)

直接退出和中间周转一次时，受保护输入分别产生 392 和 784 字节 MuSig2 签名材料。原生多签在 BIP143 下分别为 287 和 572 字节，在 OTDA 下分别为 286 和 573 字节。普通入金输入是两边共同的成本。

验收复放了两条 BIP327 官方签名聚合向量。会话测试覆盖缺 nonce、缺部分签名、中断后作废 nonce、重试、错摘要、参与者错序和旧部分签名。两种链上方案均通过 BSV Node 1.2.3 与 chain-gang 对 **12 种已配对的 BIP143 / OTDA 签名模式 × 两种交易版本**的验证，也验证了锁定时间与输出金额更改的预期效果。两类方案在默认 regtest 策略下的 BIP143 ALL 和 OTDA ALL 入金与退出均进入内存池并出块。统一 SDK 的 Python、TypeScript、Go 和 Rust 验收均复放了 BIP143 ALL 和 OTDA SINGLE 的 MuSig2 聚合签名。[验收入口](../reference/test_musig2.py) · [官方聚合向量](https://github.com/bitcoin/bips/blob/4f9567fd60021cb7dea032250ab241cd68d9ff91/bip-0327/vectors/sig_agg_vectors.json) · [钱包夹具](../reference/sdk_fixture.py)

按[项目验收说明](../README.zh-CN.md#复现验收)安装依赖后，从仓库根目录运行。

```sh
PYTHONPATH=src:. bash tools/verify_node.sh -- \
  projects/p2pkh-schnorr/workspace/p2pkh-schnorr/bin/python projects/p2pkh-schnorr/reference/compare_threshold.py \
  --output /tmp/p2pkh-schnorr-threshold.json
PYTHONPATH=src:. bash tools/verify_node.sh --profile default -- \
  projects/p2pkh-schnorr/workspace/p2pkh-schnorr/bin/python projects/p2pkh-schnorr/reference/compare_threshold.py \
  --admission --output /tmp/p2pkh-schnorr-threshold-admission.json
```
