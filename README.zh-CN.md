# BSV Script Lab

**为 BSV 钱包接入更多签名方案，在集成前看清交易成本。**

BSV Script Lab 为钱包和支付基础设施团队提供 P-256、SM2、哈希签名和 ML-DSA-44 的锁定模板、参考实现和可复现的交易基准。先比较收款、转付和退出各阶段的开销，再用各项目的签名交易向量验证接入。

[查看项目与成本](#project-index) · [复现交易基准](shared/benchmark.zh-CN.md) · [English](README.md)

<a name="project-index"></a>

## 跨项目统计

提交 `beeb4dd` 的统一入口测量了 **7 个项目、32 种模板与签名模式组合、260 笔完整交易**。对 R1 混合输出、配对 `SINGLE` 等路径另测了 **11 种组合和 88 笔交易**。表中选列基准和常用候选，单位为字节。脚本和栈列取 ForkID ALL 的第一个输入。Deferred 的启用交易形状包含一条赞助输入。Deferred v0.2.0 数据来自提交 `9c5603d` 的重测。

| 项目 | 模板 | 发布状态 | 输入×输出 | 首个旧锁 | 首个解锁 | ForkID ALL | OTDA ALL | 两栈载荷 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [原生 P2PK 与 P2PKH](projects/p2pk-p2pkh-baseline/README.zh-CN.md) | `p2pk` | v0.1 | 2×2 | 35 | 73 | 326 | 325 | 105 |
| [原生 P2PK 与 P2PKH](projects/p2pk-p2pkh-baseline/README.zh-CN.md) | `p2pkh` | v0.1 | 2×2 | 25 | 107 | 374 | 374 | 145 |
| [P2PKH-R1](projects/p2pkh-r1/README.zh-CN.md) | `v0.2.0` | v0.2.0 | 2×2 | 46,302 | 326 | 93,374 | 101,250 | 3,479 |
| [P2PKH-R1-Deferred](projects/p2pkh-r1-deferred/README.zh-CN.md) | `hash-only` | v0.2.0 | 3×2 | 1,435 | 197 | 93,259 | 93,260 | 359 |
| [P2PKH-SM2](projects/p2pkh-sm2/README.zh-CN.md) | `v1.0.0` | v1.0.0 | 2×2 | 144,925 | 291 | 290,554 | 870,194 | 4,147 |
| [Lamport OTS](projects/lamport-ots/README.zh-CN.md) | `full-key` | v0.1 | 2×2 | 22,780 | 8,357 | 62,392 | 153,436 | 8,515 |
| [Lamport OTS](projects/lamport-ots/README.zh-CN.md) | `committed-key` | v0.1 | 2×2 | 7,746 | 16,549 | 48,708 | 79,616 | 16,707 |
| [WOTS+](projects/wots-plus/README.zh-CN.md) | `canonical` | v0.1 | 2×2 | 42,266 | 2,310 | 89,270 | 258,266 | 2,599 |
| [WOTS+](projects/wots-plus/README.zh-CN.md) | `cached-steps-reconstructed` | v0.1 | 2×2 | 33,956 | 2,310 | 72,650 | 79,090 | 2,701 |
| [纯模式 ML-DSA-44](projects/ml-dsa/README.zh-CN.md) | `pure-ml-dsa-44` | v0.1 | 2×2 | 926,412 | 2,588 | 1,858,122 | 5,563,725 | — |

v0.1 与 v0.2.0 是开发版本，SM2 v1.0.0 是正式发布。项目 README 提供协议、安全、验证测量及钱包接入入口。
