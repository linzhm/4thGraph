# BSV Script Lab

**在 BSV 上接入更多签名方案，看清从收款到花费的完整成本。**

BSV Script Lab 提供钱包可识别的锁定模板、可接入外部签名器的源码 SDK，以及可复放的签名交易向量。你可以从原生 P2PKH 基准出发，接入 P‑256 或 SM2，也可以用统一的测量口径比较 Lamport、WOTS+ 和纯模式 ML‑DSA‑44。

**[钱包 SDK 快速上手](shared/sdk/README.zh-CN.md#quickstart)** · [选择项目](#project-index) · [比较交易成本](#transaction-costs) · [复现交易基准](shared/benchmark.zh-CN.md) · [English](README.md)

<a name="project-index"></a>

## 按使用场景选项目

| 项目 | 使用场景 | 版本 | 钱包接入 |
| --- | --- | --- | --- |
| [原生 P2PK 与 P2PKH](projects/p2pk-p2pkh-baseline/README.zh-CN.md) | 以原生 secp256k1 脚本建立体积和签名基准 | v0.1 开发版 | [接入指南](projects/p2pk-p2pkh-baseline/docs/sdk.zh-CN.md#quickstart) |
| [P2PKH-R1](projects/p2pkh-r1/README.zh-CN.md) | 用固定模板向 P‑256 公钥哈希付款 | v0.2.0 开发版 | [接入指南](projects/p2pkh-r1/docs/sdk.zh-CN.md#quickstart) |
| [P2PKH-R1-Deferred](projects/p2pkh-r1-deferred/README.zh-CN.md) | 用短锁收款，之后启用为普通 R1 输出 | v0.2.0 开发版 | [接入指南](projects/p2pkh-r1-deferred/docs/sdk.zh-CN.md#quickstart) |
| [P2PKH-SM2](projects/p2pkh-sm2/README.zh-CN.md) | 使用 SM2 签名付款，在链下接收 GB/T 35275‑2026 SignedData | v1.0.0 公开版 | [接入指南](projects/p2pkh-sm2/docs/sdk.zh-CN.md#quickstart) |
| [Lamport OTS](projects/lamport-ots/README.zh-CN.md) | 评估 SHA‑256 一次性签名，比较完整公钥锁和公钥承诺锁 | v0.1 开发版 | [接入指南](projects/lamport-ots/docs/sdk.zh-CN.md#quickstart) |
| [WOTS+](projects/wots-plus/README.zh-CN.md) | 评估基于 SHA‑256 哈希链的一次性签名 | v0.1 开发版 | [接入指南](projects/wots-plus/docs/sdk.zh-CN.md#quickstart) |
| [纯模式 ML-DSA-44](projects/ml-dsa/README.zh-CN.md) | 评估在脚本中验证 FIPS 204 纯模式 ML‑DSA‑44 签名 | v0.1 开发版 | [接入指南](projects/ml-dsa/docs/sdk.zh-CN.md#quickstart) |

先用原生 P2PKH 跑通第一笔付款。七个项目在 TypeScript、Rust、Go 和 Python 中使用同一套钱包调用，各项目指南说明签名器参数、模板选项和本地依赖。 [钱包 SDK 快速接入](shared/sdk/README.zh-CN.md)

<a name="transaction-costs"></a>

## 比较交易成本

P2PKH-R1 v0.2.0 将两进两出 ForkID ALL 交易由 **119,934 字节降到 93,374 字节**。Deferred 的入金锁为 **1,435 字节**，后续启用时生成 **46,302 字节**的完整 R1 锁。比较这两条路径时，要把每个阶段的字节数和钱包需要完成的步骤一起算进去。[R1 测量](projects/p2pkh-r1/README.zh-CN.md) · [Deferred 测量](projects/p2pkh-r1-deferred/README.zh-CN.md)

统一基准在提交 `beeb4dd` 测量了七个项目、32 种模板与签名模式组合，共 **260 笔完整交易**。混合输出和配对 `SINGLE` 另测 11 种组合，共 88 笔交易。Deferred v0.2.0 行采用提交 `9c5603d` 的重测结果。

| 项目和实测模板 | 输入 × 输出 | 上一输出锁 | 解锁 | ForkID ALL 整笔 | OTDA ALL 整笔 | 两栈载荷峰值 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 原生 P2PKH | 2 × 2 | 25 | 107 | 374 | 374 | 145 |
| P2PKH-R1 v0.2.0 | 2 × 2 | 46,302 | 326 | 93,374 | 101,250 | 3,479 |
| P2PKH-R1-Deferred 启用 | 3 × 2 | 1,435 | 197 | 93,259 | 93,260 | 359 |
| P2PKH-SM2 v1.0.0 | 2 × 2 | 144,925 | 291 | 290,554 | 870,194 | 4,147 |
| Lamport OTS 公钥承诺模板 | 2 × 2 | 7,746 | 16,549 | 48,708 | 79,616 | 16,707 |
| WOTS+ 缓存步骤及重建模板 | 2 × 2 | 33,956 | 2,310 | 72,650 | 79,090 | 2,701 |
| 纯模式 ML-DSA-44 | 2 × 2 | 926,412 | 2,588 | 1,858,122 | 5,563,725 | — |

单位均为字节。锁定和解锁大小取 ForkID ALL 的第一个输入。栈峰值由本地求值器测得，统计同一输入的主栈与备用栈合计数据载荷。ML‑DSA‑44 暂无栈数据。Deferred 启用交易含一条手续费赞助输入。各项目 README 列有逐输入、逐输出的大小、增量成本和生命周期总量。

## 复现结果

基准指南给出在 BSV Node 1.2.3 和仓库固定版本的 chain-gang 上复放签名交易的方法。各项目首页另有协议规范、安全分析、验收用例和 SDK 入口。[统一基准指南](shared/benchmark.zh-CN.md)
