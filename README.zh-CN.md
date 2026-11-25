# BSV Script Lab

**在 BSV 上接入更多签名方案，看清从收款到花费的完整成本。**

BSV Script Lab 为钱包开发者提供可识别的锁定模板、统一的外部签名 SDK 和可复放的完整签名交易。项目覆盖普通付款、P‑256 与 SM2 签名器接入、延迟启用，以及一次性签名和后量子签名的实验验证。

**[钱包 SDK 快速上手](shared/sdk/README.zh-CN.md#quickstart)** · [选择项目](#project-index) · [比较交易成本](#transaction-costs) · [复现交易基准](shared/benchmark.zh-CN.md) · [English](README.md)

<a name="project-index"></a>

## 按使用场景选项目

| 项目 | 适用场景 | 接入时的取舍 | 版本 | 钱包 SDK |
| --- | --- | --- | --- | --- |
| [原生 P2PK 与 P2PKH](projects/p2pk-p2pkh-baseline/README.zh-CN.md) | 钱包首次接入、普通 secp256k1 付款、交易成本对照 | 选择在输出里放公钥还是公钥哈希 | v0.1 开发版 | [接入指南](projects/p2pk-p2pkh-baseline/docs/sdk.zh-CN.md#quickstart) |
| [P2PKH-R1](projects/p2pkh-r1/README.zh-CN.md) | 接入已有 P‑256 签名设备或服务的钱包 | 核对设备的签名方式，并持久保存 P‑256 签名随机数历史 | v0.2.0 开发版 | [接入指南](projects/p2pkh-r1/docs/sdk.zh-CN.md#quickstart) |
| [P2PKH-R1-Deferred](projects/p2pkh-r1-deferred/README.zh-CN.md) | 先用短锁接收入金，允许以后再启用的场景 | 预留手续费来源和启用步骤，届时生成完整 R1 输出 | v0.2.0 开发版 | [接入指南](projects/p2pkh-r1-deferred/docs/sdk.zh-CN.md#quickstart) |
| [P2PKH-SM2](projects/p2pkh-sm2/README.zh-CN.md) | 接入 SM2 签名器或 GB/T 35275‑2026 SignedData 服务 | 核对 SM2 消息和用户标识，使用 SignedData 时绑定预期签名者 | v1.1.0 候选版 | [接入指南](projects/p2pkh-sm2/docs/sdk.zh-CN.md#quickstart) |
| [Lamport OTS](projects/lamport-ots/README.zh-CN.md) | 研究 SHA‑256 一次性签名中公钥的存储与公开成本 | 每个 UTXO 使用新密钥，在更小的入金锁和更小的花费输入之间取舍 | v0.1 开发版 | [接入指南](projects/lamport-ots/docs/sdk.zh-CN.md#quickstart) |
| [WOTS+](projects/wots-plus/README.zh-CN.md) | 研究更短的 SHA‑256 一次性签名及不同收款模板 | 管理一次性密钥，并比较缓存式锁和 OTDA 重建 | v0.1 开发版 | [接入指南](projects/wots-plus/docs/sdk.zh-CN.md#quickstart) |
| [纯模式 ML-DSA-44](projects/ml-dsa/README.zh-CN.md) | 验证 FIPS 204 签名互操作，评估大脚本的花费成本 | 使用纯模式签名器，验证目标节点和矿工的大脚本接收策略 | v0.1 开发版 | [接入指南](projects/ml-dsa/docs/sdk.zh-CN.md#quickstart) |

先用原生 P2PKH 跑通第一笔付款。统一 SDK 在 TypeScript、Rust、Go 和 Python 中提供同一套钱包流程。选定项目后，可按接入指南连接签名器、选择锁定模板并复放付款或启用交易。[钱包 SDK 快速接入](shared/sdk/README.zh-CN.md)

<a name="transaction-costs"></a>

## 比较交易成本

P2PKH-R1 v0.2.0 将两进两出 ForkID ALL 交易由 **119,934 字节降到 93,374 字节**。Deferred 的入金锁为 **1,435 字节**，后续启用时生成 **46,302 字节**的完整 R1 锁。比较这两条路径时，要把每个阶段的字节数和钱包需要完成的步骤一起算进去。[R1 测量](projects/p2pkh-r1/README.zh-CN.md) · [Deferred 测量](projects/p2pkh-r1-deferred/README.zh-CN.md)

统一基准在提交 `beeb4dd` 测量了七个项目、32 种模板与签名模式组合，共 **260 笔完整交易**。混合输出和配对 `SINGLE` 另测 11 种组合，共 88 笔交易。Deferred v0.2.0 行采用提交 `9c5603d` 的重测结果。

| 项目和实测版本 | 输入 × 输出 | 上一输出锁 | ForkID ALL 解锁 | ForkID ALL 整笔 | OTDA ALL 整笔 | ForkID ALL 两栈载荷峰值 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 原生 P2PKH | 2 × 2 | 25 | 107 | 374 | 374 | 145 |
| P2PKH-R1 v0.2.0 | 2 × 2 | 46,302 | 326 | 93,374 | 101,250 | 3,479 |
| P2PKH-R1-Deferred 启用 | 3 × 2 | 1,435 | 197 | 93,259 | 93,260 | 359 |
| P2PKH-SM2 v1.1.0 候选版 | 2 × 2 | 144,925 | 291 | 290,554 | 316,018 | 4,147 |
| Lamport OTS 公钥承诺模板 | 2 × 2 | 7,746 | 16,549 | 48,708 | 79,616 | 16,707 |
| WOTS+ 缓存步骤及重建模板 | 2 × 2 | 33,956 | 2,310 | 72,650 | 79,090 | 2,701 |
| 纯模式 ML-DSA-44 | 2 × 2 | 926,412 | 2,588 | 1,858,122 | 5,563,725 | — |

单位均为字节。锁定、解锁和栈开销取 ForkID ALL 的第一个输入。栈峰值由本地求值器测得，统计主栈与备用栈的合计数据载荷。Deferred 启用交易包含一条手续费赞助输入。ML‑DSA‑44 暂无栈数据。各项目 README 列有逐输入、逐输出的大小、增量成本和生命周期总量。

SM2 候选版沿用 v1.0.0 的锁定模板 `1`，自动选择更短的 OTDA 解锁编码。实测两进两出 OTDA ALL 交易的每个输入解锁脚本从 290,109 字节降至 13,023 字节，整笔从 870,194 字节降至 316,018 字节，缩小 63.7%。[SM2 重建测量](projects/p2pkh-sm2/README.zh-CN.md#otda-constructor)

## 复现结果

基准指南给出在 BSV Node 1.2.3 和仓库固定版本的 chain-gang 上复放签名交易的方法。各项目首页另有协议规范、安全分析、验收用例和 SDK 入口。[统一基准指南](shared/benchmark.zh-CN.md)
