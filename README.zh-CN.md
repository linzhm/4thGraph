# BSV Script Lab

**用 4thGraph（4thG）把 Forth 编译成 BSV Script，再复放交易验证结果、测量成本。**

BSV Script Lab 提供开发和测试 BSV 合约的工具。**4thGraph** 是仓库的 Forth 工具链，可以编译独立的 Script 例程，也可以编译多笔交易组成的工作流。仓库还提供钱包锁定模板、可接入外部签名器的 SDK，以及已签名的交易测试向量。

**[立即试用 4thG](#4thg-quickstart)** · [项目改造与对照](#4thg-comparisons) · [钱包 SDK 快速上手](shared/sdk/README.zh-CN.md#quickstart) · [钱包项目](#project-index) · [交易成本](#transaction-costs) · [English](README.md)

<a name="4thg-quickstart"></a>

## 立即试用 4thG

安装 Git 和 Python 3.12，然后克隆 `feat/4thgraph` 分支。编译器直接从源码运行，只依赖 Python 标准库。先运行以下示例，再按需安装节点和复放依赖。

```sh
git clone --branch feat/4thgraph https://github.com/linzhm/bsv-script-lab.git
cd bsv-script-lab

cat > add-one.fth <<'FORTH'
bsv-effect: add-one u32 -- u32 ;
: add-one 1 cell>u32 u32+ ;
FORTH

PYTHONPATH=. python3 projects/4thgraph/protocol.py add-one.fth \
  --entry add-one --optimize safe
```

`bsv-effect:` 声明 `add-one` 消耗一个 `u32` 并返回一个 `u32`。这个词将输入加一，溢出时按 32 位回绕。编译器输出 JSON，`script_hex` 为 `8b05000000000197`，`script_bytes` 为 `8`，同时列出栈签名、源码摘要和构建摘要。把源码中的 `1` 改成其他值再编译，就能看到输出变化。

### 复放完整工作流

在 Linux x86-64 上，从同一份检出安装复放依赖。`pip` 从固定的 Git 提交构建 chain-gang，需要 Rust/Cargo 和 C 编译工具链。启动脚本通过 `curl` 下载并校验 BSV Node 1.2.3，在隔离的 regtest 网络中给示例提供测试资金。

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install ecdsa -r shared/requirements-chronicle.txt

project=projects/4thgraph
PYTHONPATH=. bash shared/verify_node.sh --profile default -- \
  python "$project/replay.py" --target both --optimize stack --samples 1 \
  --output "$project/build/quickstart-replay.json"

PYTHONPATH=. python "$project/decision_report.py" "$project/build/quickstart-replay.json" \
  --output-dir "$project/build/quickstart-decision"
```

打开 `projects/4thgraph/build/quickstart-decision/decision-report.md`，查看候选方案入选或排除的原因、结算与复核的交易字节数，以及 BSV Node 和 chain-gang 的验证结果。[4thGraph 使用手册](https://github.com/linzhm/bsv-script-lab/tree/feat/4thgraph/projects/4thgraph) · [Forth 语言规范](https://github.com/linzhm/bsv-script-lab/blob/feat/4thgraph/projects/4thgraph/language.md)

### 可以构建什么

- **Script 例程。** 把有栈类型声明的 Forth 词编译成 Script，对照不同栈调度，并按源码位置查看改写记录。
- **交易工作流。** 声明输入、签名角色、并行步骤和汇合条件。4thG 可以把步骤融合到一次花费，也可以拆到不同 UTXO 以支持独立提交。候选搜索根据授权和可用性约束比较受支持的交易边界与见证布局。宿主运行器把交易模板绑定到实际 outpoint，并准备签名请求。[并行示例](https://github.com/linzhm/bsv-script-lab/blob/feat/4thgraph/projects/4thgraph/example.fth) · [带门条件的示例](https://github.com/linzhm/bsv-script-lab/blob/feat/4thgraph/projects/4thgraph/gated.fth)
- **算术电路。** 受限的电路后端可将支持的 Forth 词编译为 Circom。计数器示例对照宿主求值、Script 执行和电路约束，覆盖回绕和分支边界。[电路示例](https://github.com/linzhm/bsv-script-lab/blob/feat/4thgraph/projects/4thgraph/proof/workflow.fth)

<a name="4thg-comparisons"></a>

## 4thG 项目改造与对照

| 项目 | 对照结果 |
| --- | --- |
| P2PKH-R1 Forth v0.3.0 探索版 | Forth 基线逐字节复现 v0.2.0 锁。优化后完整锁由 46,302 B 降到 **45,776 B**，两进两出 ForkID ALL 付款由 93,374 B 降到 **92,322 B**。复放还覆盖 OTDA，以及用 sCrypt 编译曲线内核的版本。[改造与复放](https://github.com/linzhm/bsv-script-lab/tree/feat/4thgraph/projects/p2pkh-r1/experiments/forth) |
| BLS12-381 Groth16 验证器（开发中） | 用 Forth 编排链下证明的链上验证，支持全固定、混合以及花费时提供全部公开输入。与 nChain 的对照采用相同的公开输入域和配对预计算数据放置方式。 |
| CCTP 交易布局（开发中） | 在单笔融合、同交易双输入和两笔串行布局中复放同一个 Groth16 验证任务，比较整条路径字节与最慢单笔花费的验证时间。 |

<a name="project-index"></a>

## 钱包项目

| 项目 | 使用场景 | 版本 | 钱包接入 |
| --- | --- | --- | --- |
| [原生 P2PK 与 P2PKH](projects/p2pk-p2pkh-baseline/README.zh-CN.md) | 以原生 secp256k1 脚本建立体积和签名基准 | v0.1 开发版 | [接入指南](projects/p2pk-p2pkh-baseline/docs/sdk.zh-CN.md#quickstart) |
| [P2PKH-R1](projects/p2pkh-r1/README.zh-CN.md) | 用固定模板向 P‑256 公钥哈希付款 | v0.2.0 开发版 | [接入指南](projects/p2pkh-r1/docs/sdk.zh-CN.md#quickstart) |
| [P2PKH-R1-Deferred](projects/p2pkh-r1-deferred/README.zh-CN.md) | 用短锁收款，之后启用为普通 R1 输出 | v0.2.0 开发版 | [接入指南](projects/p2pkh-r1-deferred/docs/sdk.zh-CN.md#quickstart) |
| [P2PKH-SM2](projects/p2pkh-sm2/README.zh-CN.md) | 使用 SM2 签名付款，在链下接收 GB/T 35275‑2026 SignedData，并重建符合条件的 OTDA 输出 | v1.1.0 候选版 | [接入指南](projects/p2pkh-sm2/docs/sdk.zh-CN.md#quickstart) |
| [Lamport OTS](projects/lamport-ots/README.zh-CN.md) | 评估 SHA‑256 一次性签名，比较完整公钥锁和公钥承诺锁 | v0.1 开发版 | [接入指南](projects/lamport-ots/docs/sdk.zh-CN.md#quickstart) |
| [WOTS+](projects/wots-plus/README.zh-CN.md) | 评估基于 SHA‑256 哈希链的一次性签名 | v0.1 开发版 | [接入指南](projects/wots-plus/docs/sdk.zh-CN.md#quickstart) |
| [纯模式 ML-DSA-44](projects/ml-dsa/README.zh-CN.md) | 评估在脚本中验证 FIPS 204 纯模式 ML‑DSA‑44 签名 | v0.1 开发版 | [接入指南](projects/ml-dsa/docs/sdk.zh-CN.md#quickstart) |

先用原生 P2PKH 跑通第一笔付款。七个项目在 TypeScript、Rust、Go 和 Python 中使用同一套钱包调用，各项目指南说明签名器参数、模板选项和本地依赖。 [钱包 SDK 快速接入](shared/sdk/README.zh-CN.md)

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
