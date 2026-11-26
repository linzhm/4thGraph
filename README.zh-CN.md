# 4thGraph

[English](README.md) · **简体中文**

> **用 Forth 构建 BSV 上的比特币合约，从源码到可验证的花费。**

4thGraph 把脚本判定、UTXO 状态管理、跨交易合约构建和零知识证明流程放进一套工具链。基于 Forth 的 SDL 描述每笔花费必须证明什么、哪个输出承载下一状态，以及交易之间如何依赖。仓库提供编译器、标准库、可运行项目、多语言钱包 SDK 和 Codex skill。

**[用 AI 开始](#start-with-ai)** · [工具链能力](#capabilities) · [架构](#architecture) · [终端快速上手](#4thg-quickstart) · [项目](projects/README.md) · [成果](showcase/README.md)

<a name="start-with-ai"></a>

## 用 AI 写第一个比特币程序

准备好 Python 3.11 或更新版本，在 Codex 打开这个仓库并粘贴下面这段提示。Codex 可以直接读仓库里的 skill，并在本地工作空间安装编译器。

```text
阅读 skills/4thgraph/SKILL.md。用 PELS Counter 项目做一个 BSV 计数器。
从 0 开始。每次花费必须加一，只创建一个后继输出，并保留同一套计数规则。

把 Forth 源码和构建 JSON 放到 projects/pels-counter/workspace/。
用 4thGraph 编译，再用 PELS 项目的运行器构建完整锁。给我源码、
可复跑的命令和锁定脚本字节数。如果能运行 regtest，复放 0 → 1 → 2，
再检查错误的下一状态会被拒绝。使用项目里的公开测试夹具。
```

先检查 Forth 和构建产物。验证完整合约时，再查看复放报告里的引擎判定，确认正确花费通过、错误的后继被拒绝。 [计数器项目](projects/pels-counter/README.md) · [安装 Codex skill](docs/install.md#codex-agent-skill)

---

<a name="capabilities"></a>

## 一套工具链可以构建什么

| 能力 | 4thGraph 做什么 | 运行示例 |
| --- | --- | --- |
| **锁定与解锁脚本判定** | 把带类型的 Forth 编译为锁定 Script，并构造花费见证。复放用实际前输出的锁校验解锁数据，以 BSV Node 和 chain-gang 核验交易。 | [原生付款锁](projects/p2pk-p2pkh-baseline/forth/README.md) |
| **状态管理** | 用 UTXO 承载合约状态。每次花费验证状态转换，并把新状态和规则写入约定的后继输出。 | [PELS 计数器](projects/pels-counter/README.md) |
| **跨交易合约** | 规划交易依赖，比较符合约束的融合、拆分和串行布局。运行时绑定实际父输出的 outpoint，并请求每笔花费所需的签名。 | [交易工作流](projects/workflow-examples/README.md) |
| **零知识证明构建** | 把受支持的关系编译为 Circom。使用匹配的设置文件和见证生成 Groth16 证明，并构建将公开信号绑定到实际花费的 BSV 验证器。 | [证明计数器](projects/proof-counter/README.md) · [Groth16 后端](docs/groth16-bls12-381.md) |
| **递归证明构建** · 研究方向 | 研究在同一个电路里核验已认证的前序状态证明和下一次转换。状态通过后继 UTXO 连续推进的过程已有带入金的复放。 | [验证范围](docs/language/stdlib.md#验证路径) · [状态复放](projects/pels-counter/README.md#spend-and-verify-on-regtest) |

<a name="why-4thgraph"></a>

## 为什么需要 4thGraph？

同一条合约规则在数据和签名能同时到齐时，可能一笔交易就能完成。参与者必须独立提交时，工作流可能需要中间 UTXO 和后续汇合交易。这些选择会改变锁定脚本、见证和整条路径的成本。4thGraph 将规则和交易约束写在同一份 Forth 源码里，让候选布局可以用同一组输入构建和复放。 [工作流示例](projects/workflow-examples/README.md)

4thGraph 用三项设计实现这一点。栈效果和数值范围为 Script 优化提供依据。构建报告列出符合约束的交易布局及各自的成本。受支持的 `relation:` 可以采用直接 Script 或证明路径，两条路径都检查状态和实际后继。 [SDL 规范](docs/language/specification.md) · [构建与复放手册](docs/toolchain.md)

<a name="architecture"></a>

## 架构

```mermaid
flowchart TD
    source["Forth SDL 和标准库"] --> frontend["带类型的词和合约声明"]
    frontend --> script["优化并生成 BSV Script"]
    frontend --> graph["规划 UTXO 状态和交易依赖"]
    frontend --> circuit["生成 Circom 并准备证明验证"]
    circuit -.-> recursive["递归证明构建（研究）"]
    script --> build["锁定脚本、交易计划和构建报告"]
    graph --> build
    circuit --> build
    build --> spend["绑定实际 outpoint、签名和见证"]
    spend --> replay["使用 BSV Node 和 chain-gang 复放并验证花费"]
```

交易运行器先解析符号输出引用，再请求签名。采用证明路径时，公开信号也绑定到经过认证的交易。复放报告将所选构建与实际交易、引擎判定和入块记录关联起来。 [完整目录](docs/repository-layout.md) · [复放与报告](docs/toolchain.md) · [成果](showcase/README.md)

---

<a name="4thg-quickstart"></a>

## 在终端运行 4thGraph

使用 Python 3.11 或更新版本。从 4thGraph 检出的根目录运行以下命令，将 CLI 安装到本地工作空间，再编译 PELS 计数器的递增词。

```sh
bash tools/setup-workspaces.sh
python3 tools/install.py --prefix workspace/toolchain
workspace/toolchain/bin/4thgraph projects/pels-counter/pels-counter.fth \
  --entry advance --optimize safe
```

JSON 输出列出 `advance` 入口、导入的 `std/u32` 和 8 字节的 Script 片段。接下来可以构建完整的计数器锁，或运行其他示例。 [安装指南](docs/install.md) · [PELS Counter](#pels-counter) · [P2PKH](#p2pkh-example) · [P2PK](#p2pk-example)

<a name="pels-counter"></a>

### PELS Counter

从 `0` 开始。每次花费把计数加一，并把同一套规则写入后继输出。

Forth 状态转换从标准库导入 `u32-inc`。完整示例会加上检查，把状态转换绑定到实际交易的后继输出。 [Forth 源码](projects/pels-counter/pels-counter.fth)

```forth
REQUIRE stdlib/u32.fth
: advance ( u32 -- u32 ) u32-inc ;
```

```sh
export PYTHONPATH=src:.
counter=projects/pels-counter/pels_counter.py
python3 "$counter" build
```

输出的 `script_hex` 是完整锁脚本。构建只用 Python 标准库。

在装有 `curl`、Rust/Cargo 和 C 编译工具链的 Linux x86-64 上，可以运行带入金的复放来验证花费。

```sh
python3 -m venv workspace/venv
. workspace/venv/bin/activate
python -m pip install ecdsa -r tools/requirements-chronicle.txt

bash tools/verify_node.sh --profile default -- python "$counter" replay \
  --output projects/pels-counter/workspace/build/pels-counter.json
```

复放先为 `0` 创建测试输出，再把 `0 → 1 → 2` 的两笔花费挖入区块。每次花费扣 **1,000 sat**。JSON 报告记录双引擎判定和入块结果。要单独构造花费，运行 `spend --parent` 并传入父交易原始字节。[花费与验证说明](projects/pels-counter/README.md#spend-and-verify-on-regtest)

<a name="p2pkh-example"></a>

<details>
<summary>P2PKH · 25 字节锁</summary>

```sh
python3 projects/p2pk-p2pkh-baseline/forth/payments.py --hash160 751e76e8199196d454941c45d1b3a323f1433bd6
```

锁中写入公钥哈希。花费时压入签名和公钥。 [Forth 源码](projects/p2pk-p2pkh-baseline/forth/p2pkh.fth) · [签名交易示例](projects/p2pk-p2pkh-baseline/README.zh-CN.md)

</details>

<a name="p2pk-example"></a>

<details>
<summary>P2PK · 35 字节锁</summary>

```sh
python3 projects/p2pk-p2pkh-baseline/forth/payments.py --public-key 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
```

锁中写入压缩公钥。花费时压入签名。 [Forth 源码](projects/p2pk-p2pkh-baseline/forth/p2pk.fth) · [签名交易示例](projects/p2pk-p2pkh-baseline/README.zh-CN.md)

</details>

---

<a name="toolchain"></a>

## 工具链与 SDL

编译器检查栈效果和数值范围，优化 Script，并比较符合约束的交易布局。`4thgraph-circuit` 为受支持的关系生成 Circom，`4thgraph-verify` 构建验证路径，`4thgraph-report` 汇总编译决策和已记录的复放结果。 [工具链手册](docs/toolchain.md) · [SDL 语言文档](docs/language/README.md) · [标准库](docs/language/stdlib.md)

安装 Codex skill 后，可以编写 Forth、比较编译产物并审查复放证据。钱包 SDK 支持 TypeScript、Rust、Go 和 Python。 [Codex skill](skills/4thgraph/SKILL.md) · [安装 skill](docs/install.md#codex-agent-skill) · [钱包 SDK](sdk/README.zh-CN.md#quickstart)

<a name="4thg-comparisons"></a>

## 4thG 项目改造与对照

| 项目 | 对照结果 |
| --- | --- |
| P2PKH-R1 Forth v0.3.0 探索版 | Forth 基线逐字节复现 v0.2.0 锁。优化后完整锁由 46,302 B 降到 **45,776 B**，两进两出 ForkID ALL 付款由 93,374 B 降到 **92,322 B**。复放还覆盖 OTDA，以及用 sCrypt 编译曲线内核的版本。[改造与复放](projects/p2pkh-r1/experiments/forth) |
| [BLS12-381 Groth16 验证器](docs/groth16-bls12-381.md)（开发中） | 用 Forth 编排链下证明的链上验证，支持全固定、混合以及花费时提供全部公开输入。[固定声明对照](projects/proof-counter/experiments/fixed-statement/README.md)使用相同的证明和公开声明测试 4thGraph 和 nChain。 |

<a name="project-index"></a>

## 钱包项目

钱包项目提供可识别的锁定模板、统一的外部签名 SDK 和可复放的完整签名交易。项目覆盖普通付款、P‑256 与 SM2 签名器接入、延迟启用，以及一次性签名和后量子签名的实验验证。

| 项目 | 适用场景 | 接入时的取舍 | 版本 | 钱包 SDK |
| --- | --- | --- | --- | --- |
| [原生 P2PK 与 P2PKH](projects/p2pk-p2pkh-baseline/README.zh-CN.md) | 钱包首次接入、普通 secp256k1 付款、交易成本对照 | 选择在输出里放公钥还是公钥哈希 | v0.1 开发版 | [接入指南](projects/p2pk-p2pkh-baseline/docs/sdk.zh-CN.md#quickstart) |
| [P2PKH-R1](projects/p2pkh-r1/README.zh-CN.md) | 接入已有 P‑256 签名设备或服务，或对照 Forth 编译的锁 | 核对设备的签名方式，并持久保存 P‑256 签名随机数历史 | [v0.3.0 Forth 探索版](projects/p2pkh-r1/README.zh-CN.md#version-history) | [v0.2.0 SDK 指南](projects/p2pkh-r1/docs/sdk.zh-CN.md#quickstart) |
| [P2PKH-R1-Deferred](projects/p2pkh-r1-deferred/README.zh-CN.md) | 先用短锁接收入金，可以稍后单独启用的场景 | 预留手续费输入和启用步骤，届时生成完整 R1 输出 | v0.2.0 开发版 | [接入指南](projects/p2pkh-r1-deferred/docs/sdk.zh-CN.md#quickstart) |
| [P2PKH-SM2](projects/p2pkh-sm2/README.zh-CN.md) | 接入 SM2 签名器或 GB/T 35275‑2026 SignedData 服务，或重建符合条件的 OTDA 输出 | 核对 SM2 消息和用户标识，使用 SignedData 时绑定预期签名者 | v1.1.0 候选版 | [接入指南](projects/p2pkh-sm2/docs/sdk.zh-CN.md#quickstart) |
| [P2PKH-Schnorr](projects/p2pkh-schnorr/README.zh-CN.md) | 向 BIP340 x-only 公钥哈希或 MuSig2 聚合公钥付款 | 使用外部 BIP340 签名器和 4thGraph 编译的模板 | v0.6.0 候选版 | [接入指南](projects/p2pkh-schnorr/docs/sdk.zh-CN.md#quickstart) |
| [Lamport OTS](projects/lamport-ots/README.zh-CN.md) | 比较 SHA‑256 一次性签名在完整公钥锁和公钥承诺锁下的开销 | 每个 UTXO 使用新密钥，在更小的入金锁和更小的花费输入之间取舍 | v0.1 开发版 | [接入指南](projects/lamport-ots/docs/sdk.zh-CN.md#quickstart) |
| [WOTS+](projects/wots-plus/README.zh-CN.md) | 研究更短的 SHA‑256 一次性签名及不同收款模板 | 管理一次性密钥，并比较缓存式锁和 OTDA 重建 | v0.1 开发版 | [接入指南](projects/wots-plus/docs/sdk.zh-CN.md#quickstart) |
| [纯模式 ML-DSA-44](projects/ml-dsa/README.zh-CN.md) | 验证 FIPS 204 签名互操作，评估大脚本的花费成本 | 使用纯模式签名器，验证目标节点和矿工的大脚本接收策略 | v0.1 开发版 | [接入指南](projects/ml-dsa/docs/sdk.zh-CN.md#quickstart) |

先用原生 P2PKH 跑通第一笔付款。统一 SDK 在 TypeScript、Rust、Go 和 Python 中提供同一套钱包流程。选定项目后，可按接入指南连接签名器、选择锁定模板并复放付款或启用交易。[钱包 SDK 快速接入](sdk/README.zh-CN.md)

<a name="transaction-costs"></a>

## 比较交易成本

P2PKH-R1 的两进两出 ForkID ALL 付款在 v0.1.0 为 **119,934 B**，在 v0.2.0 为 **93,374 B**，在 Forth v0.3.0 探索版为 **92,322 B**。Deferred 的入金锁为 **1,435 B**，启用时生成 **46,302 B** 的 R1 v0.2.0 锁。[R1 测量](projects/p2pkh-r1/README.zh-CN.md#完整交易与栈测量) · [Deferred 测量](projects/p2pkh-r1-deferred/README.zh-CN.md)

统一基准在提交 `beeb4dd` 测量了七个项目、32 种模板与签名模式组合，共 **260 笔完整交易**。混合输出和配对 `SINGLE` 另测 11 种组合，共 88 笔交易。Deferred v0.2.0 行采用提交 `9c5603d` 的重测结果。R1 Forth v0.3.0 行来自该实验有资金的 regtest 对照。 [R1 Forth 复放](projects/p2pkh-r1/README.zh-CN.md#forth-探索版)

| 项目和实测版本 | 输入 × 输出 | 上一输出锁 | ForkID ALL 解锁 | ForkID ALL 整笔 | OTDA ALL 整笔 | ForkID ALL 两栈载荷峰值 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 原生 P2PKH | 2 × 2 | 25 | 107 | 374 | 374 | 145 |
| P2PKH-R1 v0.2.0 | 2 × 2 | 46,302 | 326 | 93,374 | 101,250 | 3,479 |
| P2PKH-R1 Forth v0.3.0 探索版 | 2 × 2 | 45,776 | 326 | 92,322 | 100,192 | 3,478 |
| P2PKH-R1-Deferred 启用 | 3 × 2 | 1,435 | 197 | 93,259 | 93,260 | 359 |
| P2PKH-SM2 v1.1.0 候选版 | 2 × 2 | 144,925 | 291 | 290,554 | 316,018 | 4,147 |
| Lamport OTS 公钥承诺模板 | 2 × 2 | 7,746 | 16,549 | 48,708 | 79,616 | 16,707 |
| WOTS+ 缓存步骤及重建模板 | 2 × 2 | 33,956 | 2,310 | 72,650 | 79,090 | 2,701 |
| 纯模式 ML-DSA-44 | 2 × 2 | 926,412 | 2,588 | 1,858,122 | 5,563,725 | — |

单位均为字节。锁定、解锁和栈开销取 ForkID ALL 的第一个输入。栈峰值由本地求值器测得，统计主栈与备用栈的合计数据载荷。Deferred 启用交易包含一条手续费赞助输入。ML‑DSA‑44 暂无栈数据。各项目 README 列有逐输入、逐输出的大小、增量成本和生命周期总量。

R1 v0.2.0 和 WOTS+ 缓存步骤模板的 OTDA ALL 数据取自显式启用重建的实测。

SM2 候选版沿用 v1.0.0 的锁定模板 `1`，自动选择更短的 OTDA 解锁编码。实测两进两出 OTDA ALL 交易的每个输入解锁脚本从 290,109 字节降至 13,023 字节，整笔从 870,194 字节降至 316,018 字节，缩小 63.7%。[SM2 重建测量](projects/p2pkh-sm2/README.zh-CN.md#otda-constructor)

## 复现结果

基准指南给出在 BSV Node 1.2.3 和仓库固定版本的 chain-gang 上复放签名交易的方法。各项目首页另有协议规范、安全分析、验收用例和 SDK 入口。[统一基准指南](docs/benchmark.zh-CN.md)
