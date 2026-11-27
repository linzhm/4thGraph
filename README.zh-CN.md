# 4thGraph

[English](README.md) · **简体中文**

> **用 Forth 写比特币合约，让应用状态随交易延续。**

4thGraph 是面向 BSV 的合约描述语言（SDL）和工具链。你可以在同一个项目里定义花费条件、管理 UTXO 状态、构建相互依赖的交易，并为适合在链下完成的计算生成零知识证明，在链上验证结果。

**[用 Agent 开始](#start-with-agent)** · [开发与调优](#develop-and-tune) · [可运行项目](#project-index) · [钱包 SDK](sdk/README.zh-CN.md) · [文档](docs/README.zh-CN.md) · [实测结果](#results)

---

<a name="why-4thgraph"></a>

## 为什么从整条交易链开始？

脚本构建工具通常关注一笔花费，检查解锁数据能否满足这把锁。开发代币钱包还得追踪一连串花费。Alice 付给 Bob 的 275 枚代币，怎样才能成为 Bob 下一笔付款的有效输入，同时保证两次转账都没有凭空增加代币？

### 两笔相连的 Token 付款

沿**实线**追踪代币从哪个输出（`vout`）产生，又被哪个输入（`vin`）花费。**虚线**标出 Groth16 证明和持有人签名进入验证器输入的位置。

```mermaid
flowchart LR
    accTitle: 代币输出及实际花费它们的输入
    accDescr: Alice 付给 Bob 275，Bob 的下一笔付款用输入 2 花费这个输出。每笔结算的输入 1 用 Groth16 证明和持有人签名解锁验证器。
    companion["伴随锁 · vout[0]"] -->|"vin[0]"| tx1(["TX₁<br/>Alice → Bob"])
    verifier["验证器锁 · vout[0]"] -->|"vin[1]"| tx1
    proof1(["π₁ · Groth16<br/>+ 持有人签名"]) -.->|"vin[1]"| tx1
    mintA["铸造 A · vout[1]<br/>代币锁 · Alice 300"] -->|"vin[2]"| tx1
    mintB["铸造 B · vout[1]<br/>代币锁 · Alice 200"] -->|"vin[3]"| tx1
    tx1 --> bob["vout[0] · 代币锁<br/>Bob 275"]
    tx1 --> alice["vout[1] · 代币锁<br/>Alice 225"]
    bob -->|"vin[2]"| tx2(["TX₂<br/>Bob → Carol"])
    mintC["铸造 C · vout[1]<br/>代币锁 · Bob 150"] -->|"vin[3]"| tx2
    proof2(["π₂ · Groth16<br/>+ 持有人签名"]) -.->|"vin[1]"| tx2
    tx2 --> carol["vout[0] · 代币锁<br/>Carol 350"]
    tx2 --> change["vout[1] · 代币锁<br/>Bob 75"]
    classDef lock fill:#ddf4e9,stroke:#34735d,color:#153b30
    classDef tx fill:#ffdfb5,stroke:#946835,color:#3c2d22
    classDef proof fill:#eee8fb,stroke:#8263a8,color:#402a61
    class companion,verifier,mintA,mintB,mintC,bob,alice,carol,change lock
    class tx1,tx2 tx
    class proof1,proof2 proof
```

> **跟着 Bob 的 275 枚代币。** 第一笔把 300 和 200 分成 Bob 的 275 和 Alice 的找零 225。第二笔通过 `TX₂.vin[2]` 花费 `TX₁.vout[0]`，把这 275 和另一枚 150 分成 Carol 的 350 和 Bob 的找零 75。

两笔付款各用一对新的伴随输出和验证器输出，图中在第一笔展开这对锁。代币锁要求本次花费同时消费规定的伴随输出。伴随锁核对实际花费的验证器，验证器用 `vin[1]` 提供的证明和签名检查这笔转账，把数量守恒和授权绑定到实际输入、输出。

---

<a name="start-with-agent"></a><a name="start-with-ai"></a><a name="pels-counter"></a>

## 用 Agent 开始

在 Codex 等能读写文件、运行命令的编程 Agent 中打开这个仓库，把下面的话发给它。

```text
读 skills/4thgraph/SKILL.md，用 PELS Counter 写一个从 0 开始的计数器。
每笔花费只能加一，唯一的后继输出必须保留同一条规则。
用项目工作区保存源码，编译完整锁，给我一条可复跑的命令。
如果能运行 regtest，演示 0 → 1 → 2，再试一次从 0 直接跳到 2。
```

> [!TIP]
> **验收结果**
>
> 检查 Agent 生成的 Forth 规则和完整锁。运行 regtest 后，两笔加一交易应当入块。BSV Node 和 chain-gang 都应拒绝从 0 直接跳到 2 的花费。[计数器源码与复放](projects/pels-counter/README.zh-CN.md)

<a name="4thg-quickstart"></a>

[手工配置 CLI 与 Agent skill](docs/install.md)

<a name="develop-and-tune"></a>

## 用 Agent 开发和调优

先用高层 Forth 写合约的花费条件和状态转换，固定基线及验收夹具。工具把可复跑的调优路径并列展示，Agent 选择本轮值得比较的候选。

```mermaid
flowchart TD
    forth["高层 Forth · 输出、状态和授权"] --> baseline["冻结基线、夹具和目标"]
    baseline --> source["Forth 实现 · 固定编译计划"]
    baseline --> passes["编译 pass 和顺序 · 固定源码"]
    baseline --> layout["合法的交易与见证布局 · 固定合约"]
    source --> agent["Agent 选择候选批次和预算"]
    passes --> agent
    layout --> agent
    agent --> evaluate["编译候选并用固定评估器验证"]
    evaluate --> report["输出判定、成本和产物哈希"]
    report --> agent
    report --> selected["保存选定计划并复跑结果"]
```

下面列出 Agent 可以选择并复跑的已登记路径。

```sh
PYTHONPATH=src:. python3 -m fourthgraph.workflow.protocol experiment capabilities
```

按指南提交候选批次、核对固定评估结果并复跑选中的构建。 [Agent skill](skills/4thgraph/SKILL.md)

<a name="capabilities"></a><a name="project-index"></a><a name="p2pkh-example"></a><a name="p2pk-example"></a>

## 按开发目标选择项目

| 我想做什么 | 可以从这里开始 |
| --- | --- |
| 构建付款、接入签名器 | 用原生 P2PK 或 P2PKH 生成锁和签名交易，再从 TypeScript、Rust、Go 或 Python 调用同一套钱包接口。[付款脚本](projects/p2pk-p2pkh-baseline/forth/README.md) · [钱包 SDK](sdk/README.zh-CN.md#quickstart) |
| 让状态跨交易延续 | 修改计数器的状态转换，观察错误的计数、金额或后继脚本怎样使花费失败。[PELS Counter](projects/pels-counter/README.zh-CN.md) |
| 让参与者分别提交、最后结算 | 在同一份 Forth 里声明分支和汇合，比较一次提交与分笔提交所需的交易、签名和字节数。[工作流示例](projects/workflow-examples/README.zh-CN.md) |
| 为计算生成零知识证明 | 从同一份受支持的状态关系生成 Script 或 Circom，使用匹配的设置文件和见证生成 Groth16 证明，再验证它与实际花费的绑定。[证明计数器](projects/proof-counter/README.zh-CN.md) · [Groth16 验证器](docs/groth16-bls12-381.md) |

[浏览全部项目](projects/README.zh-CN.md)

<a name="results"></a><a name="4thg-comparisons"></a><a name="transaction-costs"></a>

## 从实测看构建结果

- **脚本优化省下多少交易字节？** P2PKH-R1 编译器从 v0.7.0 迭代到 v0.8.0 后，两进两出 BIP143 ALL 付款从 83,294 B 降到 **82,998 B**，OTDA ALL 付款从 94,632 B 降到 **93,612 B**。 [P2PKH-R1 实测结果](projects/p2pkh-r1/README.zh-CN.md#实测结果)
- **链上验证一份证明要付出多少成本？** 在同一份 BLS12-381 Groth16 证明、同一组固定公开输入下，4thGraph 的部署加一次花费共 **280,731 字节**，受测 nChain 配置为 **393,553 字节**。两种花费都在 BSV regtest 入块。[实验条件、原始数据与交易 ID](projects/proof-counter/reference/fixed-statement/README.md)

[全部项目成果](showcase/README.md) · [钱包交易成本明细](docs/benchmark.zh-CN.md#transaction-costs)

**BIP143 / OTDA** 表示这里比较的两种 BSV 签名摘要格式。两种格式均设置 `SIGHASH_FORKID`（`0x40`）。BSV 的 BIP143 格式使用交易各部分的哈希，Chronicle OTDA 加设 `0x20` 位，使用原始交易摘要算法。 [BIP143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki) · [Chronicle](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release)

<a name="architecture"></a><a name="toolchain"></a>

## 工具链架构

| 层次 | 开发者写什么，工具交付什么 |
| --- | --- |
| **语言与标准库** | 用带类型的 Forth 词描述计算，用合约声明描述参与角色、交易依赖和状态转换。编译器检查栈效果和数值范围。[SDL 规范](docs/language/specification.md) · [中文语法](docs/language/syntax.md) · [English syntax](docs/language/syntax.en.md) · [标准库](docs/language/stdlib.zh-CN.md) |
| **编译与规划** | 编译器生成 BSV Script，规划器比较满足约束的交易布局及成本。证明后端为支持的关系生成电路和验证器。[工具链手册](docs/toolchain.md) |
| **运行与验证** | 运行器绑定实际父输出、请求签名并组装见证。复放报告把构建产物与实际交易、BSV Node 和 chain-gang 的判定对应起来。[仓库目录](docs/repository-layout.md) · [复放流程](docs/toolchain.md#复放与编译) |

**递归证明是研究方向。** 上图的 Token 转账逐笔验证直接父输出与本次状态转换。递归方案还要在新证明中核验前序证明，并把前序证明认证的状态绑定到本次实际花费的输出。[当前工具链支持的验证路径](docs/language/stdlib.zh-CN.md#验证路径)

---

## 许可证

4thGraph 采用 [MIT 许可证](LICENSE)。
