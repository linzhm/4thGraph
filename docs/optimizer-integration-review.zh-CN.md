# PELS 标准库模板族与编译器优化接入评审

**ForthGraph 表达程序，编译器选择交易实现。** Forth 源码定义业务计算、状态推进、授权与必须满足的约束。编译器依据编译目标选择合法的交易切割和每个锁的实现。PELS 是这些锁可调用的标准库模板族。BIP143、OTDA、双模式及更多组合由编译器按目标选型和链接。组装器使用最终 Script、交易计划和各花费路径的见证布局。

本次实测冻结两个版本。主线快照 `5fef0b7` 已合入 #82 的公式开关和 #83 的 PELS 组件。本地实现分支的评审基线为 `96eff50`，含项目包及实验入口，与主线的共同祖先是 `db63d62`。下文标注了分别在哪个版本验证过，两个版本的组合仍待集成。[主线 #82](https://github.com/linzhm/4thGraph/pull/82) · [主线 #83](https://github.com/linzhm/4thGraph/pull/83) · [本次测量及引擎判定](reviews/optimizer-integration/measurements.json)

交付前复核远端 `main` 为 `70e6536`。新增 #84 将项目 README 改为由 manifest 生成，实测涉及的 PELS 汇编词、编译器和标准库源码与上述快照相同。后续接到该主线时，计数实例的项目简介应写入 `projects/pels-counter/manifest.yaml` 并重新生成 README。[主线 #84](https://github.com/linzhm/4thGraph/pull/84)

## 从程序目标到交易计划

| 层 | 需要表达或交付的内容 |
|---|---|
| ForthGraph 程序 | 定义业务值怎样产生、在哪些条件下推进到后继状态、谁授权、哪些效果必须原子完成、哪些阶段必须能独立提交。普通词描述计算，`lock:` 表达单笔花费的明确约束，工作流表示跨交易的依赖。 |
| 编译目标 | 声明交易版本范围、适用链规则、签名算法策略，以及按整路字节、最大单笔或确认依赖衡量的编译目标。可接受的中间状态和交易边界由程序约束和目标签名者可用性共同决定。 |
| 编译器及链接器 | 先比较满足程序约束的交易计划，例如融合成一笔、拆成顺序相连的多笔，或在程序允许时并行后汇合。再为每个锁匹配 PELS 和授权原语并链接字节。只有各步骤合起来兑现同一个程序目标，才进入成本排序。 |
| 组装器 | 根据具体交易计划、精确 Script 及见证布局绑定实际 UTXO，按输入角色和路径准备签名材料并组装交易。 |

同一份程序可以编译成不同的交易图。若程序要求“这一笔交易同时支付并发出回执”，两项效果须留在同一花费。若程序允许先推进状态、后完成发放，串行计划须为中间 UTXO 写清状态和授权，并让下游绑定实际父输出。新的中间阶段只有在其可观察状态及独立提交条件满足程序契约时才合法。现有 Workflow 已有融合、串行与双输入原子布局，以及排除不符合授权或独立提交要求的候选。更一般的切割由该模型逐步支持。[现有工作流布局](toolchain.md#两阶段状态工作流的三种布局) · [交易图](../src/fourthgraph/workflow/transaction_graph.py)

**普通 R1 锁的业务语义只有两项。** 构建时绑定 R1 公钥的 HASH160。花费时验证给出的公钥匹配该哈希，并用这个公钥验证当前花费的 R1 签名。应用在 Forth 里调用表达这一语义的授权词。原像格式、逆元等见证辅助材料、点运算及栈排列由编译目标与后端实现决定。组装器依所选路径完成见证。只有当应用还明确要求特定后继输出时，编译器才需要匹配额外的 PELS 约束。[现有 R1 项目接口和验收](project-contracts.zh-CN.md#做一次构造测试)

## PELS 的 Forth 接口评审

### 用什么模板验证什么内容

成员契约写清输入形状、输出约束、需要认证的字段、每条花费路径的 sighash 和见证布局。Forth 作者写左栏的交易语义，编译器按右栏匹配原语并决定安排。各成员可复用手写汇编的编码和交易绑定基础件。

| 应用要求 | 可选成员及须兑现的承诺 |
|---|---|
| 唯一后继，状态或金额依赖实际前序金额 | 先用 BIP143 ALL（`0x41`）。它在原像中承诺当前前序金额，用 `hashOutputs` 绑定完整有序输出。已有单输入、唯一后继的 PELS 原型。 |
| 唯一后继或有序多输出，金额由合约规则直接确定 | 可做 BIP143 ALL 或 OTDA ALL（`0x61`）的明确成员。两者都能验证完整输出向量，BIP143 用输出哈希，OTDA 把输出计数及序列化输出写入原像。多输出成员需声明构造的完整顺序，例如先付款、再写回执。Workflow 已验证这种构造。 |
| 只约束与本输入同索引的输出，其他输出留给交易构造者 | 可另评审成对的 SINGLE 成员。它能承诺对应输出的金额和脚本，约束范围限于该输出。OTDA SINGLE 缺少同索引输出时没有可序列化的交易原像，排除在这类成员的花费域之外。 |
| 只验证已覆盖的输入或原像字段，例如当前 outpoint、`nLockTime` | 可评审更小的成员，具体由签名模式决定。`NONE` 对输出无承诺，`ANYONECANPAY` 对输入只覆盖当前项。若模板要求全体输入或输出，构建时应拒绝覆盖不足的组合。 |

**OTDA 的金额边界。** OTDA ALL 覆盖本笔输出金额，原像里没有当前 **prevout** 的金额。若应用需要“前序金额减手续费”，OTDA 成员须另有链上认证的前序证据，例如在 Script 里把父交易哈希和 vout 绑定到已认证的实际 outpoint，再读取该输出的金额。钱包校验金额仍是宿主自己的职责。没有这项链上证据的金额依赖规则，构建时仅允许 BIP143 路径。[本仓库原像序列化](../src/fourthgraph/bsv/transaction.py) · [Workflow 覆盖检查](../src/fourthgraph/workflow/gforth.py) · [BIP143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki) · [BSV Chronicle](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release)

**双模式是一份锁、两条明确的花费路径。** `both` 从同一锁分别走 `0x41` 或 `0x61`，每次花费选择其一。多模式沿用相同约定。对于同一个公开的业务入口，每条路径都必须证明相同的约束，并绑定自己的见证布局、签名类型、`scriptCode` 和实际输入。共用词可返回同样的业务结果，或返回带模式的已认证原像。锁内分支必须验证所选模式及其布局。宿主按最终清单选取一条已编入的花费路径，准备及组装见证。若同一项目有两种业务意图，例如结算约束完整输出、另一条路径只约束成对输出，分别给这些业务入口命名，再按每条路径独立验收。

应用统一引用 `stdlib/pels.fth`。下文带 BIP143 名称的低层路径是已有的评审夹具。具体模式汇编由后端解析。每条花费路径的受约束字段、输入输出数量和见证布局由成员契约及最终清单给出。[当前构建命令](project-contracts.zh-CN.md#按编译目标构建-pels-锁)

Workflow 和单输入 PELS 锁均支持 BIP143、OTDA、双模式及自动构建。双模式用例使用固定 chain-gang 验证同一父输出的两路花费及 Chronicle 激活边界。新的独立锁使用 `pels-witness` 组装。项目 WASM 宿主仍验证 `0x41`，多模式的标准钱包包属于后续集成。[原像重建](../src/fourthgraph/workflow/forkid_lowering.py) · [Workflow 实跑](../tests/test_workflow.py) · [独立锁实跑](../tests/test_pels_lock.py)

### Forth 直接定义锁

独立锁沿用现有的 `lock:`、命名构建参数和普通 Forth 业务词。`tx-output` 构造一个预期输出，`outputs=` 按顺序断言完整输出列表，`tx-locktime` 表示当前花费已认证的原像字段。当前实现也支持断言前序金额等于常量，以及用字面量边界的 `DO` 或 `?DO` 循环构造输出列表。[锁语法](language/syntax.md) · [覆盖检查](../src/fourthgraph/workflow/gforth.py)

```forth
REQUIRE stdlib/pels.fth
bytes-param: recipient-lock 25 ;

: payout ( -- output ) 10000 recipient-lock tx-output ;
: receipt ( -- output ) 0 bytes-hex 006a055245414459 tx-output ;

lock: settle ( )
    1 inputs= verify
    payout receipt 2 outputs= verify
    tx-locktime 42 = verify
;
```

例中锁约定单输入、付款和回执两个有序输出，以及 `nLockTime = 42`。原像见证布局由编译器生成并交付给宿主。当前输出在构建时求值。动态状态、任意已认证字段运算和 R1 所有者授权的组合留作其他成员。断言真实前序金额时，`auto` 会排除 OTDA。显式要求 OTDA 或双模式会报告缺少认证金额。

### 编译目标选定交易签名规则

编译目标在构建入口统一选择。现有代码已经分别记录交易头整数版本 `nVersion`、执行时代及签名算法。这里把它们归入同一个目标配置。BIP143 与 OTDA 具体由 sighash 及适用链规则区分。例如格式版本 2 可使用 BIP143，在允许 Chronicle 的上下文也可使用 OTDA。现有 CLI 的交易目标与签名族参数可作为配置入口。[现有目标定义](../src/fourthgraph/workflow/protocol.py) · [签名算法实跑](../tests/test_workflow.py)

| 目标策略 | 编译器的选择 |
|---|---|
| `bip143` 或 `otda` | 目标固定摘要算法及其允许的 sighash。编译器核对完整的业务及授权覆盖，选定原语、见证编码和字节码布局。 |
| `both` 或显式模式集合 | 构建一份支持要求集合的锁，所有必需模式各有能实跑的路径。ALL 首例为 `0x41` 和 `0x61`，更广覆盖按相同规则组合。 |
| `auto` | 先用目标链规则、允许的 sighash、业务字段和兼容要求推导候选集合，再按稳定的成本目标选择。目标允许任选一种时可生成单模式，确需两路兼容时按双模式契约决选。 |

自动模式的选择发生在构建期。同一份锁源码可以按不同目标生成 BIP143、OTDA 或双模式的精确锁。业务约束在各目标下都要成立。无法满足时，编译器报告缺少的认证事实或链规则。构建产物绑住交易版本及执行条件、每条路径的实际 sighash、见证布局、`scriptCode` 和签名锚点。组装器按清单选择已编入的路径并构造见证。模板版本标识这一份精确构建，用来匹配实际 UTXO。

### 编译器怎样完成选择

| 阶段 | 选择规则和记录 |
|---|---|
| 推导契约 | 从 Forth 声明与调用图得到交易形状、输出顺序、认证字段、明确要求的模式集合、目标链规则及栈边界。原始汇编词的潜在失败和字段需求由其登记契约给出。模式集合按精确 sighash 值规范化，重复声明的顺序没有意义。 |
| 查已验收实现 | 从原语目录查找满足契约的实现。目录记录实现和版本、覆盖及前提、输入输出与备用栈效果、编码、见证布局、插入点、签名锚点及验证证据。同一契约可有完整原像、紧凑重建和专用汇编等多种实现。 |
| 枚举合法组合 | 双模式和多模式由能满足整套要求的片段组合实现。枚举各路径实现、可共用的输出构造和前缀、以及确实会改变布局的分支顺序。按精确模式、可用链规则、栈效果及锚点筛选。若某已声明模式没有匹配项，报错并列出缺少的条件。 |
| 优化并链接 | 业务公式走现有 pass。已认可的原语按插入点链接，重新定位实际 `CODESEPARATOR`、签名锚点和 `scriptCode`。按完整锁及各路径的真实见证获得最终候选成本。 |
| 决选及复跑 | 在所有满足同一契约的已验收候选中按固定目标排序。建议交易路径字节为首要目标，Script 字节与栈上限是可配置约束，等值按稳定实现 ID 取舍。多路径目标应明确使用最大路径成本或给出固定权重，同时记录每路指标。发布构建使用冻结的目录版本、目标及计划，报告记录实际选中的实现、布局、候选淘汰原因和复跑证据。 |

模式组合按业务入口或交易阶段表达。一个入口要求 `{0x41, 0x61}` 就编出同一锁的两个分支，单路候选虽短也无法满足契约。若两笔连续花费的锁各支持这两种模式，验收轨迹为 `41→41`、`41→61`、`61→41`、`61→61` 四种。相邻步骤引用上一笔真实的 outpoint。只有业务明确要求不同阶段固定不同模式时，编译器才据各阶段独立的模式集合生成相应单路锁。

完整选择覆盖目录里所有登记的模式集合与原语组合，缺少合法实现时返回具体前提。最优性以同一契约、候选目录、用户目标和验证覆盖为范围。单路最短的两个片段可能需要不同的上下文或栈布局。共用输出构造、分支跳转、见证长度和 CompactSize 编码都在链接后的整路比较里计入。小空间穷举合法选择，较大空间报告候选数、剪枝及预算。手写汇编仍可单独做优化，再用同一契约产出新的可选实现。

研发验收用实际签后夹具提供度量，普通编译使用固定的目录和可复现成本规则。已知结构取链接后字节，依赖签名编码等数据的指标使用声明过的估算或冻结样本。采用新方案时记录完整原语版本与构建输入，旧模板由具体字节和清单继续识别。

### 已运行的低层 Forth 夹具

这是使用前序金额的 BIP143 ALL 成员实例。文件名标明单输入和唯一输出。源码沿用现有的 `REQUIRE 文件名` 和 Forth 调词语法。以下片段已经在临时库目录内编译和执行，公开安装路径和两个新词仍待标准库登记。[完整 Forth 示例](reviews/optimizer-integration/output-preimage.fth)

```forth
REQUIRE stdlib/pels/bip143-all-1in-1out.fth

: expected-output0 ( script -- script )
    ( Keep the five-byte state and serialize the previous amount. )
    op-8 op-num2bin
;

: require-output-and-time ( script -- script )
    bsv-empty expected-output0 pels-verify-preimage
    bytes-hex 2a000000 pels-assert-locktime
;
```

| 引用 | 构建期 | 花费时承诺 |
|---|---|---|
| `expected-output0` | 应用提供一个生成规则片段的词，名字由作者选择。 | 此例输入为当前五字节状态和前序金额，返回后继状态字节与八字节小端金额。标准库用它们和当前执行代码构造**唯一有序输出**，核对整笔交易的 `hashOutputs`。 |
| `pels-verify` | 已有底层词接收前缀与规则两段 Script。 | 输入 `tail head state`，返回与当前输入绑定的摘要。只需要授权摘要的调用者可直接使用它。 |
| `pels-verify-preimage` | 本次试验的同成员入口，参数同上。 | 保留重建的完整原像，用其 HASH256 交给同一原生签名绑定，成功才留下该原像供后续断言。见证送来的 head/tail 单独使用时没有这一保证。 |
| `pels-assert-locktime` | 接收前缀与恰好四字节的期望值，按 wire 小端编码，例中为 42。 | 输入为上一步留下的已认证原像，相等时原样保留，失配时验证失败。调用方需要摘要时可继续 `op-hash256`。检查更多字段时，只开放该成员实际承诺的字段。 |

这里的“控制”是花费的接受条件。宿主构造候选，Script 验证其输出和 preimage。该成员不能表达任意数量的输出；另一种输出向量需有自己的完整序列化、签名覆盖和公开入口。`script` 类型本身无法证明一段任意栈数据已经过认证，因此公开组合和测试都从 `pels-verify-preimage` 返回的同一值继续。[试验库的手写指令及栈效果](reviews/optimizer-integration/stdlib/pels/bip143-all-1in-1out.fth)

以关闭全部公式 pass 的方式构建该示例，完整锁 **629 B**。固定 chain-gang 实跑三笔独立夹具，各自根据自己的交易重算见证。保留 10,000 sat 且 `nLockTime=42` 通过，仅将锁定时间改为 43 或仅将输出降为 9,999 sat 均被拒绝。这验证的是 Script 自己的两项接受条件。[执行器](reviews/optimizer-integration/verify_output_preimage.py) · [实测回执](reviews/optimizer-integration/measurements.json)

### 手写汇编与编译器的接口

手写汇编负责精确编码、交易绑定和栈排列，可以由小汇编器直接发射，也可以像 #83 一样用 Forth 的 `op-*` 构造词逐条生成。标准库交付版本、固定片段或摘要、规则插入点、栈契约和签名锚点。链接后另记完整 Script 的摘要。业务规则是显式插入的可变片段，其长度可以移动后段偏移，故签名锚点按最终布局核对。库内手调实现独立建候选版本，沿用相同语义夹具逐字节和逐交易比较。编译器计划止于该边界，禁止越过规则插入点或对链接后的已认可基础件再做 peephole。

主线实现可直接验证这一边界。对同一份标签规则使用 #82 的全部 12 组合法计划，`pels-verify` 含该规则的段始终为 **636 B，SHA-256 完全相同**。这是现有手工排列的证据，最短长度仍须单独测量。[段摘要与计划](reviews/optimizer-integration/measurements.json)

### 主线已经具备的组合

主线上已经有一段可以直接读懂的组合。项目先交给 PELS 一段状态和金额规则，再把已认证的交易摘要交给 R1 所有者验证。调用者不用手排原像、签名或中间栈槽。[主线组合源码](https://github.com/linzhm/4thGraph/blob/5fef0b71bb93507fb1d0206d7d72e3d692a74847/projects/p2pkh-r1/forth/r1-pels-lock.fth)

```forth
: r1-pels-body ( script -- script )
    bsv-empty increment-and-pay-fee pels-verify
    bsv-owner r1-verify-owner
;
```

| 归属 | 已实现及其边界 | 建议保留的接口 |
|---|---|---|
| 标准库模板族 | #83 的词位于 R1 项目内，可独立 `REQUIRE`。当前成员限定 BIP143 ALL、单输入、唯一后继、五字节状态前缀和保持执行代码。 | 按成员登记交易形状、编码、签名覆盖、构造参数、失败条件、主栈及备用栈效果。其他成员可有自己的契约。 |
| 后继检查及原像认证 | `pels-assert-successor` 接受完整原像，外层须认证同一份消息。`pels-verify` 用见证 head/tail 和规则产生的后继重建原像，绑定当前输入后返回摘要。 | 公开入口优先提供已认证结果。使用可组合的底层检查词时写清调用方义务。规则从当前状态、前序金额产生序列化的后继状态和金额。 |
| 应用与钱包 | 主线组合的 `+1 / 1000 sat` 与独立夹具的 `+2 / 500 sat` 验证规则可替换。本分支的 `pels-counter` 是另一套完整原像实例，使用 `advance.wasm`。 | 项目决定状态含义、金额策略、授权角色和见证。宿主按实际 prevout、路径和已认可的精确模板选择模块，不凭族名签署。 |

**对“符合标准”的判断。** 组合使用了 Forth 习惯的短词、冒号定义、显式栈效果和显式依赖。`:` 属于 Forth Core，`REQUIRE` 属于 File-Access 扩展词集。`script` 类型、`bsv-*`、`op-*` 和构建期片段拼接依赖 4thGraph。比如 `swap` 交换构建参数，`op-swap` 向 Script 写入一条运行时指令。仅看 `( script script -- script )` 无法推断花费时的栈效果。合适的表述是“采用 Forth 2012 习惯，符合仓库支持的 Forth 子集，带显式 BSV 扩展”。本次没有验证完整 Forth 2012 系统一致性或跨解释器可移植性。[Forth Core 冒号定义](https://forth-standard.org/standard/core/Colon) · [Forth REQUIRE](https://forth-standard.org/standard/file/REQUIRE) · [Forth 一致性范围](https://forth-standard.org/standard/usage) · [4thGraph 语法](language/syntax.md)

**哪一层已经好读。** 上面的项目组合让人看见授权依赖的是哪一次推导。再往下一层，`pels-read-script-code` 仍直接写了按 104 字节切分及 CompactSize 宽度选择，`increment-and-pay-fee` 也手排了数值编码和栈操作。前者宜留在有标准字节向量的序列化词里，后者宜把“推导后继状态”和“推导金额”各自命名，保持编码交界明确。评审高层源码时，应能指出每个关键结果来自哪个词；编译器决定该值是否占槽。只有测过成本的低层片段才需要保留手工排栈。[后继构造词](https://github.com/linzhm/4thGraph/blob/5fef0b71bb93507fb1d0206d7d72e3d692a74847/projects/p2pkh-r1/forth/pels-successor.fth)

**动态后继成员升入标准库的验收。** 登记公开词及依赖摘要，用栈底哨兵测试两栈保留，并把下面的非计数实例纳入回归。记录各实例的钱包支持域。本分支的 `u32-inc` 允许回绕，`advance.wasm` 在最大值拒绝准备，须分开验证这两个边界。[后继构造](https://github.com/linzhm/4thGraph/blob/5fef0b71bb93507fb1d0206d7d72e3d692a74847/projects/p2pkh-r1/forth/pels-successor.fth) · [认证入口](https://github.com/linzhm/4thGraph/blob/5fef0b71bb93507fb1d0206d7d72e3d692a74847/projects/p2pkh-r1/forth/pels-verify.fth) · [实例钱包策略](../projects/pels-counter/contract/main.go)

**非计数调用已经跑通。** 评审夹具在主线原有的 `pels-verify` 上组合了一个两态标签规则。“草稿”与“就绪”分别编码为 3、9，实际前序走完 `3 → 9 → 3`，两步保留金额，使用该成员原有的单输入、单后继及五字节布局。独立期望值从实际前序复制代码、替换标签并序列化输出。初始锁 645 B，两笔花费各 1,478 B，固定 chain-gang 均通过。该结果验证了非计数规则复用、实际前序和成功花费。它是评审夹具，尚无钱包包及公开模块登记。[Forth 规则](reviews/optimizer-integration/status-labels.fth) · [执行器](reviews/optimizer-integration/verify_status_labels.py) · [逐笔回执](reviews/optimizer-integration/measurements.json)

从仓库根目录，在已安装固定 chain-gang 的 Python 环境里可重放。命令把已核对的主线提交导出到新的临时目录，确保编译器和 PELS 组件来自同一提交。

```sh
snapshot=$(mktemp -d)
git archive 5fef0b71bb93507fb1d0206d7d72e3d692a74847 | tar -x -C "$snapshot"
PYTHONPATH="$snapshot/src${PYTHONPATH:+:$PYTHONPATH}" python docs/reviews/optimizer-integration/verify_status_labels.py \
  "$snapshot/projects/p2pkh-r1/forth"
PYTHONPATH="$snapshot/src${PYTHONPATH:+:$PYTHONPATH}" python docs/reviews/optimizer-integration/verify_output_preimage.py \
  "$snapshot/projects/p2pkh-r1/forth"
```

## 已积累哪些优化

| 类目 | 现有实现和使用条件 | 实验入口或证据 |
|---|---|---|
| 类型、范围和控制流 | `safe` 依据已知区间省去多余回绕或余数计算，比较值仅供 IF 时可直接使用条件。保留返回给调用方的完整 Forth flag。裸输入类型只是声明，采用范围前提须能指到入口检查或证明。 | [范围](../src/fourthgraph/compiler/ranges.py) · [词降级](../src/fourthgraph/compiler/lowering.py) |
| 纯公式改写及特化 | 有界 ScriptNum 公式支持特定交叉项、乘二转加、融合栈底缓存除数的装载。常量绑定只适用于调用点确定的值，须保留数值范围、编码及除数前提。 | [公式发射](../src/fourthgraph/compiler/script_formula.py) |
| 图共享、活跃值、最后使用 | 图按操作、操作数及 kind 识别可共享节点，从返回值回溯活跃定义。最后一次使用可以移动值，仍需复用时保留副本。语义节点可有多个来源，无须每个名称各占一个栈槽。 | [图和栈布局](../src/fourthgraph/compiler/stack_schedule.py) |
| 目标栈排布和指令选择 | 紧凑栈操作、可交换操作数布局以及相邻、单次使用的等价 VERIFY 形式。#82 的 `search_order` 在图上尝试另一种终端调度，默认束宽 96，超过 128 个活跃定义走既有排布。字节发射后没有第二轮 `search`。 | [调度器](../src/fourthgraph/compiler/stack_schedule.py) · [开关测试](../tests/test_formula_passes.py) |
| 计划集合与有限次序 | #82 正规化为 12 组合法集合，`search` 依赖 `stack`。本地实验在语义层枚举 `double-as-add`、`common-values` 及有意义的重复，深度上限 3。语义改写必须先于建图和终端发射。 | [有序规则](../src/fourthgraph/compiler/formula_experiment.py) · [实验报告](../src/fourthgraph/benchmark/experiment.py) |
| 曲线内核和表示 | R1 区分窗口、点加/倍点公式和其栈调度。Schnorr 已用 GLV 分解及格基常量复用。SM2 有仿射固定表、专用混合点加和字节反转，SM3 有轮状态的表示选择。改变算法或数值表示需固定计划单独测。 | [R1](../projects/p2pkh-r1/forth/msm_experiment.py) · [Schnorr v0.16.0](https://github.com/linzhm/4thGraph/blob/5fef0b71bb93507fb1d0206d7d72e3d692a74847/projects/p2pkh-schnorr/README.zh-CN.md) · [SM2 v1.10.0](https://github.com/linzhm/4thGraph/blob/5fef0b71bb93507fb1d0206d7d72e3d692a74847/projects/p2pkh-sm2/README.zh-CN.md) |
| 目标构造与见证 | PUSHTX 紧凑绑定、按模板与签名覆盖重建可推导的原像字段、复用已生成片段。Lamport 的 Forth 锁 7,746 → 7,042 → 6,830 B 包含源码及绑定两类变化。改变见证格式须单独配对宿主与模板。 | [绑定实现](../src/fourthgraph/bsv/pushtx.py) · [Lamport 记录](https://github.com/linzhm/4thGraph/blob/5fef0b71bb93507fb1d0206d7d72e3d692a74847/projects/lamport-ots/README.zh-CN.md) |
| 整条交易路径与验证布局 | Workflow 可融合或拆分阶段，按签名角色、可用数据和独立提交要求排除候选。直接 Script、透明 R1CS 和 Groth16 是不同验证选择，各有公开输入、可信设置或证明成本。独立于公式 pass，先核交易或验证契约。 | [工具链](toolchain.md) · [重建机制的适用范围](https://github.com/linzhm/4thGraph/blob/5fef0b71bb93507fb1d0206d7d72e3d692a74847/docs/language/stdlib.zh-CN.md) |

## 把优化计划接到精确模板

```text
Forth 程序、依赖 + 编译目标 + 固定计划
    → 合法交易布局及每笔的业务约束 → 原语匹配与业务优化
    → 对每个锁链接选中的汇编片段 → 交易图、精确 Script、参数和签名锚点
    → 项目构建器配对准确的 WASM、manifest 和夹具
    → 实际父输出 → recognize → prepare_spend → 宿主审核及授权 → assemble_unlock
    → 已签交易 + 实际父交易 → 固定 chain-gang → 候选对比、公开回执及重放
```

沿用 Yul 把高层表达式优化与目标栈排布分开的做法。用 4thGraph 自己的范围、ScriptNum、失败语义、栈成本及签名边界约束改写。允许优化的区域应有明确输入输出、纯度、可失败点及分支边界。读者标出的关键值保留来源，依赖和最后使用点由编译器推导。目标后端保留相应的 CODESEPARATOR、执行中的 scriptCode 和签名覆盖。任一项未经证明，维持原发射路径。[Solidity 优化器](https://docs.soliditylang.org/en/latest/internals/optimizer.html) · [本仓库公式规范](language/specification.md#钱包锁中的数值公式)

**实验与发行共用一次构建。** A 轴冻结源码、算法、夹具和目标，只变编译计划。B 轴冻结成员契约、夹具和计划，为不同算法源码各给一个身份。A、B 先分别测量，只对入围组合交叉复测。确定性枚举小空间，agent 在预算内按上轮机器报告提候选。报告记录来源、实际计划、编译和验证的独立状态、失败阶段、产物摘要、各指标及其对照差。未跑的层级记为 `not_measured`。等长 Bézier 候选追加搜索得到 47 和 46 B，故探索去重须含完整 pass 可见状态及后续可用预算。最终验证缓存另绑定产物字节、布局、模块、夹具、引擎和上下文。固定计划可脱离模型重放。[现有两轮实验及 JSON 用法](project-contracts.zh-CN.md#公式优化与-agent-的两轮实验)

**钱包接入的缺口在链接之后。** 现有构建能配对冻结模板，但项目适配器还不能把任意已验证计划传给整锁构建器，并据其最终布局生成对应识别材料。建议让链接结果一次交出精确字节、参数槽、不可变片段、真实签名锚点及派生的 scriptCode 范围，供清单和识别器共用。单脚本开发可直接交付 Script。钱包包需另外绑定模块、路径、夹具和验收回执。模板变更后保留旧包服务旧 UTXO，项目清单由宿主独立认可。多个脚本按角色、具体 outpoint 和交易阶段配对。[现有构建器](../tools/build_project_contract.py) · [钱包宿主](../src/fourthgraph/workflow/project_contract.py)

## 实测与采用条件

**试测编译器选择所依据的成本。** 用一份非计数 Forth 源码，把“草稿”切换为“就绪”，最终要求有序的结算付款和状态回执。固定 Chronicle v2、业务优化计划和测试签名者。现有 Workflow 编译器对 BIP143 自己比较完整原像与重建原像，两种流程都选了重建。下表将每个候选强制构建，并用固定 chain-gang 验证所有花费，合计 **8 套构建、12 条有效轨迹**。字节数含合成父交易及整条花费路径。每个双模式候选的各轨迹从同一部署 UTXO 独立复跑。[Forth 源码](reviews/optimizer-integration/selection-workflow.fth) · [离线复跑](reviews/optimizer-integration/measure_selection.py) · [逐路径测量](reviews/optimizer-integration/selection-measurements.json)

| 模式及原像实现 | 融合一笔 | 两步串行 |
|---|---:|---:|
| BIP143，完整 | 1,446 B | 4,594 B |
| BIP143，重建 | 1,335 B | 4,259 B |
| OTDA，重建 | 1,313 B | 4,180 B |
| 双模式，重建 | BIP143 1,399 B · OTDA 1,391 B | `41→41` 4,498 B · `41→61` 4,491 B · `61→41` 4,482 B · `61→61` 4,475 B |

在固定 BIP143 的情况下，重建给融合路径省 **111 B**，给串行路径省 **335 B**。两个混合顺序的结果相差 **9 B**，所以成本报告要保留逐阶段模式。这组测量针对 Workflow 的选择和链接。以下命令在已安装仓库固定 chain-gang 的环境重放这一组样本。

```sh
PYTHONPATH="src:.${PYTHONPATH:+:$PYTHONPATH}" python docs/reviews/optimizer-integration/measure_selection.py
```

**实验一固定 R1 普通路径的 `split-4` 算法。** 只改点加、倍点的公式计划。每套候选经现有链接器重建，评审临时目录按候选字节、owner 槽和签名锚点分别配对 WASM。每套均通过原有 14 个夹具用例，实际花费和无私钥重放均经固定 chain-gang 与本地 BSV Node 检查。这个手动配对实验证明接口可接通，尚未成为项目公共命令。单位为字节，双栈列为成功路径的主栈/备用栈项目峰值。[完整数据及产物摘要](reviews/optimizer-integration/measurements.json)

| 实际公式计划 | 点加 / 倍点 | 整锁 | 合成父交易 | 已签退出 | 两笔合计 | 双栈峰值 |
|---|---:|---:|---:|---:|---:|---:|
| 空集合 | 392 / 222 | 116,364 | 116,428 | 389 | 116,817 | 160 / 131 |
| stack | 156 / 80 | 47,962 | 48,024 | 389 | 48,413 | 111 / 131 |
| rewrite + share + stack | 142 / 79 | 45,827 | 45,889 | 389 | 46,278 | 111 / 131 |
| 上项加 search | 123 / 74 | 41,986 | 42,048 | 389 | 42,437 | 113 / 131 |

退出只付到 `OP_1`，所以最后再省的 3,841 B 全落在创建该锁的父交易。代价是主栈峰值多 2 项、双栈峰值载荷从 3,472 增到 3,636 B。栈指标来自开发求值器，原生 CHECKSIG 在此按成功建模。验签判定来自实际交易引擎。R1 的单次编译包含不同的冷启动开销，仅留原始耗时。Bézier 在本分支串行五轮，三开关与再加搜索的编译中位数分别为 2.34 和 177.72 ms。

**实验二固定 `pels-counter` 的完整原像见证，比较两步路径。** 业务词 `advance` 在 baseline/safe/stack 下字节完全相同，都是 8 B。单独变更 PUSHTX 目标实现得到下表。两套都以参考构造器和实际前序通过两个引擎，只有 705 B 版本有匹配的项目 WASM。旧模块对 547 B 返回 `NoMatch`，因此后者目前只能作为 Script 候选。[分步数据](reviews/optimizer-integration/measurements.json)

| 目标构造 | 整锁 | 每步见证 | 每笔花费 | 父交易及两步合计 | 双栈峰值 |
|---|---:|---:|---:|---:|---:|
| baseline | 705 | 860 | 1,629 | 4,025 | 5 / 32 |
| compact | 547 | 702 | 1,313 | 3,235 | 32 / 2 |

**实验三复核主线 #83 的 Forth 组合。** 独立 PELS 正例锁 623 B、花费 1,434 B。R1 组合参考锁共 9,905,009 B，状态前缀 7 B、PELS 段 624 B、R1 所有者验证段 9,904,378 B。连续两笔花费各 19,810,345 B，同样通过双引擎。这个组合已有 Python 宿主，见证为公钥、签名、tail、head。它与前两项的普通见证和签名域不同。[主线宿主](https://github.com/linzhm/4thGraph/blob/5fef0b71bb93507fb1d0206d7d72e3d692a74847/projects/p2pkh-r1/forth/pels_r1.py) · [逐段回执](reviews/optimizer-integration/measurements.json)

当前 WASM ABI 的请求和响应各限 8 MiB，使用 JSON 十六进制承载字节。单个 9,905,009 B 锁已超过这个界限。先验证能接受同一摘要、输入域和失败语义的较小 R1 内核，测出**真实请求和响应**的峰值。若仍超限，再评审绑定不可变字节的限额读取及见证传递。普通 R1 的 41,986 B 结果不能直接替代这个组合。[ABI 限制](../sdk/go/contractabi/reactor_wasip1.go) · [宿主限额](../src/fourthgraph/workflow/contract_runtime.mjs)

**采用按调用路径判定。** 先核对成员契约和夹具，再比较完整父交易、各步花费、整路与最大单笔字节，同时保留双栈峰值和编译时间。SM2 主线的 v1.9 → v1.10 在两进两出 OTDA ALL 省 1,504 B，十二进一出却从 197,151 增至 197,213 B。收益为零保留简单计划，权衡随形状反转就给适用范围，验证失败保留诊断并排除。独立合约包实跑与公开重放默认用固定 chain-gang。可显式追加 BSV Node。入池、确认和正式 MESA 各有自己的验收范围。[SM2 实测](https://github.com/linzhm/4thGraph/blob/5fef0b71bb93507fb1d0206d7d72e3d692a74847/projects/p2pkh-sm2/README.zh-CN.md) · [项目包验证命令](project-contracts.zh-CN.md#做一次构造测试)

## 建议的开发顺序

| 独立评审单元 | 改动和可验收结果 |
|---|---|
| 1 · Forth 锁与编译器选型 | 复用 `lock:`、参数绑定和已有形状及覆盖表示，先提供业务输出与约束。把签名算法策略放进构建目标，登记 #83 的构件和首批等价 BIP143 原语。用非计数规则验收编译、链接、实跑和报告。保留原实例逐字节回归，检查两栈及失败边界。 |
| 1b · OTDA、多模式和自动选择 | 同一锁源码分别用 BIP143 目标、允许 OTDA 的目标及要求兼容两路的目标构建，验证编译器的实际选择。同时验收显式 OTDA、显式双模式、覆盖不足及两步四种轨迹。报告选中模式和整路排名，最后配对 WASM。新增覆盖模式按同一目录和选择流程接入。 |
| 2 · 从计划到模板 | 先接固定窗口的普通 R1 路径。现有公式计划 → 整锁链接 → 参数和锚点 → 项目包。字节相同可复用已核对的模板身份，构建记录仍各自保存实际计划。字节有变就构建对应识别材料并验证旧包仍能花旧输出。 |
| 3 · 代表性调用路径 | 把上述两类候选交给同一个“编译、实跑、比较”入口。以固定夹具核对预期与实际见证、父子交易、验证状态和差额；agent 凭上一轮 JSON 产生下一批。可选双引擎逐项记录；自动采用须另行决定。 |
| 4 · R1 授权与 PELS 组合 | 用主线 #83 的 Python 参考和精确成员契约验独立授权，再验实际两步后继。先解决 8 MiB 限额；无配套 WASM 只能报告 Script 层通过。评审通过后才讨论更广交易形状。 |

本轮先评审 Forth 的语义声明、后端原语契约及确定性决选。成对输出、灵活输出向量及需要父交易金额证据的成员，分别在明确调用方和验收后接入同一个选择流程。
