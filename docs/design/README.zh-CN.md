# 4thGraph 工作流与验证统一设计

[English](README.md) · [文档索引](../README.zh-CN.md) · [CPN 实验历史](cpn-experiments.zh-CN.md)

4thGraph 用类型化 Forth 定义计算，用可组合的交易断言约束花费，并用有色 Petri 网（CPN）探索如何把迁移放进交易。编译器先检查语义约束，再比较成本。选中方案固定部署锁、见证接口和交易边界。

## 当前实现

| 接口 | 当前编译器能力 |
| --- | --- |
| Forth | 类型化 Core 子集与 BSV 扩展表达有界计算、范围、字节编码、宿主操作和 Script 构造。 [语言](../language/README.md) · [标准库](../language/stdlib.zh-CN.md) |
| `stage:` | 声明计算词、输入、输出及签名角色。编译器生成带类型的依赖图。两阶段可用 Script 或阶段证明，支持同输入融合、同笔双输入和串行布局，符合条件的三阶段支持串行及前缀融合。Gforth 前端记录有序资源、选择器、签名上下文和验证策略，可执行后端只包含已有的 Script 布局。 [工作流构建](../toolchain.md#可执行交易图) · [Gforth 前端](../../projects/workflow-examples/gforth/README.md) |
| `relation:` | 把公开的 `u32 -- u32` 转换词和 `u32 -- route` 决策词编译为一次花费。规划器比较 Script、透明 R1CS 和使用匹配外部设置的 BLS12-381 Groth16。电路也能从两条 `stage:` 推断入口，两个词仍在同一电路。 [规划器](../../src/fourthgraph/verification/plan.py) · [电路生成](../../src/fourthgraph/verification/circuit_backend.py) |
| 布局探索 | `--search --explain` 比较已支持的交易边界和见证布局，说明授权、独立提交和适用的大小约束。`--cpn-plan` 输出所选计划的规范编码。早期的 `--explore-partitions`、`--partition-cut` 和 `reuse` 属于旧工作区原型，曾在一个直线词中寻找类型化切点。 [主线探索](../toolchain.md#有界候选搜索) · [历史实验](cpn-experiments.zh-CN.md) |
| 验证器 | BLS12-381 有固定、混合和动态公开输入的验证库。BN254 是独立项目，其固定声明复放用所有者授权和另一套绑定接口。BLS12-381 单阶段电路和混合布局已接入工作流的统一交易绑定。 [BLS12-381 发布历史](../../projects/groth16-bls12-381/README.zh-CN.md) · [BN254 项目](../../projects/groth16-bn254/README.zh-CN.md) |
| STARK | 计数器使用 Winterfell 在宿主为有界公开关系出证并验证。独立的 SHA-256 配置已用编译生成的 Script 核验选取的轨迹开封。完整 Script 验证器和交易断言外壳仍待接入。 [Winterfell SHA-256 STARK](../../projects/stark-winterfell-sha256/docs/verification.zh-CN.md) |

## 状态与交易断言

库所定义状态类型、披露策略、编码和来源规则。迁移包含有序的输入和输出库所、一个类型化 Forth 关系、证据与授权要求和交易断言。物理计划把迁移映射到交易和输入索引。实际可花费标记携带 outpoint、金额、脚本和经过验证的状态或承诺。

| 状态载体 | 下一阶段如何读取 |
| --- | --- |
| 同一输入的栈 | 融合阶段直接传递已验证的值。Script 的最终结果受适用成功条件和栈规则约束。栈的生命周期止于当前输入。 |
| 可花费的后继输出 | 父交易创建 `<state> <body>` 或嵌入状态承诺。消费时从新锁读取数据，并核对真实前序及必要的来源条件。 |
| 公开尾部或回执 | 在适用规则下，顶层 `OP_RETURN` 可在栈顶为真时终止可花费锁，元数据留在锁的序列化字节中。单独的 `OP_FALSE OP_RETURN <data>` 回执占用不可花费输出。宿主可读取两者，后续 Script 可从已认证的父交易核对字节。 |

PELS 表达后继状态、金额和代码约束。`A → B → C → A` 每一圈都消费并产生实际 UTXO。应用能在授权的状态退出，超时分支可竞争同一 UTXO。有限执行计划记录实际依赖。独立 PELS 构建器和动态同代码后继模板已覆盖有界情形。 [PELS 锁与见证组装](../pels-locks.zh-CN.md) · [CPN 执行模型](../../src/fourthgraph/workflow/cpn.py)

每种断言声明需要认证的字段，例如配对输出、完整有序输出、前输出金额、时锁或指定后继程序。PUSHTX 是固定键 secp256k1 ECDSA 原像认证机制，把输入或重建的原像与节点实际验证的花费绑定。PELS 用这些已认证字段施加后继约束。应用可在支持的锁里用所有者 ECDSA 或 BIP340 签名授权，首版工作流角色沿用 ECDSA。调用遵循库声明的栈顺序，签名覆盖最终连接的 `scriptCode`。 [Forth 接口](../language/stdlib.zh-CN.md) · [固定键绑定](../../src/fourthgraph/bsv/pushtx.py)

| Sighash | 组装器与覆盖要求 |
| --- | --- |
| BIP143 ALL `0x41` | 认证当前 outpoint、前输出金额、sequence、链接后的 `scriptCode`，以及输入、sequence 和有序输出哈希。重建并比较断言需要的输入与输出向量。 |
| Chronicle OTDA ALL `0x61` | 认证适用的序列化输入与输出向量。OTDA 省略前输出金额，使用该金额的断言需要另行认证父输出。检查 Chronicle 激活规则和适用输入形状。 |
| `SINGLE`、`NONE`、`ANYONECANPAY` | 配对输出须检查槽位确实存在。`SINGLE` 和 `NONE` 在需要完整输出覆盖时须补证据。`ANYONECANPAY` 下的全输入向量断言同样需要额外证据。 |

同一输入的断言在旗标、链接脚本和覆盖字段一致时，共用一次原像认证。可选完整原像、符合前提的重建原像，或为部署时已知的后继预计算有序输出哈希。重建出的原像必须逐字节一致。分别评估锁长度与见证长度。 [按断言生成交易承诺](../toolchain.md#按断言生成交易承诺) · [交易序列化](../../src/fourthgraph/bsv/transaction.py)

## 阶段声明和验证策略

保留现有五参数 `stage:` 和 `relation:` 写法。下列扩展由联合规划器处理。库所给状态声明类型和可见性。`witness:` 添加公开操作数，`private-witness:` 添加仅供证明者读取的操作数。附加输入按声明顺序排在状态输入之后。`stage:` 最后一个参数为签名角色。

```forth
REQUIRE BSV

: advance ( u32 -- u32 ) 1 cell>u32 u32+ ;
: decide ( u32 -- route ) #20 cell>u32 u32<
    IF route-review ELSE route-settle THEN ;

workflow-input: a u32 ;
place: a u32 public ;
place: b u32 public ;
place: c route public ;

stage: ab advance a b operator ;
stage: bc decide b c bob ;
policy: ab allow-direct ;
policy: bc require-zk ;
atomic: ab bc ;
```

若 `bc` 需要私有操作数，用下面的定义替换它。允许公开时可写 `witness: bc delta u32 ;`，栈顺序相同。如果应用要求特定增量，还须将增量绑定至已认证输入或承诺。

```forth
range: small-delta u32 1 5 ;
: decide-with-delta ( u32 u32 -- route )
    check-range small-delta u32+ decide ;

stage: bc decide-with-delta b c bob ;
private-witness: bc delta u32 ;
policy: bc require-zk ;
```

| 策略 | 候选资格 |
| --- | --- |
| `allow-direct` | 可用直接 Script 或证明。Script 见证中的操作数须获准公开。透明 R1CS 需要 `assignment-disclosure: STAGE allow ;`，允许公开完整赋值及中间线值。 |
| `require-proof` | 必须由证明后端提供证据。允许公开完整赋值时才可使用透明 R1CS。 |
| `require-zk` | 需要匹配的零知识电路与设置。链上辅助数据仅依赖证明、公开信号与公开参数。公开输出及从中可推导的信息仍会披露。 |

任一策略遇到私有见证，均排除直接 Script 与透明 R1CS。已有单关系 `require-groth16` 选择证明系统，阶段的披露要求由阶段声明确定。`atomic:` 要求同一笔交易，允许多个输入。`independent-submit:` 保留独立提交。冲突应指向声明位置。输出构造器用同一批已认证字段组合金额、脚本、顺序及费用断言。 [现有语法](../language/syntax.md#3-声明与解析)

## A 到 B 到 C

`ab` 用 Script 计算 `b = (a + 1) mod 2^32`。Groth16 的 `bc` 电路约束 `r = decide(b)`、32 位 `b` 和 1 位 `r`。其公开输入接口为 `[r, b, bindLo, bindHi]`。编译时核对 `.zkey`、生成的 BLS12-381 R1CS 及二阶段设置，将验证密钥和槽顺序固定在锁内。组装器在真实输入和有序输出确定后生成证明。本笔交易的最终 txid 在见证完成后产生。

首版对执行 `bc` 验证的输入使用完整规范的 BIP143 ALL 原像 `P_i`，采用最终链接的 `scriptCode`。阶段描述摘要包含阶段、类型化关系、有序公开槽和绑定格式版本，在设置前计算。锁字节与验证密钥通过 `P_i` 的链接脚本覆盖。

```text
domain = ASCII("4thGraph/stage-bind/v1") || 0x00
d = HASH256(domain || stage_descriptor_sha256 || P_i)
bindLo = uint128_le(d[0:16])
bindHi = uint128_le(d[16:32])
```

在电路中对两个半段做范围检查，并保留为参与约束的公开输入。验证器和交易断言读取同一个规范编码的包。锁用固定键 ECDSA 认证 `P_i`，检查两个摘要半段，把包中的 `b` 和已认证的中间值比较，再用 `hashOutputs` 核对精确的 `[payment(r), receipt(root,b)]`。角色签名按规定的覆盖授权最终交易。已有单关系的接口是 `[next, route, current, bindLo, bindHi]`，绑定采用无域前缀的原像哈希。 [证明外壳](../../src/fourthgraph/verification/plan.py) · [公开输入包编码](../groth16-bls12-381.md#见证布局)

| 布局 | 中间值与原子性 |
| --- | --- |
| 同笔单输入融合 | A 锁运行 `ab`，比较栈上结果与包中 `b`，再验同一包的证明、付款和回执。两个角色都签名。验证器调用须隔离或保留交易外壳仍需使用的栈值和备用栈上下文。一把锁通过即完成两段。 |
| 同笔双输入 | 部署有序同级输出，分别使用 A 锁与 `bc` 守卫锁。两输入各自认证原像，并校验有序同级 outpoint 和同一完整输出向量。A 锁把算出的 `b` 写进回执，守卫锁用该回执约束证明的 `b`。任一输入失败则整笔失败。 |
| 跨交易串行 | `T_AB` 约束可花费 B 的槽位、金额和完整脚本。`T_BC` 消费 `(txid(T_AB), vout_B)`，查验来源并读取实际 B 状态或承诺。采用承诺时，生产方验证承诺，消费方的证明验证同一承诺的开封。B 可单独确认，并须保留应用声明的退出或退款。替换父交易时须重新绑定子交易和证据。 |

后端替换保持同一个交易断言的条件是，两边在同一组已认证数据上实现一致的类型化计算和失败语义，检查相同的授权与有序输出字节，并遵循同一披露和提交约束。各部署按实际 outpoint 和脚本重新构建及绑定。运行时选择只有锁在部署时已经包含所有可选分支，且各分支保留同一外壳语义时才成立。

## CPN 探索与候选报告

1. 用活跃值、范围和失败顺序寻找可切分位置。跨交易值须有编码和来源校验。保留授权、公开效果、恢复与独立提交约束。
2. 组合各阶段验证后端、交易布局和适用的 sighash 组装器。先按授权可用性、隐私、原子性、状态来源、电路和设置、目标节点规则及资源预算筛选。计入部署、必要退款、内嵌后继锁和祖先见证。
3. 部署前报告通过候选及淘汰原因。记录最大锁、最大交易、整路字节、主栈和备用栈载荷峰值与预算、见证大小、证明时间和内存、验证时间与引擎及未测字段。分别标注估算、完整输入复放、节点策略和入块。

可探索的方案还包括切分前合并可证明等价的连续计算、同笔对有序数据批次共用原像认证、以紧凑 `hashOutputs` 延迟启用完整计算锁。批处理仍须逐项验证输入及结果。短承诺须由后续花费公开并核对代码，或验证计算证据。串行阶段的资源上界取决于状态交接能否限制来源见证。接入定长检查点前，先比较推进 2、4、8 次时的最大交易和见证。检查点承诺流程根、规则版本、步号、状态和允许的出口。 [历史实测与限制](cpn-experiments.zh-CN.md)

当前编译器枚举显式声明的阶段和已有的交易布局，可在 BIP143 ALL 下比较验证后端。直接 Script 候选还可以用 `--sighash-family auto` 比较适用的 Chronicle 组装器。任意词内切分、批量构造和多轮历史的成本评估仍需接入。编译估算计入部署和后继数据。入金复放记录签名后的实际交易字节、主栈和备用栈载荷峰值、证明与见证准备时间、两种引擎的验证结果和入块结果。准备时间包含工具启动和出证端自检，未测出证内存。

### 命名路径与证明依赖

交易路径可为每个类型化阶段指定后端和职责。同输入融合用栈交接状态，同笔双输入用共同校验的回执交接，跨交易用后继 UTXO 交接。当前两阶段编译器中，首段用证明须采用同笔双输入且只接受公开状态操作数。末段证明可用上述三种布局。透明 R1CS 须显式允许全部赋值公开。Groth16 支持末段使用私有见证。承诺形式的跨阶段私有状态和任意电路切分需要单独的编译实现。

一条路径可以描述多个证明系统的依赖。例如 STARK 负责证明轨迹，SNARK 负责验证并封装该证明，最终由结算锁消费 SNARK 声明。职责说明每一环做什么。规划器检查边上的声明是否一致、各环是否都通往末端，以及依赖是否成环。目前能将两份独立的阶段证明绑定到同一笔交易。嵌套证明在报告中标记 `composed_verifier_unavailable`，直到有适配器约束前序证明、验证参数和公开输入。已有的 SHA-256 开封验证器可用于构成该适配器。

### 构建、选择与复放

`4thgraph cpn` 用同一入口规划和复放纯 Script 与证明阶段。`cpn tune` 也比较编译优化级别。`cpn verify` 核对入金回执与所选计划，再用固定版本的 chain-gang 离线复验。 [智能体实操指南](../../skills/4thgraph/references/cpn.zh-CN.md)

公开计数器声明 `advance` 和 `decide`。用 `4thgraph-circuit --stage STAGE --output FILE` 可导出任一阶段。Groth16 设置文件必须匹配在 BLS12-381 域上编译的电路。下面的路径相对于目录文件。用 `workflow_paths` 命名可选择的阶段组合，用 `evidence_paths` 描述证明依赖。

```json
{
  "groth16-bls12-381": {
    "decide": {"zkey": "setup/decide.zkey", "ptau": "setup/phase2.ptau"}
  },
  "workflow_paths": {
    "direct": {"layout": "fused", "stages": {
      "advance": {"role": "推进状态", "backend": "script"},
      "decide": {"role": "约束结算输出", "backend": "script"}
    }},
    "settle": {"layout": "atomic", "stages": {
      "advance": {"role": "推进状态", "backend": "script"},
      "decide": {"role": "约束结算输出", "backend": "groth16-bls12-381"}
    }}
  },
  "evidence_paths": {
    "wrap-trace": {"stage": "decide", "terminal": "wrapper", "nodes": {
      "trace": {"role": "证明轨迹", "backend": "winterfell-sha256", "proves": "bounded-trace", "requires": {}},
      "wrapper": {"role": "验证轨迹证明", "backend": "groth16-bls12-381", "proves": "decide",
                  "requires": {"trace": "bounded-trace"}}
    }}
  }
}
```

```sh
export PYTHONPATH=src:.
SOURCE=projects/proof-counter/workflow.fth
python -m fourthgraph.verification.circuit_backend "$SOURCE" --stage decide --output decide.circom
python -m fourthgraph.workflow.protocol "$SOURCE" --keys "$KEYS" --current 19 \
  --target both --sighash-family bip143 --optimize stack --backend-catalog "$CATALOG" \
  --search --explain > report.json
python -m fourthgraph.workflow.protocol "$SOURCE" --backend-catalog "$CATALOG" \
  --select-candidate report.json path/settle --cpn-plan > selected.json
REGTEST_MIN_MINING_FEE=0.00000001 bash tools/verify_node.sh --profile long-script -- \
  python -m fourthgraph.replay.proof_workflow "$SOURCE" --candidate path/settle \
  --backend-catalog "$CATALOG" --report report.json --output replay.json
```

重建时核对源码与导入摘要、阶段安排、构建摘要和规范计划。保留原目录及设置文件。复放使用固定测试角色，在本地 regtest 上入金并将选中方案入块，输出独立实测报告。若希望报告和复放使用相同公钥，用复放模块的 `TestKeys().public` 生成 `KEYS`，把公钥值编码成十六进制。私有示例可用 `--witness delta=1`。 [公开工作流](../../projects/proof-counter/workflow.fth) · [私有工作流](../../projects/proof-counter/workflow-private.fth) · [复放入口](../../src/fourthgraph/replay/proof_workflow.py)

下表使用 `current=19`、BIP143 ALL 和栈优化，公开工作流未额外声明原子性限制。部署及各笔花费均在隔离的 BSV Node 1.2.3 regtest 入块，使用降低后的出块费率门槛。字节数包含签名。

| 布局与 `advance → decide` 后端 | 部署（B） | 花费（B） |
| --- | ---: | ---: |
| 同输入融合，Script → Script | 1,052 | 347 |
| 同输入融合，Script → 透明 R1CS | 14,927 | 856 |
| 同输入融合，Script → Groth16 | 348,709 | 1,550 |
| 同笔双输入，Script → Groth16 | 349,605 | 1,755 |
| 同笔双输入，透明 R1CS → Groth16 | 363,423 | 2,160 |
| 同笔双输入，Groth16 → Groth16 | 707,015 | 2,857 |
| 跨交易串行，Script → Groth16 | 349,473 | 348,892 + 350,376 |
| 同输入融合，Script → Groth16（私有见证） | 348,711 | 1,548 |

要构建 R1CS → Groth16，在同目录复制公开工作流并加入 `assignment-disclosure: advance allow ;`，将 `settle` 路径的 `advance` 后端改为 `r1cs`。该花费的合计栈载荷峰值为 32,769 B。一次复放中，证明与见证准备耗时 5.67 秒，BSV Node 验证 RPC 耗时 145 毫秒。

<a name="spv-token-cpn"></a>

## SPV Token 的 CPN 编译示例

先用一份可执行的 Forth 关系对照 CCTP 已通过验收的交易。逻辑图从发行进入持有，普通转移回到持有，也可走销毁等授权出口。持有状态携带资产、最初发行的 `txid:vout`、适用规则、持有人及数量或数量承诺。转移消费实际代币输入，约束完整有序输出。用带范围检查的整数最小单位求和，铸造和销毁各有明确的供应量规则，载体聪数独立记账。 [CCTP 实际交易关系](https://github.com/linzhm/4thGraph/blob/11c919ab9f87de22ddbbb94bf701f61f6ab2d874/projects/spv-token/docs/actual-transaction-relation.md)

源码策略决定哪些检查可由 Script、证明或收款钱包承担。收款钱包按采用的区块头链检查区块包含及确认，并结合当前花费与冲突视图判定收据能否消费。编译器比较交易布局时保留相同的证据要求。 [SPV Token 验证模型](https://github.com/linzhm/4thGraph/blob/11c919ab9f87de22ddbbb94bf701f61f6ab2d874/projects/spv-token/README.md#design-conditions)

### 同一份源码的三种编译候选

| 候选 | 生成的检查与所需数据 |
| --- | --- |
| PELS 加确定性构造器 | 根据实际 outpoint 认证直接父及其授权创建规则。用获准模板和有界状态构造后继，分别验证所需父数据和生成锁的大小上界。 |
| PELS 加父检查点证明 | 证明选定父字段确实属于实际花费的 outpoint。由 Script 验证授权、守恒和精确有序后继。CCTP 已有这一布局的连续两笔入块基线。 |
| 递归证明加 PELS 结算 | 验证适用的前序证明，用本次迁移延续其声明。每份前序声明须对应本笔实际消费的输出，并继承同一个发行锚和获准规则。PELS 将最终声明绑定到实际花费。 |

在线性证明中，零跳证明锚定授权发行点。递归步用预期验证密钥核验前序证明，检查最初发行锚和规则身份一致，再让本次合法边从前序证明认证的终点延续到新终点。合并时分别核对每个互异的代币输入。规则可固定在验证规则中，也可将标识纳入已认证声明。终点采用规范化 `txid:vout`，出证时由定稿交易导出，使用声明时从已认证的实际花费取得。区块包含和钱包侧花费状态各有独立检查。 [CCTP 递归溯源](https://github.com/linzhm/4thGraph/blob/11c919ab9f87de22ddbbb94bf701f61f6ab2d874/projects/spv-token/docs/recursive-provenance.md) · [通用 TCP 谓词](https://github.com/nchain-innovation/transaction_chain_proof/blob/beffd037078bfecaa22b47ca19cd0569d9b776eb/src/predicates/universal_tcp.rs#L96)

排序前做三项检查。按模型边界检查状态可达、授权和证据可用，以及声明的出口。检查生成交易和锁构造的依赖成环，并对同一交易形状反复推进，测量锁、见证及所需历史的增长。把每条 Forth 断言追踪到实际发出的检查和认证过的操作数。报告记录源码词、对应的 Script 片段或证明约束、数据生产者和相应反例。替换父交易、输出槽位或顺序时，即便证明对自己的声明有效，也应在对应绑定处失败。

同笔切分时，各部分绑定同一组实际输入和有序输出。通过认证承诺拆电路时，两份证明还要约束同一个类型化中间值与交易上下文。跨交易时，消费方认证真实中间 outpoint、状态或承诺和待执行约束，并保留原子性及声明的退出要求。按整路比较部署、验证器资金、重建字节、电路约束、出证成本、栈峰值和确认深度。选定计划中固定电路指纹、公开输入顺序与编码、验证密钥以及输出锁。电路改变后重新检查设置兼容性。

固定槽位的递归声明指定一次单前序延续的两个端点。运行 `4thgraph-circuit SOURCE --lineage token-lineage --output statement.json` 可查看公开槽、基础情形与递归步要求及声明摘要。验证前序证明的实现由匹配的后端适配器提供。

```forth
: token-edge ( transaction -- outpoint outpoint )
    dup #0 tx-input-prevout swap #1 tx-output-outpoint ;
recursive: token-lineage token-edge ;
```

### 编译与复放证据

以下守恒词可用当前 Forth 编译。它检查正的无符号 64 位数量和有界总量。外层合约从经过认证的输入及输出提供这些数量。

```forth
REQUIRE BSV
range: token-quantity script-int 1 18446744073709551616 ;
range: zero script-int 0 1 ;

lock: conserve-2x2 ( in-a:token-quantity in-b:token-quantity out-a:token-quantity out-b:token-quantity )
    in-a in-b OP_ADD check-range token-quantity
    out-a out-b OP_ADD OP_SUB check-range zero drop
    1 verify ;
```

CCTP 提交 `11c919a` 中的两笔 2→2 归档付款各为 4,075 B，计入共享验证器资金后两笔合计 913,547 B。用归档交易和父交易独立复放时，BSV Node 与 chain-gang 都接受两笔付款的全部三个输入。上述 Forth 用栈优化编译为 115 B。在隔离花费中，两种引擎均接受 `300 + 200 → 275 + 225` 和 `275 + 150 → 350 + 75`，并拒绝多发一单位、零额输出和累计量溢出。 [固定版本的 CCTP 复放和字节统计](https://github.com/linzhm/4thGraph/blob/11c919ab9f87de22ddbbb94bf701f61f6ab2d874/projects/spv-token/docs/covenant-backtrace.md) · [归档结果](https://github.com/linzhm/4thGraph/blob/11c919ab9f87de22ddbbb94bf701f61f6ab2d874/projects/spv-token/fixtures/covenant-backtrace-2x2-summary.json)

对同一提交中的 CCTP BSB22 归档做独立 Script 复放，BSV Node 1.2.3 和固定版本的 chain-gang 均通过两笔认证发行与两笔转移的全部 9 个输入。四笔交易从 2,124,650 B 到 15,081,190 B，计入了该布局携带的交易上下文和前序证据。 [CCTP 连续性归档摘要](https://github.com/linzhm/4thGraph/blob/11c919ab9f87de22ddbbb94bf701f61f6ab2d874/projects/spv-token/fixtures/v3-continuity-regtest-summary.json)

独立的本地组件试验还把类型化 Forth 边降为 nChain MNT4/MNT6 后端的槽位参数，接受零跳、一跳和两跳，拒绝替换发行根和换用属于错误前序的有效证明。另一个 656 B PELS 片段从 BIP143 ALL 原像的第 68 字节读取 36 B 的实际 outpoint，两种 Script 引擎均拒绝相同 txid 的错误 vout 和过期原像。编译器可用 `--lineage` 输出类型化递归声明。需要递归声明的候选在接通链上递归验证器前均被排除。现有 CPN 图、候选报告和选定计划可用带前置条件的工作流示例复跑。 [可执行的 CPN 示例](../../projects/workflow-examples/README.zh-CN.md#compile-and-replay-a-cpn)

## 首版接入和验证

当前范围覆盖两阶段的 Script、BLS12-381 Groth16、获准披露赋值的透明 R1CS、末段私有见证，并支持满足上述限制的同输入、同笔双输入和串行布局。下一步需要接入统一阶段接口的 BN254、嵌套证明验证，以及固定原始发行和规则的递归溯源。确认 UTXO 恢复和有界构建承诺由编译器路线图跟踪。 [工具链路线图](../toolchain.md#路线图)

计数器的 Script 与 Groth16 在下表四个输入上均通过两种引擎。两种引擎都拒绝重排的输出、使用相同原像却约束错误 `b` 的有效证明、来自另一部署的有效证明，以及同一公开输入但用另一验证密钥生成的证明。私有见证使规划器排除 Script 和透明 R1CS。两个产生相同路由的私有增量生成了相同的公开包及未签名交易，两份证明均通过。

| 验证项 | 通过条件 |
| --- | --- |
| 差分与回绕 | Script 和电路均输入 `18, 19, 0xfffffffe, 0xffffffff`，得到 `19, 20, 0xffffffff, 0`，路由依次是复核、结算、结算、复核。比较付款、金额、回执及槽位顺序。 |
| 错误交接或输出 | 给错误 `b` 生成自洽证明。更改付款、金额、回执、输出顺序或数量后重新生成交易证据，并验证相应断言拒绝该花费。 |
| 错误上下文和密钥 | 把证明移到相同状态的另一部署，分别试旧包加新原像、新公开摘要加旧证明。构建时拒绝不匹配的 `.zkey`，链上拒绝另一套设置生成的证明，并覆盖损坏或非规范公开输入。 |
| 授权和隐私 | 拒绝缺失或错误角色签名、禁止的 sighash 或激活规则、将私有见证送入直接 Script 或透明 R1CS，以及没有合格候选的证明策略。检查 Groth16 公开接口、解锁见证和回执的实际披露。 |
| 完整花费 | 用 BSV Node 和固定版本的 chain-gang 复放，分别记录每个输入的结果、内存池和入块。双输入测试任一输入失败，串行测试父交易替换、错误来源、暂停、退出和退款竞争。 |

[已有关系复放](../../src/fourthgraph/verification/plan.py) · [已有工作流复放](../toolchain.md#可执行交易图) · [Groth16 复放计划](../../projects/groth16-bls12-381/docs/replay-plan.zh-CN.md)
