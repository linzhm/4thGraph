# 用 Forth 定义交易网络

此入口用 Gforth 执行 Forth 定义词，从实际构造出的记录建立交易网络。`workflow.fth` 使用 Forth 2012 的 `CREATE`、数据区和执行令牌。`REQUIRE` 负责文件依赖。4thGraph 用同一份关系词源码构建 Script。普通 4thGraph 入口继续读取原有的阶段声明。

## 源码决定什么

| 对象 | 写法 | 含义 |
| --- | --- | --- |
| 有序列表 | `x1 x2 2 list: name` | 建立两个元素的列表。`x1` 保持在索引 0。空列表写 `0 list: name` |
| 资源 | `0 CONSTANT deposit` | 一个计划实例中的符号资源编号。部署列表与各阶段的输出列表定义生产者。编号与真实 `vin`、`vout` 分开 |
| 签署角色 | `role: operator` | 指定签署角色，构建锁时从密钥表读取该角色的公钥 |
| 关系 | `relation-ref advance` | 保存 Forth 词名和执行令牌，后端按词名从共享关系文件解析、检查并编译该词 |
| 签名上下文 | `modes prevout-amount context: name` | `modes` 是允许的原生 `sighash` 字节列表。金额参数用 `no-amount`、`signed-amount` 或 `parent-amount` 表达是否需要当前 prevout 金额及其证据 |
| 阶段 | `inputs outputs input-selector output-selector relation role context policy stage: name` | 保存两个有序资源列表、两个交易侧选择器、关系、角色、签名上下文和验证策略 |
| 导出 | `deployment emit-roots` 和 `stage-name emit-stage` | 选择根资源和属于这次构建的阶段。每个阶段导出一次 |

`direct-script` 要求链上直接验证。`proof-required` 要求验证某种证明，`groth16-required` 进一步指定证明系统。证明策略和签署角色分别生效。逐阶段证明的后端还需要由构建结果固定电路和验证密钥，并把公开信号中的状态、索引和后继承诺绑定到实际消费和产生的输出。隐私要求还要声明哪些值只进入证明见证。后端缺少所需的绑定能力时，生成锁会报错。

## 选择哪个输入或输出

选择器的计数范围约束**真实交易一侧的总项数**，包括外部输入或额外输出。`min`、`max` 是闭区间，`0 -1` 表示不设额外计数条件。索引从 0 开始。每个阶段各有一个输入选择器和一个输出选择器。物理索引与阶段关系内部的 Forth 栈深分别解释。

| 写法 | 选择 |
| --- | --- |
| `min max ordered: name` | 整个有序列表。`1 1 ordered: one-in` 同时要求恰好一个输入 |
| `min max i n at-range: name` | 从 `[i,n)` 中选择一项，同时检查该项实际存在。固定索引 `i` 用 `[i,i+1)` |
| `min max current: name` | 正在验签的输入。用于输入侧 |
| `min max paired: name` | 与正在验签输入同索引的输出，必须存在。用于输出侧 |
| `unselected: name` | 省略输出侧的取项和计数条件。只可用于没有声明后继资源的阶段 |

例如 `2 4 1 3 at-range: payout` 允许交易有 2 到 4 个输出，从索引 1 或 2 选一个。验收关系必须同时满足 `index < 实际输出数`，并认证该位置的输出字段。`2 4 1 2 at-range: payout` 固定索引 1。范围宽度大于一时，花费可在允许集合内选择索引。一个阶段要同时约束多个位置时，可使用 `ordered:` 表达整个向量，再由关系逐项比较。向量中的位置可以允许不同金额、锁脚本或附加数据；这些是关系的约束，和原像覆盖是两件事。

`ALL` 能承诺完整输出列表。ForkID 要打开或重建其序列化数据并核对 `hashOutputs`。OTDA 直接序列化所覆盖的输出。`SINGLE` 支持同索引输出，签名覆盖不足以证明总输出数或任意固定 `vout`。未配对的 OTDA `SINGLE` 使用常量摘要，本入口要求显式选择且认证同索引输出。`NONE` 的签名原像没有输出覆盖。`ANYONECANPAY` 下原像仅认证当前输入，无法用来核对总输入数。OTDA 原像省略当前 prevout 金额，`parent-amount` 表示需要额外核对父交易的真实 `txid:vout`。

## 网络与构建边界

阶段产生多项资源可以分叉，同时消费多项资源可以汇合。多条路径消耗同一资源表示竞争。构建器检查唯一生产者、同一阶段重复消费、循环以及必须同时完成相互竞争的上游阶段。一份计划描述一次有限执行，循环型合约需要把下一轮实例的状态和来源作为显式交接。机器计划按拓扑排序，同层按阶段名排序，有序资源保留输入和输出顺序。输入引用用 `[父步骤编号, 资源槽位]` 表示，部署编号为 0。资源槽位是父阶段输出列表的索引。后端再将它绑定到实际 `vout`，例如单项范围选择可能把资源槽位 0 绑定到真实 `vout 1`。

初版可生成任意上述有界网络的符号计划，并校验每个声明的签名模式。**链上后端已接通 4thGraph 的串行计数器工作流**。它接受一条从 `u32` 到 `route` 的链，每步恰好一个输入，过程交易恰好一个输出，结束交易恰好两个有序输出（支付和回执）。所有阶段须显式选用直接 Script 和相同的 ALL 签名模式集合。其他布局、逐阶段 ZKP、通过父交易核对金额和动态槽位的 Script 降级仍需接入后端。请求为这些计划生成锁时，命令会明确拒绝。

## 构建和测试

从仓库根目录运行，环境须有 `gforth`。源码作为构建程序执行，只运行信任的 Forth 文件。锁生成使用现有 4thGraph 及其 Python 依赖。

构建锁时，`--rules` 及其依赖的源码行必须与本次 Gforth 实际读取的内容一致。构建器按 `relation-ref` 保存的执行令牌核对定义位置，并核对关系调用的用户定义词。在阶段声明后重新定义同名词，原阶段仍绑定原定义。宿主提供的基础词须实现对应的 4thGraph 语义。

```sh
project=projects/4thgraph
PYTHONPATH=.:$project python "$project/workflow-forth/build.py" \
  "$project/workflow-forth/counter.fth"
PYTHONPATH=.:$project python "$project/workflow-forth/build.py" \
  "$project/workflow-forth/counter.fth" \
  --rules "$project/workflow-forth/counter-rules.fth" \
  --keys /path/to/public-keys.json --current 19
PYTHONPATH=.:$project python -m unittest discover -s "$project/workflow-forth" -v
PYTHONPATH=.:$project bash shared/verify_node.sh --profile raised -- \
  python -m unittest discover -s "$project/workflow-forth" -v
```
