# 4thGraph 架构与验收

[English](architecture.md) · [Forth 基线](language/README.md)

4thGraph 将高层 Forth 程序编译成 BSV Script，并为支持的工作流产生交易计划。程序表达值怎样产生、由谁授权、本次花费须约束哪些状态和输出，以及哪里必须原子执行或可独立提交。编译目标提供适用交易版本、链规则、签名覆盖与成本策略。

| 层 | 职责 |
| --- | --- |
| Forth 与标准库 | [Forth 基线](language/README.md)固定源码语义、语法和公共词。PELS 是交易约束模板族。R1 是所有者授权示例，用公钥哈希锁定，并验证当前花费的签名。 |
| 编译器与规划器 | 检查源码契约，比较合法交易切割，匹配 Script 片段并链接。交付精确 Script 字节和所选构建入口对应的元数据。 |
| 组装器与钱包 | 按实际前序绑定交易，准备所选路径的待签材料，按需请求宿主授权，并组装见证。使用编译期选定的 Script 和清单。钱包可搭配项目 WASM。 |
| 独立评估 | 固定向量评估纯公式。固定版 chain-gang 对照实际父交易验证完整花费。按需记录 BSV Node 复核。分别记录估算、离线验证、入池与确认结果。 |

## 开发与调优

从最高层 Forth 开始，固定语义、目标、依赖与夹具。并列列出可复跑的探索路径。固定编译计划比较 Forth 实现，固定源码比较编译计划与有限 pass 次序，在相同覆盖契约下比较合法交易和见证布局。Agent 选择有预算的候选批次。固定评估器给出验收判定，以及实际量到的 Script 字节、栈峰值、时间和整路字节。按报告选择下一批，或脱离模型重放选中的构建。

类型化 AST 和依赖图记录结果怎样推导。源码快照、规范化约束、构建计划、精确 Script 和片段分别保存摘要。字节哈希定位产物，源码和构建记录说明它由哪些修改产生并支持重放。多个计划即使得到相同字节，也各自保留来历。

## 构建与花费的交接

- **独立编译。** `4thgraph SOURCE --entry WORD` 输出 Script 字节、栈签名，以及源码与产物摘要等构建元数据。
- **工作流构建。** 构建报告描述所选布局、交易图和输出 Script。用 `--cpn-plan` 导出规范化交易计划。
- **钱包项目包。** 版本化项目包将精确的锁模板和指令清单与 WASM 模块、manifest 和可执行夹具配对。清单记录适用的模板参数槽和签名锚点。运行项目包验证后生成测试回执。

钱包模块通过 `recognize`、`prepare_spend` 和 `assemble_unlock` 使用实际 prevout 与选定的命名路径。宿主核对请求并按需签名。完整交易和实际父交易交给独立引擎验收。

功能 Profile 标识所支持的模板族，模板版本标识获准的精确字节与见证布局，候选身份绑定一次拟议花费。旧输出继续由已认可的旧版本识别。清单按路径记录摘要算法、链上下文和 `scriptCode`。

## 独立验收项

| 范围 | 基线证据 | 完成条件 |
| --- | --- | --- |
| Forth 基线 | 语言语义、双语语法、标准库统一索引。 | 每次构建记录编译器提交和能力清单。支持范围变化时同时更新对应文档和行为测试。 |
| PELS 编译目标 | 主线有 BIP143 PELS 参考实现，分段 Workflow 支持 BIP143、OTDA 及双模式。 | 同一份 Forth 独立锁通过单模式、双模式和自动选择的实际验证。固定各路径的输入输出承诺、签名模式与见证身份。动态后继和更多输出形状使用各自的契约和夹具扩展。 |
| 交易计划 | Workflow 在支持的形状上已经有融合、串行和原子布局。 | 扩大切割范围时保留授权、顺序、状态与原子性。比整路成本前验证实际父子关系、中间状态和独立提交约束。 |
| Agent 探索与追踪 | 公式编译器已有显式 pass 集合，工作流报告已有构建计划身份。 | 有界的源码及编译实验输出固定判定和复跑请求。跨交易扩展逐步关联业务节点、计划、链接后 Script 和验证回执。 |
| 钱包与示例 | 主线的 R1 和 PELS 示例各有授权和后继规则。 | 精确配对项目 Script 与 WASM。多模式钱包包要按已认可路径验收识别、准备和组装。R1 用测试密钥作为集成示例复跑。 |

需求项具备代码、构建命令和实测验收记录后再标记完成。编译器用中性的夹具独立评审，支付项目和 WASM 发布走各自的评审和验收。

## 整体验收与评审状态

基础依赖 #86–#90 已进入主线。以下各评审项独立验收，合入后从同一提交重建并复跑。先落地调优评估入口，再把调用点选型改以主线为基线。

| 验收项 | 评审与证据 |
| --- | --- |
| Forth 基线与构建身份 | 本页基线与 wheel 复跑回执记录提交、产物摘要和能力清单。 |
| 模块调用选型 | 同源点加夹具验证常量绑定、守卫路径和不兼容排除。[#93](https://github.com/linzhm/4thGraph/pull/93) |
| PELS 编译目标 | 非计数静态锁覆盖单模式、双模式和自动选型。动态状态标签夹具用实际前序重放两步。[#87](https://github.com/linzhm/4thGraph/pull/87) · [#95](https://github.com/linzhm/4thGraph/pull/95) |
| 交易计划 | 同源三阶段工作流比较串行和前缀融合，验证父子关系、授权和终态。[#92](https://github.com/linzhm/4thGraph/pull/92) |
| Agent 探索与追踪 | 固定向量验证源码及 pass 对照、完整花费、栈计划及重放。[#94](https://github.com/linzhm/4thGraph/pull/94) |
| 钱包与示例 | 双模式中性结算包复跑两条路径，现有 R1 走宿主签名集成回归。[#91](https://github.com/linzhm/4thGraph/pull/91) · [#89](https://github.com/linzhm/4thGraph/pull/89) |

在含上述实现的干净检出上运行 `bash tools/verify_architecture_acceptance.sh workspace/architecture-acceptance`。命令使用已有 Python 与 Go 环境、Node.js WASI 运行器和固定版 chain-gang。可通过 `PYTHON`、`WHEEL_PYTHON` 和 `GO` 指定解释器。由 `PYTHONPATH` 提供额外安装位置时，已安装的 wheel 仍优先加载。脚本在仓库外复跑并生成 `acceptance.json`，记录证据文件摘要和安装包摘要。[组合复跑脚本](../tools/verify_architecture_acceptance.sh)

### 基线评审

- 类型化 PELS 编译目标、字面量循环展开与字节追踪。独立结算夹具验收同一份锁的两条路径。[编译器 PR #87](https://github.com/linzhm/4thGraph/pull/87)
- Agent 有界选候选、固定评估和公式报告重放。首页流程图与 skill 说明同一个循环。[调优 PR #88](https://github.com/linzhm/4thGraph/pull/88)
- BIP143 ALL 项目 WASM 包，R1 和 PELS Counter 作为验收实例。[钱包示例 PR #89](https://github.com/linzhm/4thGraph/pull/89)
- 将现有 BIP143 动态后继按原字节纳入标准库。非计数状态标签夹具复跑两步，R1 作为调用该库的组合示例。[动态后继 PR #90](https://github.com/linzhm/4thGraph/pull/90)

从各评审分支组合构建的 wheel 包含公式夹具、WASI 运行文件和两个 PELS 标准库入口。在仓库外，已安装包的两种 Bézier 编译方案均通过 625 个向量，并用 chain-gang 0.13.2 重放了一笔 R1 夹具花费。[固定提交、构建命令和重放结果](architecture-wheel-replay.md)
