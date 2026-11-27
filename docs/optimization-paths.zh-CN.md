# 按计算任务选择优化路径

[English](optimization-paths.md) · [架构](architecture.zh-CN.md)

计算和标准库调用共用 `experiment run` 和 `experiment replay`。合法计划由源码契约决定。公式计划比较代数实现和栈调度，库调用计划根据调用点已证的输入事实或构建参数选择打包内核。下表按同一夹具各向量中资金交易与花费交易序列化字节之和的最大值排名。

| 任务 | 候选 | 选定方案与证据 |
| --- | --- | --- |
| 有符号 256 位整数 2×2 矩阵乘法 | 在同一 pass 计划下比较直接乘法与七次乘法的 Strassen 算法 | 直接乘法加 `stack + search` 的完整路径为 **710 B**，Strassen 为 **753 B**。直接乘法执行八次 `OP_MUL`，栈载荷峰值 403 B。Strassen 执行七次，峰值 650 B。两者各通过 64 个正例和 64 个拒绝用例。 |
| 保留中间摘要的 SHA-256 链 | 每轮用 `OP_SHA256`，或在连续区域内用 `OP_HASH256` 合并两轮 | 保留单轮检查点，并对后续 65 轮配对。长区域发出 32 个 `OP_HASH256` 和一个 `OP_SHA256`，完整路径从 4,363 B 降至 **4,331 B**。两套方案均通过 29 个正例和 29 个拒绝用例，输入从空字节串到 4,096 B。 |
| secp256k1 点加 | 完整射影、常量证明下的仿射、有射影回退的守卫仿射 | 按调用点的坐标证据选出 **777 B** 的常量仿射加运行时通用方案。**882 B** 的带守卫方案可继续重放。 |
| 有符号模累加 | 折叠常量子图、提取公共乘数、消除有证明的多余取余 | 同一份 Forth 使用 `stack` 的完整路径为 **202 B**，三条规则组合后为 **187 B**。每个候选均通过 96 个正例和 96 个拒绝用例。 |
| 固定宽度字段与字节常量 | 逐字段或批量换序，直接推入常量或从已证明重复的种子展开 | 两项绑定组合后为 **912 B**。观测栈载荷预算为 500 B 时，单独展开常量的 **1,542 B** 方案胜出。 |

矩阵实验固定输入范围及四个结果槽。直接乘法只用 `stack` 时为 712 B，增加 `search` 后再省 2 B。加上 `rewrite` 和 `share` 后字节相同，因此保留较短的 pass 列表。向量覆盖有符号边界、正负混合、零元素和确定性的满宽输入。栈载荷由开发评估器测量，含调用方哨兵值。

哈希夹具返回中间和最终两个摘要。编译器只为构建期已知至少两轮的连续区域选择配对内核，记录轮数、打包内核摘要、链接字节范围以及奇数轮尾部成本。单轮检查点和异类内核的配对绑定会被拒绝。[矩阵源码](../src/fourthgraph/benchmark/formulas/matrix-mul.fth) · [哈希调用方](../src/fourthgraph/benchmark/fixtures/hash-chain.fth) · [哈希内核](../src/fourthgraph/stdlib/hash-chain.fth)

## 有序公式规则

这些规则适用于封闭的算术公式。调用方须保证输入采用规范 ScriptNum 编码，并满足声明的范围。

| 规则 | 适用条件 | `stack` 加单条规则的完整路径 |
| --- | --- | ---: |
| `fold-literals` | 所有操作数均为字面量，且类型化运算合法。按 Script 的有符号余数语义求值。 | 195 B |
| `factor-products` | 两个乘积共享同一个图值。保留减法方向，重新验证新增中间值和乘积的 ScriptNum 上限。 | 196 B |
| `elide-redundant-remainder` | 已证明被除数在恒等范围内，或它已用同一个正模数取余。 | 200 B |

三条规则组合后，Script 从五次乘法和两次取余变成两次乘法和一次取余，实测栈载荷峰值从 48 B 降到 44 B。有序搜索最多接纳 32 个候选。终端 pass 列表非空时会加入未优化基线，同一终端计划下的空规则候选可用于衡量规则本身的收益。`compile.lowering.ordered_rules` 记录命中次数，追踪保留结果范围和源码位置。调用方也可用 `ScriptBuilder(..., formula_passes=["stack"], experimental_rules=[...])` 显式应用这些规则。[夹具源码](../src/fourthgraph/benchmark/formulas/modular-dot.fth)

## 批量换序与重复常量

`byte-layout` 对一个 32 字节字段和一组打包的六个字段分别做换序和掩码运算。编译器为两种换序绑定生成相同的精确宽度检查。批量方案复用 BIP340 的六字段内核并保留字段顺序。编译器根据固定常量能否递归拆成相同的两半选择展开方式。192 字节掩码用 3 字节种子和六次 `OP_DUP OP_CAT` 生成。单字段与非重复掩码调用各走通用实现。[调用方源码](../src/fourthgraph/benchmark/fixtures/byte-layout.fth) · [字节库](../src/fourthgraph/stdlib/byte-layout.fth)

| 绑定方案 | 完整路径 | 观测主栈与备用栈合计载荷峰值 |
| --- | ---: | ---: |
| 逐字段换序与字面量掩码 | 1,720 B | 425 B |
| 批量换序 | 1,090 B | 617 B |
| 重复种子展开 | 1,542 B | 425 B |
| 批量换序加重复种子展开 | 912 B | 617 B |

`"enumerate":"binding-combinations"` 依次尝试基线、单个替换和不同调用点的组合。每个调用点只选一个内核，最多接纳 32 个计划。每个组合先链接、实测花费，再参加排名。`max_payload_bytes` 用固定开发向量上的主栈与备用栈载荷观测值筛选，包含调用方的哨兵值。超过预算的候选仍记录花费回执和排除原因。重放会核对预算和排名。四种方案各通过 24 个正例和 24 个内容变更的拒绝用例，两套引擎也拒绝了畸形字段长度。

## 重放

从仓库根目录使用已安装的 `4thgraph` 和[固定版本的 chain-gang](../tools/requirements-chronicle.txt)。JSON 报告记录候选 ID、源码和库摘要、逐向量判定、观测到的编译耗时和栈峰值。

```sh
mkdir -p workspace/tuning
printf '%s\n' '{"fixture":"matrix-mul","evaluation":"spend","enumerate":"sets"}' > workspace/tuning/matrix-passes-request.json
printf '%s\n' '{"fixture":"matrix-mul","axis":"B","evaluation":"spend","plans":[{"passes":["stack","search"]},{"implementation":"matrix-mul-strassen","passes":["stack","search"]}]}' > workspace/tuning/matrix-algorithms-request.json
printf '%s\n' '{"fixture":"hash-chain","evaluation":"spend","enumerate":"bindings"}' > workspace/tuning/hash-bindings-request.json
printf '%s\n' '{"fixture":"modular-dot","evaluation":"spend","enumerate":"orders","trace":true}' > workspace/tuning/modular-orders-request.json
printf '%s\n' '{"fixture":"byte-layout","evaluation":"spend","enumerate":"binding-combinations"}' > workspace/tuning/byte-layout-request.json
printf '%s\n' '{"fixture":"byte-layout","evaluation":"spend","enumerate":"binding-combinations","max_payload_bytes":500}' > workspace/tuning/byte-layout-budget-request.json
for experiment in matrix-passes matrix-algorithms hash-bindings modular-orders byte-layout byte-layout-budget; do
  4thgraph experiment run "workspace/tuning/$experiment-request.json" > "workspace/tuning/$experiment.json"
  4thgraph experiment replay "workspace/tuning/$experiment.json" > "workspace/tuning/$experiment-replay.json"
done
4thgraph experiment next workspace/tuning/modular-orders.json > workspace/tuning/modular-next.json
4thgraph experiment run workspace/tuning/modular-next.json --parent workspace/tuning/modular-orders.json > workspace/tuning/modular-follow.json
4thgraph experiment replay workspace/tuning/modular-follow.json --parent workspace/tuning/modular-orders.json > workspace/tuning/modular-follow-replay.json
```

用隔离 regtest 对算术及字节运算向量运行 BSV Node 独立复核。测试同时要求固定版 chain-gang。

```sh
REGTEST_CHRONICLE_HEIGHT=10 bash tools/verify_node.sh -- python -m unittest \
  tests.test_project_experiment.FormulaExperiments.test_large_arithmetic_and_hash_spends_match_regtest \
  tests.test_project_experiment.FormulaExperiments.test_modular_spends_match_regtest \
  tests.test_project_experiment.FormulaExperiments.test_byte_layout_spends_and_malformed_fields_match_both_engines
```

支付回归矩阵对 R1、Schnorr、SM2、Lamport、WOTS+ 和 ML-DSA 的完整模板改动见证与交易字段，在各项目的上下文中核对授权和交易承诺。[项目矩阵](../tests/test_optimization_matrix.py)

## 椭圆曲线 lowering

对范围为 `[0,n)` 的标量及已登记的生成点，编译器支持 secp256k1、P-256 和 SM2 的二进制、两位窗口和四位窗口固定基算法。固定表由曲线参数计算，自动选择比较生成的 Script 字节数。脚本返回齐次射影坐标 `X Y Z`，无穷远点的 `Z = 0`。

secp256k1 的联合点乘入口检查两个标量的范围和传入的仿射点，再对生成点与公钥点做联合乘法，返回 `p X Y Z`。GLV 路径使用本曲线的自同态，并在四个 128 位分量上使用两位窗口。P-256 和 SM2 使用已登记的固定基计划。

联合点乘的 `auto` 会比较原始 64 窗口、预打包索引的字节表、栈上查表，以及缩放坐标下的栈上查表。优化候选使用合并倍点，固定仿射点使用混合点加。CLI 报告记录坐标模型、查表布局、脚本字节数和哈希。也可指定候选以固定复现路径。

在 Forth 源文件中，`curve-multiply:` 可将选出的脚本绑定为带类型的词。`auto` 与 CLI 使用同样的字节比较，调用声明的词时执行输入检查。

```forth
curve-multiply: mul-p256-generator p256 generator auto ;
curve-multiply: mul-secp256k1-joint secp256k1 joint auto ;
```

复跑使用 OpenSSL 提供独立的点乘结果，并在项目验证环境中运行 BSV Node 和 chain-gang。

```sh
PYTHONPATH=src:. python -m fourthgraph.workflow.protocol curve-multiply --curve p256 --strategy auto
PYTHONPATH=src:. python -m fourthgraph.workflow.protocol curve-multiply --curve secp256k1 --operation joint
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- \
  "$SCRIPT_LAB_SDK_PYTHON" -m unittest tests.test_curve_windows
```

[BIP340 源码和实测对照](../projects/p2pkh-schnorr/docs/high-level-forth.zh-CN.md#64-window-lowering)

### 坐标模型选择

`REQUIRE stdlib/weierstrass.fth` 提供 `weierstrass-scale ( p X Y Z u2 u3 -- p X' Y' Z )`。它对短 Weierstrass 曲线的齐次坐标应用 `(u²X, u³Y, Z)`，对应系数为 `a' = a·u⁴` 和 `b' = b·u⁶`，均在模 `p` 下计算。编译器验证 secp256k1 登记的缩放因子后，才使用 `a=0, 3*b=1` 内核。固定表在编译期转换，输入点在执行时映射，输出恢复为原始模型。[基础库 Forth 词](../src/fourthgraph/stdlib/weierstrass.fth)

P-256 使用同一套坐标模型接口及原 `a=-3` 内核。它的六次幂判定为 `(3b)^((p-1)/6) ≠ 1 mod p`，所以没有 `3*b=1` 的缩放模型。该域中保持 `a=-3` 的缩放也会保持 `b`。

## 数据流和返回边界

`--optimize dataflow` 会把通用等价改写和现有栈编译一起比较，保留较小的结果。同一控制流块中，标明只依赖显式操作数的运算若已经成功执行，可以复用结果。字节宽度来自长度检查、常量分割、拼接和哈希输出。编译器只有证明宽度匹配，才会选用已登记的定宽实现。条件分支分别分析，依赖交易上下文的操作保留调用。

返回边界有一段连续的活值位于栈顶时，调度器比较逐项移除死值和暂存活值后成对丢弃的两种写法，再按原顺序恢复活值和调用方的备用栈。标准 Forth 前端也支持 `layout:`，可用名称和类型声明栈重排。

共享 Script 库可解码单个 32 字节大端字段，也可解码编译期定数量的连续字段。它与窗口索引打包共享掩码和位组交换词。批量解码保留字段顺序和无符号语义。[共享实现](../src/fourthgraph/stdlib/script-fragments.fth) · [Schnorr 对照](../projects/p2pkh-schnorr/docs/high-level-forth.zh-CN.md#dataflow-iteration)

数据流调度器也会比较连续操作数成组搬运和逐项搬运。移动时保留已就位操作数的顺序，并检查被移动值的剩余用途。返回值已按顺序排好时，可直接移除夹在其中的死值。比较结果只供 `verify` 消费时，可使用脚本引擎提供的融合指令。[边界复放](../projects/p2pkh-schnorr/docs/high-level-forth.zh-CN.md#stack-and-model-boundaries)

`weierstrass-scale-affine` 将 `p X Y u2 u3` 映射成 `p X' Y'`。仿射及齐次坐标各有 `-root` 形式，接收一个非零域元素并计算完整的平方和立方。编译器对登记曲线的已约减坐标比较两种写法。256 位内核把 `-root` 路径的最大中间值限制在 129 个 ScriptNum 字节。批量解码用 `bsv-tile-top` 将运行时的掩码通过倍增和拼接重复。[缩放词](../src/fourthgraph/stdlib/weierstrass.fth) · [解码库](../src/fourthgraph/stdlib/script-fragments.fth)

`dataflow` 会识别将同一个值连续拼接的 `bytes-cat` 序列。它要求输入字节宽度已知，而且每个中间结果都只在这一段中使用。编译器比较替换前后整个 Script 的字节数，把搬栈成本一并计算。六份拼接用例从 `stack` 的 21 B 降到 16 B。直接构造 Script 片段时也可调用 `bsv-tile-top`。[回归用例](../tests/test_dataflow.py)

链接调用若声明某个输出与输入是同一个值，调度器可把原值移入调用，即使返回后仍要使用它。模缩放 lowering 根据已登记的根、模数、坐标范围和 ScriptNum 预算比较预计算因子与运行时求幂。证据不足或中间值超出预算时，使用预计算因子的实现。Schnorr 建表会比较保留模数和复制模数两种调度，选较短的脚本。[模缩放 lowering](../src/fourthgraph/compiler/modular_scale.py)
