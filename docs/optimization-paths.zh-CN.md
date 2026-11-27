# 按计算任务选择优化路径

[English](optimization-paths.md) · [架构](architecture.zh-CN.md)

计算和标准库调用共用 `experiment run` 和 `experiment replay`。合法计划由源码契约决定。公式计划比较代数实现和栈调度，库调用计划根据调用点已证的输入事实或构建参数选择打包内核。下表按同一夹具各向量中资金交易与花费交易序列化字节之和的最大值排名。

| 任务 | 候选 | 选定方案与证据 |
| --- | --- | --- |
| 有符号 256 位整数 2×2 矩阵乘法 | 在同一 pass 计划下比较直接乘法与七次乘法的 Strassen 算法 | 直接乘法加 `stack + search` 的完整路径为 **710 B**，Strassen 为 **751 B**。直接乘法执行八次 `OP_MUL`，栈载荷峰值 403 B。Strassen 执行七次，峰值 587 B。两者各通过 64 个正例和 64 个拒绝用例。 |
| 保留中间摘要的 SHA-256 链 | 每轮用 `OP_SHA256`，或在连续区域内用 `OP_HASH256` 合并两轮 | 保留单轮检查点，并对后续 65 轮配对。长区域发出 32 个 `OP_HASH256` 和一个 `OP_SHA256`，完整路径从 4,363 B 降至 **4,331 B**。两套方案均通过 29 个正例和 29 个拒绝用例，输入从空字节串到 4,096 B。 |
| secp256k1 点加 | 完整射影、常量证明下的仿射、有射影回退的守卫仿射 | 按调用点的坐标证据选出 **777 B** 的常量仿射加运行时通用方案。**882 B** 的带守卫方案可继续重放。 |
| 有符号模累加 | 折叠常量子图、提取公共乘数、消除有证明的多余取余 | 同一份 Forth 使用 `stack` 的完整路径为 **202 B**，三条规则组合后为 **187 B**。每个候选均通过 96 个正例和 96 个拒绝用例。 |
| 固定宽度字段与字节常量 | 逐字段或批量换序，直接推入常量或从已证明重复的种子展开 | 两项绑定组合后为 **912 B**。观测栈载荷预算为 500 B 时，单独展开常量的 **1,542 B** 方案胜出。 |
| secp256k1 倍点窗口 | 完整逐轮倍点或成对倍点，域模数在栈底或紧贴点坐标 | 九轮窗口用成对倍点和就近模数时为 **1,144 B**。观测栈载荷预算为 700 B 时，就近模数加逐轮倍点的 **1,156 B** 方案胜出。 |

矩阵实验固定输入范围及四个结果槽。直接乘法只用 `stack` 时为 712 B，增加 `search` 后再省 2 B。加上 `rewrite` 和 `share` 后字节相同，因此保留较短的 pass 列表。向量覆盖有符号边界、正负混合、零元素和确定性的满宽输入。栈载荷由开发评估器测量，含调用方哨兵值。

哈希夹具返回中间和最终两个摘要。编译器只为构建期已知至少两轮的连续区域选择配对内核，记录轮数、打包内核摘要、链接字节范围以及奇数轮尾部成本。单轮检查点和异类内核的配对绑定会被拒绝。[矩阵源码](../src/fourthgraph/benchmark/formulas/matrix-mul.fth) · [哈希调用方](../src/fourthgraph/benchmark/fixtures/hash-chain.fth) · [哈希内核](../src/fourthgraph/stdlib/hash-chain.fth)

## R1 同源自动选型

固定 `r1-baseline-lock` 及其依赖，先用当前编译器建立对照，再试验窗口选型。原有仅窗口入口 `--auto --auto-rounds 1` 按链接后的锁字节数比较六个方案。只有源码和依赖摘要匹配时才替换已验证的 P-256 乘法区域。原有结果检查和交易绑定继续参与构建。其他源码快照沿用已有公式计划。

| 编译方式 | 锁字节 | BIP143 资金交易＋花费字节 | 主栈 / 备用栈峰值项数 |
| --- | ---: | ---: | ---: |
| 默认基线 | 415,058 | 415,511 | 71 / 39 |
| 已有 `--optimize` | 139,333 | 139,786 | 24 / 39 |
| `--auto` 选择 `split-5x4-affine-g-ifdup` | 41,264 | 41,715 | 161 / 119 |

交易数据来自单输入单输出合成夹具，栈峰值由开发评估器观测。固定版 chain-gang 和隔离 regtest 中的 BSV Node 均验证了六种方案的 BIP143 ALL、OTDA ALL，以及配对和无配对的 OTDA SINGLE。改动锁定时间后，原见证均在交易绑定检查处被拒绝。[构建与复跑](../projects/p2pkh-r1/forth/README.md)

传入 `--auto-rounds 6` 时，搜索实际执行五轮，在编译 32 个不同候选后达到上限。上述花费检查覆盖全部 32 个候选。进一步比较窗口宽度和守卫后，最小锁仍为 41,264 B。JSON 记录每轮实际比较的方案和截至该轮的最小锁。

## R1 有序方法探索

下文的初始矩阵和搜索数字使用原编译器快照。[原始构建与计划](https://github.com/linzhm/4thGraph/tree/9b13dfbbd50487ca868831788f653e2b75f9cd5a)

矩阵每格先应用行方法，再应用列方法。两张矩阵固定同一份 Forth 和两进两出夹具。一张从通用分表起步，另一张从已证明可用仿射 G 内核的分表起步，以便交换紧凑存储和零位守卫。五种方法分别选择联合窗口、专用化固定 G 调用、压紧 G 表、缩短零位守卫，以及对当前可见的点加内核执行显式栈搜索。

先做仿射专用化，再跑栈搜索会发出 41,927 B 的锁。反过来，新出现的仿射内核走默认降低，锁为 41,366 B。仿射起点下，紧凑表和守卫交换顺序后，锁同为 41,165 B。紧凑方案的 BIP143 ALL 路径最短，为 165,575 B。OTDA ALL 则是联合窗口的 176,617 B 最短，紧凑方案为 176,807 B。

报告保留 50 个有序对，其中 25 格满足前提，共有 9 组不同的锁和重建程序，均由固定版 chain-gang 对实际夹具前序验收。结果按交易目标分别排名，可用 `method-matrix --replay` 复跑。[构建与复跑](../projects/p2pkh-r1/forth/README.md)

`method-search` 从通用分表起步，逐步扩展当前适用的方法，包括独立加宽 G 窗口。此次从六种已登记的方法出发，扩展了 19 个编译器状态，尝试了 114 次转移后收敛，最长代表序列有五步。BIP143 ALL 选择仿射 G、紧凑 G 表和缩短守卫三步，两个 OTDA 模式都选择单步联合窗口。`--replay` 使用原报告里的预算。

随后在方法搜索中加入 OTDA 重建选择。`joint-2` 可先倍增生成 128 份窗口片段，再裁掉最后一份。当这一选择节省指令字节且临时值能容纳在已构造后缀的字节上限内时才尝试。42,382 B 锁逐字节相同，重建程序从 3,062 B 缩至 3,043 B。双输入夹具的 OTDA ALL 完整路径从 176,617 B 降至 176,579 B，配对 OTDA SINGLE 从 176,546 B 降至 176,508 B。BIP143 路径和观测栈峰值相同。

扩展搜索还比较缩窄独立 Q 窗口、用主栈生成重复片段，以及连续相同内核只查一次字典。两种打包方法仅在当前状态发出的重建程序实际缩小时进入搜索。纳入比较的候选使用已验证的完整交易排名。回执区分达到状态预算和用尽合法状态。 本轮登记十种方法，在 64 个状态时达到预算，独立验证了 61 组不同产物。通用分表缩窄 Q 窗口后，虽然重建程序变小，OTDA ALL 完整路径增加了 8,229 B。主栈重复使紧凑仿射候选的 OTDA 路径少 16 B。合并相邻内核引用使联合窗口的 OTDA 路径再省 2 B，ALL 为 176,577 B，配对 SINGLE 为 176,506 B。BIP143 ALL 的最优路径为 165,575 B。

在 `c02df4a` 的编译器上，三个付款目标都在 160 状态预算内用尽 152 个状态，锁均为 41,114 B。两个 OTDA 目标还选中了主栈重复和相邻内核打包。`--replay-plan` 核对编译器源码摘要，按保存的序列编译，再核对两项产物摘要。chain-gang 0.13.2 实测资金交易加花费总量分别为 BIP143 ALL 165,371 B、OTDA ALL 176,547 B、配对 OTDA SINGLE 176,476 B。[方案和命令](../projects/p2pkh-r1/forth/README.md)

## 有序公式规则

这些规则适用于封闭的算术公式。调用方须保证输入采用规范 ScriptNum 编码，并满足声明的范围。

| 规则 | 适用条件 | `stack` 加单条规则的完整路径 |
| --- | --- | ---: |
| `fold-literals` | 所有操作数均为字面量，且类型化运算合法。按 Script 的有符号余数语义求值。 | 195 B |
| `factor-products` | 两个乘积共享同一个图值。保留减法方向，重新验证新增中间值和乘积的 ScriptNum 上限。 | 196 B |
| `elide-redundant-remainder` | 已证明被除数在恒等范围内，或它已用同一个正模数取余。 | 200 B |

三条规则组合后，Script 从五次乘法和两次取余变成两次乘法和一次取余，实测栈载荷峰值从 48 B 降到 44 B。有序搜索最多接纳 32 个候选。终端 pass 列表非空时会加入未优化基线，同一终端计划下的空规则候选可用于衡量规则本身的收益。`compile.lowering.ordered_rules` 记录命中次数，追踪保留结果范围和源码位置。调用方也可用 `ScriptBuilder(..., formula_passes=["stack"], experimental_rules=[...])` 显式应用这些规则。[夹具源码](../src/fourthgraph/benchmark/formulas/modular-dot.fth)

`expand-cross-products` 在检查新中间量的范围后，将 `(a+b)(c+d)-ac-bd` 改写为 `ad+bc`。Groth16 用 `ScriptBuilder` 对 Fp2 公式应用这条规则，再把结果内联到整个验证器的算术图。栈调度器可以安排相邻运算共享的值。[Fp2 公式](../src/fourthgraph/stdlib/bls12-381-fp2.fth) · [验证器项目](../projects/groth16-verifier/README.zh-CN.md)

## 批量换序与重复常量

`byte-layout` 对一个 32 字节字段和一组打包的六个字段分别做换序和掩码运算。编译器为两种换序绑定生成相同的精确宽度检查。批量方案复用 BIP340 的六字段内核并保留字段顺序。编译器根据固定常量能否递归拆成相同的两半选择展开方式。192 字节掩码用 3 字节种子和六次 `OP_DUP OP_CAT` 生成。单字段与非重复掩码调用各走通用实现。[调用方源码](../src/fourthgraph/benchmark/fixtures/byte-layout.fth) · [字节库](../src/fourthgraph/stdlib/byte-layout.fth)

| 绑定方案 | 完整路径 | 观测主栈与备用栈合计载荷峰值 |
| --- | ---: | ---: |
| 逐字段换序与字面量掩码 | 1,720 B | 425 B |
| 批量换序 | 1,090 B | 617 B |
| 重复种子展开 | 1,542 B | 425 B |
| 批量换序加重复种子展开 | 912 B | 617 B |

`"enumerate":"binding-combinations"` 依次尝试基线、单个替换和不同调用点的组合。每个调用点只选一个内核，最多接纳 32 个计划。每个组合先链接、实测花费，再参加排名。`max_payload_bytes` 用固定开发向量上的主栈与备用栈载荷观测值筛选，包含调用方的哨兵值。超过预算的候选仍记录花费回执和排除原因。重放会核对预算和排名。四种方案各通过 24 个正例和 24 个内容变更的拒绝用例，两套引擎也拒绝了畸形字段长度。

## secp256k1 倍点窗口

`doubling-window` 暴露第一轮倍点后的精确坐标，再执行独立的九轮窗口。每种绑定都检查栈底的 secp256k1 域模数。就近方案把模数复制到 `X Y Z` 下方，窗口结束后移除副本，保留调用方的栈。报告记录字段检查、搬运成本和链接后的内核范围。[Forth 调用方](../src/fourthgraph/benchmark/fixtures/doubling-window.fth) · [现有曲线内核](../src/fourthgraph/stdlib/secp256k1.fth)

成对方案先完整执行一轮，后续每一对都从上一块获得已约减的有符号坐标，剩下一轮时用完整内核收尾。每对延迟第一次 `X` 约减，仍保留精确的有符号余数。下一轮的 `X` 只线性使用此前的 `X`，而下一轮的 `Y` 和 `Z` 只依赖已经约减的 `Y`、`Z`。非零余数保留乘数符号，零余数对应最终乘积可被模数整除。约减输入使最大的延迟 `X` 中间值的 ScriptNum 编码最多占 226 B。单轮检查点的长度不足以成对。

| 九轮窗口的绑定 | 完整路径 | 观测主栈和备用栈合计载荷峰值 |
| --- | ---: | ---: |
| 逐轮倍点，模数在栈底 | 1,171 B | 653 B |
| 成对倍点，模数在栈底 | 1,155 B | 748 B |
| 逐轮倍点，模数放到点下方 | 1,156 B | 686 B |
| 成对倍点，模数放到点下方 | 1,144 B | 781 B |

表中四组的单轮检查点使用栈底模数。搜索还实测了在检查点搬移模数的四组对应方案，该搬移在检查点多占 9 B。字节优先的胜出方案在完整调用方少执行四个 `OP_MOD`。八个方案各通过 32 个正例和 32 个替换输入点的拒绝用例，覆盖无穷远、负值与未约减坐标。两套引擎也拒绝了每套方案的错误域模数用例。

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
printf '%s\n' '{"fixture":"doubling-window","evaluation":"spend","enumerate":"binding-combinations"}' > workspace/tuning/doubling-window-request.json
printf '%s\n' '{"fixture":"doubling-window","evaluation":"spend","enumerate":"binding-combinations","max_payload_bytes":700}' > workspace/tuning/doubling-window-budget-request.json
for experiment in matrix-passes matrix-algorithms hash-bindings modular-orders byte-layout byte-layout-budget doubling-window doubling-window-budget; do
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
  tests.test_project_experiment.FormulaExperiments.test_byte_layout_spends_and_malformed_fields_match_both_engines \
  tests.test_project_experiment.FormulaExperiments.test_doubling_window_checkpoint_and_field_checks_match_both_engines
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
