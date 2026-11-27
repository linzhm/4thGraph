# BLS12-381 Groth16 verifier

[`verifier.fth`](../src/fourthgraph/stdlib/groth16-bls12-381.fth) 是本子项目的构建入口。同一份源码通过验证密钥和公开输入配置生成固定、混合和动态锁。4thGraph 解析 Forth 并检查静态栈效果，Python 后端把验证阶段降为 BSV Script，继续复用域运算、栈调度和见证编码。

| 路径 | 内容 |
| --- | --- |
| [`verifier.fth`](../src/fourthgraph/stdlib/groth16-bls12-381.fth) | 见证读取、MSM、子群检查、Miller 循环及配对余数的 Forth 源码 |
| [`build_verifier.py`](../src/fourthgraph/verification/bls12381/build.py) 与 [`bls12381/`](../src/fourthgraph/verification/bls12381/) | 编译入口、域运算和两类见证布局 |
| [`replay_verifier.py`](../src/fourthgraph/replay/bls12381_verifier.py)、[证明夹具](../projects/proof-counter/versions/v0.1.0/bls12381-counter.json) 与 [`tests/`](../tests/bls12381/) | 双引擎复放、测试证明和回归 |
| [固定声明对照](../projects/proof-counter/reference/fixed-statement/README.md) | 固定声明的 nChain 对照 |

既有的 CCTP 复放使用当时的目录和外部基线附件。复现这些测量时，请检出链接所固定的提交并按原说明运行。 [CCTP 交易边界与复放](https://github.com/linzhm/4thGraph/blob/8af1e1c33f8b90327e1ee02e00542d307495f038/projects/4thgraph/cctp/README.md) · [公开输入来源对照](https://github.com/linzhm/4thGraph/blob/8af1e1c33f8b90327e1ee02e00542d307495f038/projects/4thgraph/groth16-bls12-381/benchmarks/public-inputs/README.md)

## Forth 词

| BSV 词 | 编译内容 |
| --- | --- |
| `bls12-381-read-witness` | 解包见证，检查字节宽度、证明坐标及动态标量范围 |
| `bls12-381-check-public-inputs` | 固定项预计算，动态项在链上计算并校验公开输入 MSM |
| `bls12-381-check-g1-points` | 检查证明的 A、C 点及其子群 |
| `bls12-381-miller-loop` | 检查 B 点，计算 Miller 乘积并复用循环验证 B 的子群 |
| `bls12-381-check-residue` | 检查配对余数条件 |

`groth16-bls12-381-verify` 的静态输出 `groth16-verified` 代表完整验证路径。验证失败会终止 Script，成功留下一个真值。默认的 `--stack-schedule compact` 对稀疏配对线乘法做特化，并在检查结果可用时发出 `OP_VERIFY`。Fp12 乘法和平方在系数重组后统一取模，每次运算完成时将十二个系数约减到绝对值小于 Fp 模数的有符号余数。`--stack-schedule baseline` 使用通用域乘法和汇总验证谓词。两种模式共用见证编码。`groth16-verify` 为兼容别名。当前入口支持 BSV 验证词、Forth 词定义及栈排列词。应用可在锁外层组合签名和交易绑定。 [公开输入及绑定接口](toolchain.md#bls12-381)

编译器的余数块只接受多项式运算和同一正模数的取模。余数块的输出按模数相等，具体的有符号代表元可以不同。Verifier 在写回配对累积器或检查余数前完成约减。 [编译器实现](../src/fourthgraph/compiler/stack_schedule.py)

`compact` 模式用 `ScriptBuilder` 读取带范围的 Fp2 乘法公式，再用 `expand-cross-products` 展开虚部的交叉项。改写后的公式内联到整个验证器的算术图，由共享栈调度器安排操作数。构建清单的 `fp2_kernel` 记录公式入口、源码摘要和有序规则。 [Fp2 公式](../src/fourthgraph/stdlib/bls12-381-fp2.fth)

对只依赖显式操作数的算术图，`compact` 还比较源码顺序和按断言依赖发码的两种布局，选用序列化字节数较小的一种。两种布局按相同顺序执行断言。按依赖发码时，编译器只在断言需要某个值时发出该值的计算。 [共享栈调度器](../src/fourthgraph/compiler/stack_schedule.py)

仿射布局把斜率包定长读取交给共享调度器，`affine-witness` 也用同样的方式读取通过哈希承诺校验的配对线包。调度器把符合条件的读取改为逐次切分未读后缀，减少整包复制和偏移指令。[v0.4.0 实测记录](../projects/groth16-verifier/versions/v0.4.0/measurements.json)

紧凑发码从栈位置和剩余引用数判断何时用 `OP_TUCK` 保留二元运算的右操作数，并从单字节数字推入识别可在使用处重新推入的常量。项目和标准库入口使用同一套规则。[v0.5.0 实测记录](../projects/groth16-verifier/versions/v0.5.0/measurements.json)

高层 Forth 实验用类型化的词声明 Miller 种子轮次和终端 Fp12 剩余式。编译器核对轮次和终端断言，并允许在显式三因子乘积中选择先乘哪一对。构建与回放接受 `--arithmetic-plan` 重现搜索选出的 Fp2 改写和 Fp12 乘法顺序。[高层 Forth 实验](../projects/groth16-verifier/docs/verification.zh-CN.md#高层-forth-实验)

算术计划的 `fp2_selection: callsite` 让编译器在内联时按实际参数进行常量折叠和复用，再比较每个合法 Fp2 候选的局部栈发码。实验按完整锁与见证的序列化字节数比较调用点选择和统一公式。实验也对照 Forth 中 G1 检查和公开输入 MSM 的执行顺序。[v0.7.0 实测记录](../projects/groth16-verifier/versions/v0.7.0/measurements.json)

调用方可先写 `REQUIRE stdlib/groth16-bls12-381.fth`，再在定义体中调用验证词。构建和复放工具支持 `--entry <word>` 来选择栈效果为 `-- groth16-verified` 的入口。构建清单记录入口、导出接口及验证密钥摘要。[项目调用演示](../projects/groth16-verifier/README.zh-CN.md) · [语法书](language/syntax.md#4-公开导出)

## 调用方选择

先选定公开输入的来源、范围、Script 时代和应用交易绑定，再用 `--objective` 在满足同一证明接口的布局中比较成本。

| 目标 | 选择依据 |
| --- | --- |
| `path-bytes` | 锁和见证的序列化总长度 |
| `lock-bytes` | 锁定脚本长度 |
| `witness-bytes` | 证明见证长度 |

构建产物记录实际选中的 `witness_layout`、所有候选的字节数、排序目标和纳入摘要的选择记录。路径排序计入锁与证明见证的序列化脚本字段，包含 CompactSize。资金输入、应用原像、附加签名和其他输出按调用方的完整交易另行计量。全部公开输入固定时，只有射影布局有适用的见证格式。

需要和现有 UTXO 或见证生成器互操作时，用 `--witness-layout` 固定编码。实现选择在部署时确定。应用层可另选交易绑定和链规则。

### Script 时代

`--script-era genesis` 是默认目标。`--script-era chronicle` 允许用 `OP_2MUL`、`OP_2DIV`、`OP_SUBSTR` 和 `OP_LEFT` 缩短域运算和定长见证取片。它要求验证器 UTXO 在 Chronicle 激活后创建，支持 v1、v2 花费。同一布局下，公开输入、验证条件和见证编码相同。该开关控制 verifier 的操作码，交易认证的原像格式取决于应用绑定。

## 见证布局

| `--witness-layout` | 花费者提供的算术数据 | 固定 Γ、Δ 配对线 |
| --- | --- | --- |
| `projective`（默认） | 仿射 `VK_x` 声明和 Fp12 配对余数 | 内联 |
| `affine-inline` | MSM 窗口斜率、B 的 Miller 斜率和 Fp12 配对余数 | 内联 |
| `affine-witness` | 与 `affine-inline` 相同，另加预计算线表 | 锁含 SHA-256 承诺，花费提交表的原像 |

两种仿射布局接受动态或混合公开输入。Script 从公开输入推导窗口数位并逐步核验斜率，求出 `VK_x`。零数位、无穷远点和异号点相加的窗口要求零斜率。Miller loop 核验 B 的仿射切线或割线，检查分母非零，并用循环计算出的 `[|u|]B` 验证子群。A、C 的检查及配对余数条件沿用原谓词。验证密钥和各公开输入槽的范围由部署固定。

仿射解锁栈从底到顶依次是可选的固定线表包、斜率包、证明包和公开输入包。算术包用 48 字节小端 Fp 元素，斜率包先列 MSM 窗口，再按 Miller 顺序列 B 的 Fp2 斜率。固定线表每步依次编码 Δ 和 Γ 的截距、斜率，整包在解码前核对承诺。证明包含 A、B、C 和 Fp12 余数。应用层可继续使用最后一项公开输入包做交易绑定。

仿射算术计划可选 `msm: signed-radix4`。完整窗口用 `-1、0、1、2` 四个数位，只存基点和二倍点，负数位由基点取负。编译器与见证生成器按同一份有界进位计划生成数位和对应斜率。每个额外窗口增加 48 B 见证，需按所选计划重新生成斜率包。[MSM 实测](../projects/groth16-verifier/versions/v0.8.0/measurements.json)

有符号计划还可选 `msm_table: doubling-slopes`。锁为每个公开输入编码起始基点和由验证密钥预计算的切线斜率，Script 逐个窗口恢复二倍点和下一窗口的四倍点。两个表表示共用有符号数位及花费见证。高层 Forth 的 `bls12-381-check-g1-c-then-a` 按 C、A 的顺序执行两项 G1 检查。[点表与 Forth 实测](../projects/groth16-verifier/versions/v0.9.0/measurements.json)

`msm_table: deferred-doubling-slopes` 在倍点链上传递未归约的整数，并在每个窗口选出累加点后归约坐标。有进位的窗口直接使用偏移后的余数进行选点和符号判断。两种斜率表读取相同的见证字段。

`miller_reductions` 在两种仿射布局中选择 Fp12 累加器的归约时机。`per-operation` 分别归约平方和各乘法，`per-step` 在三次稀疏线乘法后统一归约，`per-round` 在一轮的平方、切线、可选割线和余数因子全部合并后归约。斜率核验和最终剩余式断言独立执行。后两项可用更多栈内字节换取更短的锁。[归约调度实测](../projects/groth16-verifier/versions/v0.10.0/measurements.json)

`miller_kernel: direct-normalized` 直接展开稀疏线在 Fp6 和 Fp12 的乘积，缩短中间值的栈上存活范围。它在 B 的每次仿射更新后归约坐标，并复用线截距计算下一点的 y 坐标。斜率等式及分母非零条件仍逐步核验。

`split-chord` 与 `split-chord-residue` 在一位为 1 的轮次中分别归约切线和割线阶段，后者在乘余数前也归约。两种调度共同减少大整数中间值，并共用原见证格式。[稀疏线与分段归约实测](../projects/groth16-verifier/versions/v0.11.0/measurements.json)

## 构建和复放

在仓库根目录执行，依赖见 [4thGraph 安装命令](toolchain.md#复放与编译)。示例从版本库自带的测试夹具导出一份验证密钥、证明和公开输入。

```sh
build="workspace/groth16-bls12-381"
fixture=projects/proof-counter/versions/v0.1.0/bls12381-counter.json
export PYTHONPATH="$PWD/src:$PWD"

mkdir -p "$build"
jq '.verification_key' "$fixture" > "$build/key.json"
jq '.wrap.proof' "$fixture" > "$build/proof.json"
jq '.wrap.public' "$fixture" > "$build/public.json"
printf '%s\n' '[{"bits":32},{"bits":1},{"bits":32},{"bits":2},{"bits":2}]' > "$build/inputs.json"

python -m fourthgraph.verification.bls12381.build src/fourthgraph/stdlib/groth16-bls12-381.fth \
  --verification-key "$build/key.json" --input-sources "$build/inputs.json" \
  --objective lock-bytes \
  --public "$build/public.json" --proof "$build/proof.json" \
  --output "$build/lock.json" --witness-output "$build/witness.hex"

python -m unittest discover -v -s tests/bls12381 -t tests
bash tools/verify_node.sh --profile raised -- \
  python -m fourthgraph.replay.bls12381_verifier --objective lock-bytes \
  --tx-version 2 --output "$build/replay-v2.json"
```

配置按验证密钥的公开输入槽顺序排列。整数或十进制字符串表示部署固定的标量，`null` 表示花费时提供的完整 Fr 标量，`{"bits":128}` 表示花费时提供的 128 位无符号标量，`{"max":"340282366920938463463374607431768211456"}` 表示花费时提供 `[0,2^128]` 中的标量。省略 `--input-sources` 时，所有槽采用完整 Fr 动态模式。`--public` 只为可选见证生成提供完整声明。产物 JSON 包含源码、验证密钥、脚本和构建的 SHA-256 摘要。

复放用同一份动态锁验证测试密钥下的两组公开输入。报告包含两笔真实部署和花费，以及互换声明和证明点在子群外的双引擎结果。`--tx-version 1` 可复放 v1 花费。
