# Groth16 验证器构建与回放

[English](verification.en.md) · [项目介绍](../README.zh-CN.md)

## Forth 调用与输入

项目通过标准库导入调用 `groth16-bls12-381-verify`。Forth 的返回类型表示证明校验成功。证明无效时 Script 终止。应用可以在验证器外组合签名授权和交易绑定。[项目源码](../verifier.fth) · [验证器接口](../../../docs/groth16-bls12-381.md)

```forth
REQUIRE stdlib/groth16-bls12-381.fth

: verify-proof ( -- groth16-verified )
    groth16-bls12-381-verify
;
```

演示使用证明计数器 v0.1.0 的公开测试验证密钥和两份证明。五个公开输入按验证密钥的槽位顺序在花费时提供，位宽依次为 32、1、32、2 和 2 位。[证明夹具](../../proof-counter/versions/v0.1.0/bls12381-counter.json) · [输入配置](../versions/v0.1.0/input-sources.json)

## 构建与回放

在仓库根目录运行 v0.5.0 的构建和验证命令可以复现标准库示例。构建通过 BLS12-381 后端选择 `verify-proof`，以 Genesis Script 为目标，按 `path-bytes` 选择见证布局。构建保存锁定脚本清单和 `wrap` 夹具的 push-only 见证。锁定脚本清单记录导入的标准库及入口名。[标准库示例构建与回放命令](../versions/v0.5.0/manifest.json)

入金回放使用 BSV Node 1.2.3 和固定的 chain-gang 绑定。回放为每份证明分别部署同一把锁，两笔 v2 花费都在 Chronicle 激活前入块。每组用例中，两种引擎都拒绝互换公开声明和 G1 点不在素数阶子群内的证明。命令将结果写到 `projects/groth16-bls12-381/workspace/build/`。[引擎版本](../../../tools/requirements-chronicle.txt)

## 测量与证据

v0.5.0 沿用相同的公开输入配置和证明夹具，比较自动操作数调度与 v0.4.0 构建。布局目标计量锁与见证脚本的序列化字段。入金回放计量完整部署和花费，包含资金输入签名与交易结构。栈峰值由开发求值器按栈内数据的字节数测量。[v0.5.0 操作数实测](../versions/v0.5.0/measurements.json) · [v0.4.0 字节包实测](../versions/v0.4.0/measurements.json) · [版本索引](../versions/index.json)

复现 Chronicle 回放时，设置 `REGTEST_CHRONICLE_HEIGHT=2`，传入 `--script-era chronicle` 并使用单独的输出文件。在任一 Script 时代指定回放布局时，将 `--objective path-bytes` 改为 `--witness-layout affine-witness` 或 `--witness-layout projective`。

## 当前 Forth 入口

[`forth/verifier.fth`](../forth/verifier.fth) 用 `REQUIRE` 引入三个模块，由 `verify-proof ( -- groth16-verified )` 串起验证流程。根目录的 [`verifier.fth`](../verifier.fth) 演示最简的标准库调用。这个项目使用 BLS12-381。

| 模块 | Forth 中的带类型流程 | 对应计算 |
| --- | --- | --- |
| [`public-inputs.fth`](../forth/public-inputs.fth) | 读取见证，检查证明点 A、C，准备配对密钥。 | 后端检查公开输入范围及 G1 点，计算 (VK_x=IC_0+\sum_i s_iIC_i)。选中的仿射计划核验有符号 radix-4 MSM 的斜率。[仿射发码](../../../src/fourthgraph/verification/bls12381/affine_witness.py) |
| [`miller.fth`](../forth/miller.fth) | 构建并执行 BLS12-381 种子首位之后的 63 轮。 | 零位累入切线，置位还累入割线与余数因子。后端逐步核验 B 的斜率和子群关系。[Miller 发码](../../../src/fourthgraph/verification/bls12381/affine_witness.py) |
| [`residue.fth`](../forth/residue.fth) | 将累积器、验证密钥因子和见证余数的 Frobenius 像相乘，断言结果属于 Fp6 且非零。 | 编译器通过扩域塔展开 Fp12 乘法与两项断言。[剩余式发码](../../../src/fourthgraph/verification/bls12381/verifier.py) |

Forth 定义验证流程和栈效应。[带类型的词表](../../../src/fourthgraph/verification/bls12381/build.py) 把这些词接到群运算与域运算后端。扩域塔通过公式编译器加载 [Fp2 乘法公式](../../../src/fourthgraph/stdlib/bls12-381-fp2.fth)。产物记录根源码、导入模块及 Fp2 公式的摘要和所用算术计划。[扩域塔实现](../../../src/fourthgraph/verification/bls12381/field.py)

从仓库根目录构建当前版本，并可回放两份证明的入金花费。

```sh
PYTHONPATH=src:. python3 projects/groth16-bls12-381/reference/replay_plan.py --release current
REGTEST_CHRONICLE_HEIGHT=1000 bash tools/verify_node.sh --profile raised -- \
  python3 projects/groth16-bls12-381/reference/replay_plan.py --release current --funded
```

Chronicle 回放使用激活高度 `2`，并加 `--script-era chronicle`。构建器校验文件、锁和见证摘要，产物写入 `projects/groth16-bls12-381/workspace/build/pinned-v0.13.0/`。入金回放另外输出交易验证报告。[v0.13.0 锁定计划](../versions/v0.13.0/replay-plan.json)

v0.12.0 沿用 v0.11.0 的 MSM 和 Miller 计划，比较每次 G1 倍点归约与连续两次倍点后归约。合并后两个时代均减少 1,282 B。对夹具的五个有界动态输入，锁加见证为 Genesis 238,122 B、Chronicle 237,217 B。 实测栈峰值为 29,891 B，配对测量的验证耗时有所上升。[v0.12.0 实测](../versions/v0.12.0/measurements.json)

v0.13.0 比较 1、4、8、16 次 G1 倍点的 Z 坐标分批方案，每种分别测试布尔优化。搜索选中启用布尔优化的 16 次分批方案。锁加见证为 Genesis 237,225 B、Chronicle 236,566 B。两份见证哈希一致，实测栈峰值为 29,891 B。配对验证耗时有升有降，报告记录了 4、8、16 次分批方案与 v0.12.0 的中位数。[v0.13.0 实测](../versions/v0.13.0/measurements.json)

nChain 对照使用相同的 BLS12-381 验证密钥、两份证明和五个有界动态输入。v0.11.0 路径为 239,404 B，nChain `fc20fb7` 三种布局、三档取模阈值中最短的路径为 394,212–396,635 B。nChain 投影布局的见证为 1,112–1,134 B。[同夹具对照实测](../versions/v0.11.0/nchain-comparison.json)

## 高层 Forth 实验

v0.6.0 实验在 Forth 中定义证明预处理、种子首位之后的 63 轮 Miller 循环，以及 Miller 累积器、验证密钥因子和见证余数的 Frobenius 像三者相乘的剩余式。最后两个词分别断言乘积属于 Fp6 且非零。后端核对轮次与 BLS12-381 种子一致，并提供见证、群和域运算原语。[高层 Forth 源码](../experiments/high-level/verifier.fth)

搜索枚举同一个 Fp2 公式上的合法改写，以及剩余式三个因子中先乘哪一对的三种选择。编译器也可在每个 Fp2 调用点对公式分别做常量折叠和公共子表达式复用，再估算局部栈发码的成本。搜索使用 `affine-inline` 见证布局比较调用点选择与统一公式生成的完整验证器。每个候选在开发求值器中检查两份有效证明和四个拒绝用例。搜索为每个 Script 时代选择序列化锁与见证合计最短的方案，平局取枚举中靠前的一项。[搜索程序](../experiments/high-level/optimize.py) · [v0.6.0 实测记录](../versions/v0.6.0/measurements.json)

v0.7.0 固定剩余式的乘法顺序，对同一份 Forth 文件做两轮改动，测量原顺序、两个 G1 检查都在公开输入 MSM 前，以及 MSM 在 A、C 两项检查之间。复现某一轮时，从报告记录的 Git 提交提取 `experiments/high-level/verifier.fth`，再用 `--source` 将副本传给搜索和回放。当前源码先检查两个 G1 点，再执行 MSM。[v0.7.0 实测记录](../versions/v0.7.0/measurements.json)

v0.8.0 在这份 Forth 上比较无符号和有符号 radix-4 MSM，并为每种方案生成对应的见证。负数位复用正倍点，末尾进位可能增加斜率窗口。搜索按序列化锁与见证的合计字节数排名。复现之前的无符号对照时可加 `--msm unsigned-radix4 --miller-reductions per-operation --miller-kernel cross-products`。有符号计划适用于两种仿射布局。[v0.8.0 MSM 实测](../versions/v0.8.0/measurements.json)

v0.9.0 固定有符号 radix-4，比较直接存点与从验证密钥的倍点切线恢复点这两种表表示。两种表示共用同一份见证。源码试验在高层 Forth 中把 C 的检查提前到 A 之前，再编译两份源码并记录完整锁和见证的大小。复现 v0.8.0 点表对照时可加 `--msm-table points --miller-reductions per-operation --miller-kernel cross-products`。[v0.9.0 点表与源码实测](../versions/v0.9.0/measurements.json)

v0.10.0 沿用同一份 Forth 源码、证明夹具和 Fp2 策略，比较三种有符号 MSM 表表示与三种 Miller 取模调度。胜出方案在 MSM 选点后归约累加坐标，并在每轮 Miller 结束时归约 Fp12 累加器。序列化见证与 v0.9.0 一致。复测 v0.10.0 调度时，省略栈预算并指定 `--miller-kernel cross-products`。加 `--miller-reductions per-step` 可测更短的取模分组。一起指定 `--msm-table doubling-slopes` 和 `--miller-reductions per-operation` 可复现 v0.9.0 对照。[v0.10.0 实测](../versions/v0.10.0/measurements.json)

v0.11.0 固定 v0.10.0 选中的 MSM 表，比较原 Miller 内核与直接展开稀疏乘积、归约 G2 点坐标的新内核。两种新增调度在含割线的轮次拆开归约，另可在乘余数前再归约一次。复现命令从两份有效开发用例在 `affine-inline` 布局下的主栈与备用栈合计数据峰值不超过 32,000 B 的候选中选最短路径。省略栈预算时按体积选版。复现 v0.10.0 胜出方案时，省略栈预算并加 `--miller-kernel cross-products --miller-reductions per-round`。[v0.11.0 实测](../versions/v0.11.0/measurements.json)

从仓库根目录运行搜索，再回放选出的 Genesis 计划。

```sh
PYTHONPATH=src:. python3 projects/groth16-bls12-381/experiments/high-level/optimize.py \
  --residue-association accumulator-frobenius-first --fp2-selection callsite --msm signed-radix4 \
  --msm-table deferred-doubling-slopes --max-fixture-stack-bytes 32000
out=projects/groth16-bls12-381/workspace/build/high-level
REGTEST_CHRONICLE_HEIGHT=1000 bash tools/verify_node.sh --profile raised -- \
  python3 -m fourthgraph.replay.bls12381_verifier \
  --source projects/groth16-bls12-381/experiments/high-level/verifier.fth \
  --entry verify-proof --witness-layout affine-inline --script-era genesis \
  --arithmetic-plan "$out/genesis-plan.json" --output "$out/genesis-replay.json"
```

回放 Chronicle 时将激活高度设为 `2`，并将回放参数中的 `genesis` 改为 `chronicle`。回放从指定的 Forth 和算术计划重新编译验证锁，再由 BSV Node 与 chain-gang 校验。
