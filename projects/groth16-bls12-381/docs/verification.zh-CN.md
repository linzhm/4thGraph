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

Chronicle 回放使用激活高度 `2`，并加 `--script-era chronicle`。构建器校验文件、锁和见证摘要，将产物写入 `projects/groth16-bls12-381/workspace/build/pinned-v0.13.0-affine-inline/`。其中 `release.json` 把完整版本标签和布局关联到已校验的产物摘要。入金回放另输出交易验证报告。[v0.13.0-affine-inline 锁定计划](../versions/v0.13.0/replay-plan.json)

v0.12.0 沿用 v0.11.0 的 MSM 和 Miller 计划，比较每次 G1 倍点归约与连续两次倍点后归约。合并后两个时代均减少 1,282 B。对夹具的五个有界动态输入，锁加见证为 Genesis 238,122 B、Chronicle 237,217 B。 实测栈峰值为 29,891 B，配对测量的验证耗时有所上升。[v0.12.0 实测](../versions/v0.12.0/measurements.json)

v0.13.0 比较 1、4、8、16 次 G1 倍点的 Z 坐标分批方案，每种分别测试布尔优化。搜索选中启用布尔优化的 16 次分批方案。锁加见证为 Genesis 237,225 B、Chronicle 236,566 B。两份见证哈希一致，实测栈峰值为 29,891 B。配对验证耗时有升有降，报告记录了 4、8、16 次分批方案与 v0.12.0 的中位数。[v0.13.0 实测](../versions/v0.13.0/measurements.json)

## v0.14.0 布局

将上面的构建和入金命令改用 `--release v0.14.0-projective-cofactor` 或 `--release v0.14.0-affine-witness`，即可选定见证编码及算术计划。目录和索引仍使用数字版本号。每种计划分别锁定 Genesis 和 Chronicle 的脚本摘要。[版本清单](../versions/v0.14.0/manifest.json)

为每种布局和 Script 时代指定不同的 `--output` 目录。回放工具在覆盖文件前会校验目录中已有的发布元数据、锁和入金报告。

`projective-cofactor` 用 G2 齐次射影公式计算配对线，并通过校验两个有效余因子原像来检查 A、C 的 G1 子群归属。它复用 v0.13.0 的模块化 Forth、带符号 MSM 窗口表、分段 Miller 归约和布尔发码。`affine-witness` 沿用 v0.13.0 的仿射算术计划，花费时提交带哈希承诺的 Γ、Δ 配对线表。[实测与入金回放](../versions/v0.14.0/measurements.json)

| 版本标签 | Genesis 锁 | Chronicle 锁 | 单次见证 | 栈数据峰值 |
| --- | ---: | ---: | ---: | ---: |
| `v0.13.0-affine-inline` | 227,839 B | 227,180 B | 9,378 B | 29,891 B |
| `v0.14.0-projective-cofactor` | 227,775 B | 226,996 B | 1,263 B | 35,924 B |
| `v0.14.0-affine-witness` | 206,463 B | 205,803 B | 35,493 B | 61,595 B |

固定线截距归一化和成对 G1 倍点归约让两个时代的 `projective-cofactor` 锁各减少 8,013 B。两份夹具的见证都逐字节复现，实测栈数据峰值从 35,690 B 升到 35,924 B。Genesis 对照中，合并连续两个 Miller 零位还能进一步缩锁，峰值升到 53,232 B。[射影布局优化对照](../versions/v0.14.0/measurements.json)


## nChain 与 sCrypt 对照

Genesis regtest 使用同一把 BLS12-381 验证密钥、两份证明、五个有界的花费时公开输入和同一交易版本。序列化脚本路径包含锁定脚本、解锁脚本及各自的 CompactSize 长度。区间对应两份证明。[v0.13.0 入金回放](../versions/v0.13.0/nchain-comparison.json)

| 实现和布局 | 锁定脚本 | 解锁脚本 | 序列化脚本路径 |
| --- | ---: | ---: | ---: |
| 4thGraph v0.13.0，仿射坐标，链上计算配对线函数 | 227,839 B | 9,378 B | 237,225 B |
| nChain 仿射，固定配对梯度放在锁中 | 385,600 B | 8,604–11,027 B | 394,212–396,635 B |
| nChain 仿射，配对梯度放在见证中 | 373,355 B | 21,926–24,349 B | 395,289–397,712 B |
| nChain 投影坐标 | 448,202 B | 1,112–1,134 B | 449,322–449,344 B |

4thGraph 的路径比受测 nChain 的最短路径少 39.8–40.2%。nChain 的投影坐标布局解锁脚本最小。8 笔有效花费全部出块，8 个交叉声明用例均被 BSV Node 和 chain-gang 拒绝。nChain 使用未修改的 `fc20fb7`，取模阈值为前次三档扫描选出的 6,400 位。[nChain 源码](https://github.com/nchain-innovation/zkscript_package/tree/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4) · [前次扫描数据](../versions/v0.11.0/nchain-comparison.json)

下表使用各方公开示例原有的密钥和声明，按交易的指定输入和输出统计字节数。sCrypt BLS12-381 示例公布了部署交易，因此这里有锁定脚本数据。sCrypt 因数分解教程采用 BN254 和一个固定公开输入。[交易 ID 与摘要](../versions/v0.13.0/public-comparison.json) · [nChain 论文](https://eprint.iacr.org/2024/1498) · [sCrypt BLS12-381 示例](https://scryptplatform.medium.com/guest-post-elliptic-curve-bls12-381-support-on-bitcoin-bc7bfa605135) · [sCrypt BN254 教程](https://docs.scrypt.io/bsv-docs/tutorials/zkp/)

| 公开示例 | 网络和曲线 | 锁定脚本 | 解锁脚本 | 序列化脚本路径 |
| --- | --- | ---: | ---: | ---: |
| nChain Groth16 | BSV 主网，BLS12-381 | 482,601 B | 39,876 B | 522,485 B |
| sCrypt 编写的 BLS12-381 库示例 | BSV 测试网，BLS12-381 | 27,549,371 B | — | — |
| sCrypt 因数分解教程 | BSV 测试网，BN254 | 1,515,332 B | 264 B | 1,515,604 B |

从仓库根目录用固定 chain-gang 绑定的 Python 环境执行。nChain 生成器的依赖装在独立的 Python 3.12 环境里。最后一条命令下载公开交易或读取缓存，校验交易 ID 和脚本字节数。

```sh
checkout="$PWD"
ref="$checkout/projects/groth16-bls12-381/reference"
out="$checkout/projects/groth16-bls12-381/workspace/build/comparison"
git clone https://github.com/nchain-innovation/zkscript_package "$out/nchain"
git -C "$out/nchain" checkout --detach fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4
(
  cd "$out/nchain"
  python3.12 -m venv .venv
  .venv/bin/python -m pip install -r requirements.txt
  PYTHONPATH=src:. .venv/bin/python "$ref/prepare_nchain.py" "$out/nchain-scripts.json"
)
REGTEST_CHRONICLE_HEIGHT=1000 bash tools/verify_node.sh --profile raised -- \
  python3 "$ref/replay_nchain.py" "$out/nchain-scripts.json" "$out/nchain-replay.json"
PYTHONPATH=src:. python3 "$ref/check_public_comparison.py"
```

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
