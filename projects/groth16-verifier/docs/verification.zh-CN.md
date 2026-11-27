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

入金回放使用 BSV Node 1.2.3 和固定的 chain-gang 绑定。回放为每份证明分别部署同一把锁，两笔 v2 花费都在 Chronicle 激活前入块。每组用例中，两种引擎都拒绝互换公开声明和 G1 点不在素数阶子群内的证明。命令将结果写到 `projects/groth16-verifier/workspace/build/`。[引擎版本](../../../tools/requirements-chronicle.txt)

## 测量与证据

v0.5.0 沿用相同的公开输入配置和证明夹具，比较自动操作数调度与 v0.4.0 构建。布局目标计量锁与见证脚本的序列化字段。入金回放计量完整部署和花费，包含资金输入签名与交易结构。栈峰值由开发求值器按栈内数据的字节数测量。[v0.5.0 操作数实测](../versions/v0.5.0/measurements.json) · [v0.4.0 字节包实测](../versions/v0.4.0/measurements.json) · [版本索引](../versions/index.json)

复现 Chronicle 回放时，设置 `REGTEST_CHRONICLE_HEIGHT=2`，传入 `--script-era chronicle` 并使用单独的输出文件。在任一 Script 时代指定回放布局时，将 `--objective path-bytes` 改为 `--witness-layout affine-witness` 或 `--witness-layout projective`。

## 高层 Forth 实验

v0.6.0 实验在 Forth 中定义证明预处理、种子首位之后的 63 轮 Miller 循环，以及 Miller 累积器、验证密钥因子和见证余数的 Frobenius 像三者相乘的剩余式。最后两个词分别断言乘积属于 Fp6 且非零。后端核对轮次与 BLS12-381 种子一致，并提供见证、群和域运算原语。[高层 Forth 源码](../experiments/high-level/verifier.fth)

搜索枚举同一个 Fp2 公式上的合法改写，以及剩余式三个因子中先乘哪一对的三种选择。编译器也可在每个 Fp2 调用点对公式分别做常量折叠和公共子表达式复用，再估算局部栈发码的成本。搜索使用 `affine-inline` 见证布局比较调用点选择与统一公式生成的完整验证器。每个候选在开发求值器中检查两份有效证明和四个拒绝用例。搜索为每个 Script 时代选择序列化锁与见证合计最短的方案，平局取枚举中靠前的一项。[搜索程序](../experiments/high-level/optimize.py) · [v0.6.0 实测记录](../versions/v0.6.0/measurements.json)

v0.7.0 固定剩余式的乘法顺序，对同一份 Forth 文件做两轮改动，测量原顺序、两个 G1 检查都在公开输入 MSM 前，以及 MSM 在 A、C 两项检查之间。复现某一轮时，从报告记录的 Git 提交提取 `experiments/high-level/verifier.fth`，再用 `--source` 将副本传给搜索和回放。当前源码先检查两个 G1 点，再执行 MSM。[v0.7.0 实测记录](../versions/v0.7.0/measurements.json)

从仓库根目录运行搜索，再回放选出的 Genesis 计划。

```sh
PYTHONPATH=src:. python3 projects/groth16-verifier/experiments/high-level/optimize.py \
  --residue-association accumulator-frobenius-first
out=projects/groth16-verifier/workspace/build/high-level
REGTEST_CHRONICLE_HEIGHT=1000 bash tools/verify_node.sh --profile raised -- \
  python3 -m fourthgraph.replay.bls12381_verifier \
  --source projects/groth16-verifier/experiments/high-level/verifier.fth \
  --entry verify-proof --witness-layout affine-inline --script-era genesis \
  --arithmetic-plan "$out/genesis-plan.json" --output "$out/genesis-replay.json"
```

回放 Chronicle 时将激活高度设为 `2`，并将回放参数中的 `genesis` 改为 `chronicle`。回放从指定的 Forth 和算术计划重新编译验证锁，再由 BSV Node 与 chain-gang 校验。
