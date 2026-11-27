<!-- Generated from manifest.yaml with Copier. -->

# BLS12-381 Groth16 验证器 v0.11.0

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md) · [版本](versions/index.json)

## 开发入口

在 Forth 中调用 4thGraph 的 Groth16 标准库，构建验证锁与见证，并在 BSV regtest 复放花费。

[算法与执行](#算法与执行) · [复现方法](#复现方法) · [实测数据](versions/v0.11.0/measurements.json)

| 入口 | 用途 |
| --- | --- |
| `verify-proof` | 调用标准库验证器的项目词。 |
| `groth16-bls12-381-verify` | 验证 BLS12-381 Groth16 证明及其公开信号的标准库词。 |

## 算法与执行

项目词通过 `REQUIRE` 导入并调用验证器。共享后端根据验证密钥和公开输入配置，将该调用编译为 BSV Script。[项目 Forth](verifier.fth) · [标准库源码](../../src/fourthgraph/stdlib/groth16-bls12-381.fth) · [见证布局与接口](../../docs/groth16-bls12-381.md)

紧凑模式用 `ScriptBuilder` 构造 Fp2 内核，并内联交叉项改写。锁定脚本清单记录公式摘要和有序规则。[Fp2 公式](../../src/fourthgraph/stdlib/bls12-381-fp2.fth)

紧凑模式对同一组断言比较两种调度顺序。定长字段按偏移递增且互不重叠时，编译器自动从未读后缀依次取出字段。[字节包发码实测](versions/v0.4.0/measurements.json)

共享调度器识别何时用 `OP_TUCK` 保留右操作数，并在使用处推入单字节数字常量。[操作数调度实测](versions/v0.5.0/measurements.json)

高层 Forth 实验搜索统一公式和按调用点选择的 Fp2 发码，并用同一个编译器测量每轮验证器源码改动。[实验与回放](docs/verification.zh-CN.md#高层-forth-实验)

搜索按序列化锁和对应见证的总长度比较有符号与无符号的公开输入 MSM。[MSM 实测](versions/v0.8.0/measurements.json)

有符号 MSM 实验比较直接存点和斜率重建，并重新编译改动后的 Forth 源码。[点表与源码实测](versions/v0.9.0/measurements.json)

编译同一份高层 Forth 时，MSM 可延后倍点表取模，Miller 循环可比较三种取模调度。[MSM 和 Miller 实测](versions/v0.10.0/measurements.json)

搜索比较直接展开稀疏线乘法、归约 G2 点坐标和拆分 Miller 轮次，并可在实测栈数据预算内选择最短路径。[Miller 内核与栈用量实测](versions/v0.11.0/measurements.json)

## 复现方法

使用 Python 3.11 或更新版本，从仓库根目录运行。构建只用 Python 标准库。入金回放使用固定的 chain-gang 绑定和隔离的 Linux BSV Node 1.2.3。

```sh
python3 -m pip install ecdsa -r tools/requirements-chronicle.txt
```

```sh
PYTHONPATH=src:. python3 projects/groth16-verifier/experiments/high-level/optimize.py \
  --residue-association accumulator-frobenius-first --fp2-selection callsite --msm signed-radix4 \
  --msm-table deferred-doubling-slopes --max-fixture-stack-bytes 32000
REGTEST_CHRONICLE_HEIGHT=1000 bash tools/verify_node.sh --profile raised -- \
  python3 -m fourthgraph.replay.bls12381_verifier \
  --source projects/groth16-verifier/experiments/high-level/verifier.fth \
  --entry verify-proof --witness-layout affine-inline --script-era genesis \
  --arithmetic-plan projects/groth16-verifier/workspace/build/high-level/genesis-plan.json \
  --output projects/groth16-verifier/workspace/build/high-level/genesis-replay.json
```

高层实验将 `search.json`、胜出的锁和计划以及入金回放写入 `projects/groth16-verifier/workspace/build/high-level/`。回放将两笔有效花费打包入块，并验证互换公开声明和 G1 点不在子群内的拒绝结果。[验证与复现指南](docs/verification.zh-CN.md)
