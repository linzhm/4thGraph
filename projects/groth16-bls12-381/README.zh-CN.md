<!-- Generated from manifest.yaml with Copier. -->

# BLS12-381 Groth16 验证器 v0.13.0

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md) · [版本](versions/index.json)

## 开发入口

从模块化 Forth 编译 BLS12-381 Groth16 验证器，复现 Genesis 和 Chronicle 的验证锁、见证及入金花费。

[算法与执行](#算法与执行) · [复现方法](#复现方法) · [实测数据](versions/v0.13.0/measurements.json)

| 入口 | 用途 |
| --- | --- |
| `verify-proof` | `forth/verifier.fth` 是当前模块化入口。根目录的 `verifier.fth` 演示如何调用标准库。 |
| `groth16-bls12-381-verify` | 验证 BLS12-381 Groth16 证明及其公开信号的标准库词。 |

## 算法与执行

当前入口分别引用公开输入检查、Miller 轮次和最终剩余式三个 Forth 模块。编译器解析带类型的词，并按验证密钥和公开输入配置发码。[模块化入口](forth/verifier.fth) · [Forth 及算术引用](docs/verification.zh-CN.md#当前-forth-入口)

```forth
REQUIRE BSV
REQUIRE public-inputs.fth
REQUIRE miller.fth
REQUIRE residue.fth

: verify-proof ( -- groth16-verified )
    prepare-pairing
    miller-pairing
    verify-residue
;
```

项目词通过 `REQUIRE` 导入并调用验证器。共享后端根据验证密钥和公开输入配置，将该调用编译为 BSV Script。[项目 Forth](verifier.fth) · [标准库源码](../../src/fourthgraph/stdlib/groth16-bls12-381.fth) · [见证布局与接口](../../docs/groth16-bls12-381.md)

紧凑模式用 `ScriptBuilder` 构造 Fp2 内核，并内联交叉项改写。锁定脚本清单记录公式摘要和有序规则。[Fp2 公式](../../src/fourthgraph/stdlib/bls12-381-fp2.fth)

紧凑模式对同一组断言比较两种调度顺序。定长字段按偏移递增且互不重叠时，编译器自动从未读后缀依次取出字段。[字节包发码实测](versions/v0.4.0/measurements.json)

共享调度器识别何时用 `OP_TUCK` 保留右操作数，并在使用处推入单字节数字常量。[操作数调度实测](versions/v0.5.0/measurements.json)

高层 Forth 实验搜索统一公式和按调用点选择的 Fp2 发码，并用同一个编译器测量每轮验证器源码改动。[实验与回放](docs/verification.zh-CN.md#高层-forth-实验)

搜索按序列化锁和对应见证的总长度比较有符号与无符号的公开输入 MSM。[MSM 实测](versions/v0.8.0/measurements.json)

有符号 MSM 实验比较直接存点和斜率重建，并重新编译改动后的 Forth 源码。[点表与源码实测](versions/v0.9.0/measurements.json)

编译同一份高层 Forth 时，MSM 可延后倍点表取模，Miller 循环可比较三种取模调度。[MSM 和 Miller 实测](versions/v0.10.0/measurements.json)

搜索比较直接展开稀疏线乘法、归约 G2 点坐标和拆分 Miller 轮次，并可在实测栈数据预算内选择最短路径。[Miller 内核与栈用量实测](versions/v0.11.0/measurements.json)

v0.12.0 对连续两次 G1 倍点统一归约。相同见证下，Genesis 与 Chronicle 均比 v0.11.0 少 1,282 B。[v0.12.0 实测](versions/v0.12.0/measurements.json)

v0.13.0 批量处理 Jacobian Z 坐标的缩放，并省去布尔指令前的重复数值转换。Genesis 路径再减 897 B，Chronicle 再减 651 B。[v0.13.0 实测](versions/v0.13.0/measurements.json)

## 复现方法

使用 Python 3.11 或更新版本，从仓库根目录运行。构建只用 Python 标准库。入金回放使用固定的 chain-gang 绑定和隔离的 Linux BSV Node 1.2.3。

```sh
python3 -m pip install ecdsa -r tools/requirements-chronicle.txt
```

```sh
PYTHONPATH=src:. python3 projects/groth16-bls12-381/reference/replay_plan.py --release 0.13.0
REGTEST_CHRONICLE_HEIGHT=1000 bash tools/verify_node.sh --profile raised -- \
  python3 projects/groth16-bls12-381/reference/replay_plan.py --release 0.13.0 --funded
```

当前锁定计划在输出产物前校验 Forth 模块摘要、锁脚本和两份见证。入金回放将有效花费打包入块，并拒绝互换公开声明和 G1 点不在子群内的用例。[验证与复现指南](docs/verification.zh-CN.md) · [nChain 同夹具对照](versions/v0.11.0/nchain-comparison.json)
