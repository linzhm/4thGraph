<!-- Generated from manifest.yaml with Copier. -->

# 证明计数器 v0.1.0

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md) · [版本](versions/index.json)

## 开发入口

用直接 Script 或证明后端编译并验证公开计数器的状态转换。

[算法与执行](#算法与执行) · [复现方法](#复现方法) · [实测数据](versions/v0.1.0/measurements.json)

| 入口 | 用途 |
| --- | --- |
| `4thgraph-circuit` | 将 Forth 公开关系编译为 Circom 电路。 |

## 算法与执行

**[生成电路](#generate-a-circuit)** · [可用的验证路径](../../docs/language/stdlib.zh-CN.md#验证路径) · [Groth16 固定声明对照](reference/fixed-statement/README.md)

[公开关系](verify-state.fth)导入同一份[计数规则](counter.fth)，供直接 Script 验证和 Circom 后端使用。[工作流示例](workflow.fth)把计数器用作一个交易阶段。

[工作流规划器](../../docs/design/README.zh-CN.md#构建选择与复放)比较交易布局和各阶段后端。[私有见证示例](workflow-private.fth)要求末段使用零知识证明。

## 复现方法

使用 Python 3.11 或更新版本，从仓库根目录运行版本命令。入金复放使用固定的 Chronicle 绑定和隔离节点。[Regtest 环境](../../docs/infrastructure.md)

```sh
python -m pip install ecdsa -r tools/requirements-chronicle.txt
```

```sh
PYTHONPATH=src:. python -m fourthgraph.verification.circuit_backend projects/proof-counter/verify-state.fth --output /tmp/counter.circom
PYTHONPATH=src:. bash tools/verify_node.sh --profile raised -- python -m fourthgraph.replay.groth16_bls12381 --output /tmp/proof-counter-replay.json
```

<a name="generate-a-circuit"></a>

### 生成电路

使用 Python 3.11 或更新版本，从仓库根目录运行。

```sh
bash tools/setup-workspaces.sh
PYTHONPATH=src:. python3 -m fourthgraph.verification.circuit_backend \
  projects/proof-counter/verify-state.fth \
  --output projects/proof-counter/workspace/build/counter.circom
```

生成的 `counter.circom` 包含状态转换和路由的约束，以及用于绑定实际花费的公开信号。生成 Groth16 证明还需匹配这份电路的设置文件和见证。[使用公钥构建与入金复放](../../docs/language/stdlib.zh-CN.md#验证路径) · [BLS12-381 验证器](../../docs/groth16-bls12-381.md)
