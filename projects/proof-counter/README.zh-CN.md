# 证明计数器

[English](README.md) · [项目目录](../README.zh-CN.md)

**[生成电路](#generate-a-circuit)** · [可用的验证路径](../../docs/language/stdlib.md#验证路径) · [Groth16 固定声明对照](experiments/fixed-statement/README.md)

[公开关系](verify-state.fth)导入同一份[计数规则](counter.fth)，供直接 Script 验证和 Circom 后端使用。[工作流示例](workflow.fth)把计数器用作一个交易阶段。

<a name="generate-a-circuit"></a>

## 生成电路

使用 Python 3.11 或更新版本，从仓库根目录运行。

```sh
bash tools/setup-workspaces.sh
PYTHONPATH=src:. python3 -m fourthgraph.verification.circuit_backend \
  projects/proof-counter/verify-state.fth \
  --output projects/proof-counter/workspace/build/counter.circom
```

生成的 `counter.circom` 包含状态转换和路由的约束，以及用于绑定实际花费的公开信号。生成 Groth16 证明还需匹配这份电路的设置文件和见证。[使用公钥构建与入金复放](../../docs/language/stdlib.md#验证路径) · [BLS12-381 验证器](../../docs/groth16-bls12-381.md)
