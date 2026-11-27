<!-- Generated from manifest.yaml with Copier. -->

# BN254 Groth16 验证器 v0.4.0

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md) · [版本](versions/index.json)

## 开发入口

用带类型的 Forth 组装需要所有者签名的 BN254 Groth16 固定声明锁，并在 Chronicle regtest 回放。

[算法与执行](#算法与执行) · [复现方法](#复现方法) · [实测数据](versions/v0.4.0/measurements.json)

| 入口 | 用途 |
| --- | --- |
| `verify-bn254-proof` | 从带类型的 Forth 模块编译完整的固定声明验证器。 |

## 算法与执行

Forth 模块定义 Jacobian 公式、子群与 Miller 轮次及余数检查。编译器合并成对栈操作。`wrap` 夹具的锁为 505,179 B，见证前缀为 6,765 B。[Forth 入口](forth/verifier.fth) · [验证指南](docs/verification.zh-CN.md)

## 复现方法

从仓库根目录运行，使用 Python 3.11 或更新版本、Go 1.26.6 和检出到 `workspace/runar` 的固定 Rúnar 版本。入金回放还需 Chronicle chain-gang 绑定与 BSV Node。

```sh
git clone https://github.com/icellan/runar.git workspace/runar
git -C workspace/runar checkout --detach dbcc4269f8e0895c4738cf86948b05b7d62a2010
python3 -m pip install ecdsa -r tools/requirements-chronicle.txt
```

```sh
bash projects/groth16-bn254/reference/build.sh workspace/runar \
  projects/groth16-bn254/forth/verifier.fth
REGTEST_CHRONICLE_HEIGHT=2 bash tools/verify_node.sh --profile long-script -- \
  python3 -m fourthgraph.replay.groth16_bn254 --runar workspace/runar \
  --verifier-source projects/groth16-bn254/forth/verifier.fth \
  --fixture projects/groth16-bn254/versions/v0.1.0/fixture.json \
  --output projects/groth16-bn254/workspace/build/replay.json
```

构建输出锁定脚本和见证前缀。入金回放检查有效证明及五个拒绝用例，包括不在子群内的 G2 点。[实测](versions/v0.4.0/measurements.json)
