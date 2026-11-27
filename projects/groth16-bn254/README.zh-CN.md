<!-- Generated from manifest.yaml with Copier. -->

# BN254 Groth16 验证器 v0.2.0

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md) · [版本](versions/index.json)

## 开发入口

用带类型的 Forth 组装需要所有者签名的 BN254 Groth16 固定声明锁，并在 Chronicle regtest 回放。

[算法与执行](#算法与执行) · [复现方法](#复现方法) · [实测数据](versions/v0.2.0/measurements.json)

| 入口 | 用途 |
| --- | --- |
| `verify-bn254-proof` | 构造授权，把部署时选定的五个公开输入折叠进 MSM，再生成 Rúnar 验证谓词。 |

## 算法与执行

Forth 入口组合所有者授权、固定声明和配对谓词。预计算声明的 MSM 后，锁定脚本从 1,524,095 B 降到 821,788 B。[Forth 入口](forth/fixed-verifier.fth) · [声明模块](forth/statement.fth) · [验证与 sCrypt 对照](docs/verification.zh-CN.md)

## 复现方法

从仓库根目录运行，使用 Python 3.11 或更新版本、Go 1.26.6 和检出到 `workspace/runar` 的固定 Rúnar 版本。入金回放还需 Chronicle chain-gang 绑定与 BSV Node。

```sh
git clone https://github.com/icellan/runar.git workspace/runar
git -C workspace/runar checkout --detach dbcc4269f8e0895c4738cf86948b05b7d62a2010
python3 -m pip install ecdsa -r tools/requirements-chronicle.txt
```

```sh
bash projects/groth16-bn254/reference/build.sh workspace/runar \
  projects/groth16-bn254/forth/fixed-verifier.fth
REGTEST_CHRONICLE_HEIGHT=2 bash tools/verify_node.sh --profile long-script -- \
  python3 -m fourthgraph.replay.groth16_bn254 --runar workspace/runar \
  --verifier-source projects/groth16-bn254/forth/fixed-verifier.fth \
  --fixture projects/groth16-bn254/versions/v0.1.0/fixture.json \
  --output projects/groth16-bn254/workspace/build/replay.json
```

构建使用仓库内的测试夹具，输出验证锁和见证前缀。入金回放在 BSV Node 和 chain-gang 上检查有效声明及四个拒绝用例。[实测](versions/v0.2.0/measurements.json)
