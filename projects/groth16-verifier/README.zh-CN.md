<!-- Generated from manifest.yaml with Copier. -->

# BLS12-381 Groth16 验证器 v0.1.0

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md) · [版本](versions/index.json)

## 开发入口

在 Forth 中调用 4thGraph 的 Groth16 标准库，构建验证锁与见证，并在 BSV regtest 复放花费。

[算法与执行](#算法与执行) · [复现方法](#复现方法) · [实测数据](versions/v0.1.0/measurements.json)

| 入口 | 用途 |
| --- | --- |
| `verify-proof` | 调用标准库验证器的项目词。 |
| `groth16-bls12-381-verify` | 验证 BLS12-381 Groth16 证明及其公开信号的标准库词。 |

## 算法与执行

项目词通过 `REQUIRE` 导入并调用验证器。共享后端根据验证密钥和公开输入配置，将该调用编译为 BSV Script。[项目 Forth](verifier.fth) · [标准库源码](../../src/fourthgraph/stdlib/groth16-bls12-381.fth) · [见证布局与接口](../../docs/groth16-bls12-381.md)

## 复现方法

使用 Python 3.11 或更新版本，从仓库根目录运行。构建只用 Python 标准库。入金回放使用固定的 chain-gang 绑定和隔离的 Linux BSV Node 1.2.3。

```sh
python3 -m pip install ecdsa -r tools/requirements-chronicle.txt
```

```sh
PYTHONPATH=src:. python3 projects/groth16-verifier/reference/build.py
REGTEST_CHRONICLE_HEIGHT=1000 bash tools/verify_node.sh --profile raised -- \
  python3 -m fourthgraph.replay.bls12381_verifier \
  --source projects/groth16-verifier/verifier.fth --entry verify-proof \
  --script-era genesis --objective path-bytes --tx-version 2 \
  --output projects/groth16-verifier/workspace/build/replay.json
```

在 `projects/groth16-verifier/workspace/build/` 查看 `lock.json`、`witness.hex` 和 `replay.json`。回放将两笔有效花费打包入块，并验证互换公开声明和 G1 点不在子群内的拒绝结果。[验证与复现指南](docs/verification.zh-CN.md)
