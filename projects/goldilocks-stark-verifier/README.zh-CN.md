<!-- Generated from manifest.yaml with Copier. -->

# Goldilocks + SHA-256 FRI STARK 验证器 v0.2.0

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md) · [版本](versions/index.json)

## 开发入口

生成 BSV Script 锁，在 Goldilocks 基域及其二次扩域上验证固定的 16 行 Fibonacci AIR。

[协议](docs/spec.zh-CN.md) · [算法与执行](#算法与执行) · [复现方法](#复现方法) · [实测数据](versions/v0.2.0/measurements.json)

| 入口 | 用途 |
| --- | --- |
| `stark-lock` | 将生成的 Forth 源码编译为 BSV Script 锁。 [生成的验证器](versions/v0.2.0/verifier.fth) |
| `reference/verify.py` | 生成 Forth，构建锁和见证，对比编译方案，或复放固定用例。 |

## 算法与执行

验证器按模数 `2^64 - 2^32 + 1` 检查无符号 64 位系数。锁推导挑战值，认证所有 Merkle 开口，检查 64 条二元 FRI 折叠路径及 AIR 商等式。 [参数与字节布局](docs/spec.zh-CN.md)

此项目复用 Plonky3 0.5.3 证明器和 Script 后端。二次扩域、规范编码及 transcript 域标签采用 Goldilocks 专属配置。 [原生证明器](../plonky3-stark-verifier/reference/prover/src/main.rs)

## 复现方法

从仓库根目录使用 Python 3.11 或更新版本。regtest 回放另需固定版本的 chain-gang 绑定和 `ecdsa`。

`python -m pip install ecdsa -r tools/requirements-chronicle.txt`

```sh
PYTHONPATH=src:. python projects/goldilocks-stark-verifier/reference/verify.py generate --plan affine
bash tools/verify_node.sh --profile long-script -- python projects/goldilocks-stark-verifier/reference/verify.py replay --plan affine
```

运行 `PYTHONPATH=src:. python projects/goldilocks-stark-verifier/reference/verify.py check` 检查本地 Script 夹具。入金回放确认有效花费入块，另有 12 个负例被拒绝，其中包括公开声明相同、AIR 不同的证明。 [Regtest 回执](versions/v0.2.0/replay.json)

## 脚本尺寸

公开声明为 `(0, 1, 987)` 时，锁定脚本为 **137,656 B**，解锁脚本为 **73,013 B**，原生导出的证明为 71,984 B。 [复放实测](versions/v0.2.0/replay.json) · [锁定脚本](versions/v0.2.0/lock.bin) · [解锁脚本](versions/v0.1.0/unlock.bin)

## 开发和钱包接入

用 Python 的 `generate` 根据公开输入输出完整 `verifier.fth`，可独立交给 `4thgraph script-build` 编译。`compare` 用同一见证复放四种编译方案。 [Forth 构建与编译选项](docs/spec.zh-CN.md#生成与编译-forth)
