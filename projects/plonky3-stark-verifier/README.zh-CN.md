<!-- Generated from manifest.yaml with Copier. -->

# Plonky3 + SHA-256 FRI STARK 验证器 v0.2.0

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md) · [版本](versions/index.json)

## 开发入口

生成 BSV Script 锁，验证原生 Plonky3 生成的 BabyBear 证明，约束固定的 16 行 Fibonacci AIR。

[协议](docs/spec.zh-CN.md) · [算法与执行](#算法与执行) · [复现方法](#复现方法) · [实测数据](versions/v0.2.0/measurements.json)

| 入口 | 用途 |
| --- | --- |
| `stark-lock` | 将生成的 Forth 源码编译为 BSV Script 锁。 [生成的验证器](versions/v0.2.0/verifier.fth) |
| `reference/verify.py` | 生成 Forth，构建锁和见证，对比编译方案，或复放固定用例。 |

## 算法与执行

构建时把两个初值和末行右列值写入锁。Script 自行推导 Fiat–Shamir 挑战，校验 AIR 域外商等式、两组 PCS 行承诺及所有 FRI 路径，并把 64 个查询分别折叠至末轮常数。 [协议与字节布局](docs/spec.zh-CN.md)

方案采用 BabyBear 基域及四次扩域。共享的 Rust 参考证明器固定使用 Plonky3 0.5.3，并配置带标签的 SHA-256 Merkle 哈希和对应 transcript。 [原生证明器](reference/prover/src/main.rs)

## 复现方法

从仓库根目录使用 Python 3.11 或更新版本。regtest 回放另需固定版本的 chain-gang 绑定和 `ecdsa`。

`python -m pip install ecdsa -r tools/requirements-chronicle.txt`

```sh
PYTHONPATH=src:. python projects/plonky3-stark-verifier/reference/verify.py generate --plan affine
bash tools/verify_node.sh --profile long-script -- python projects/plonky3-stark-verifier/reference/verify.py replay --plan affine
```

运行 `PYTHONPATH=src:. python projects/plonky3-stark-verifier/reference/verify.py check` 检查本地 Script 夹具。入金回放确认有效花费入块，另有 12 个负例被拒绝，其中包括公开声明相同、AIR 不同的证明。 [Regtest 回执](versions/v0.2.0/replay.json)

## 脚本尺寸

公开声明为 `(0, 1, 987)` 时，锁定脚本为 **292,315 B**，解锁脚本为 **72,533 B**，原生导出的证明为 71,504 B。 [复放实测](versions/v0.2.0/replay.json) · [锁定脚本](versions/v0.2.0/lock.bin) · [解锁脚本](versions/v0.1.0/unlock.bin)

## 开发和钱包接入

用 Python 的 `generate` 根据公开输入输出完整 `verifier.fth`，可独立交给 `4thgraph script-build` 编译。`compare` 用同一见证复放四种编译方案。 [Forth 构建与编译选项](docs/spec.zh-CN.md#生成与编译-forth)
