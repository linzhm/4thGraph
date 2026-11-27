# Goldilocks SHA-256 FRI 证明配置

[English](spec.en.md) · [项目](../README.zh-CN.md) · [共用协议](../../plonky3-stark-verifier/docs/spec.zh-CN.md)

BSV 输出将公开声明固定为 `(a, b, result)`。脚本校验 16 行 Fibonacci AIR 和二进幂域 FRI，并沿用 BabyBear 配置的四轮二元折叠、128 点低度扩展与 64 个查询。任何能提交该公开声明有效证明的人均可花费输出。这是初值与结果公开的固定 AIR 实验配置。 [共用 AIR、Transcript 与 FRI 校验](../../plonky3-stark-verifier/docs/spec.zh-CN.md#验证)

## Goldilocks 参数

| 组件 | Goldilocks 参数 |
| --- | --- |
| 素数 | `2^64 - 2^32 + 1` |
| 基域生成元 | `7` |
| 扩域 | 基 `1, u`，且 `u² = 7` |
| 编码 | 规范的八字节无符号小端基域系数 |
| 初始 transcript | ASCII 字符串 `4thgraph/fibonacci-stark/v1/goldilocks` |
| 商 | 一个分块，包含两个扩域开口，每个查询行包含两个基域系数 |

锁在接受证明之前检查每个外部系数均小于素数。Merkle 叶子与 transcript 使用规范字节编码，包括最高位为 1 的值。回绕夹具从 `p - 2` 和 `p - 1` 开始。证明包沿用共用布局，系数使用 Goldilocks 对应的宽度。对 `(0, 1, 987)`，本版的原生证明、锁定脚本和解锁脚本分别为 71,984 B、137,656 B 和 73,013 B。 [证明包布局](../../plonky3-stark-verifier/docs/spec.zh-CN.md#证明包) · [回放回执](../versions/v0.2.0/replay.json)

## 生成与编译 Forth

在仓库根目录用 Python 工具链生成完整验证器，然后独立编译生成的 Forth 文件。

```sh
project=projects/goldilocks-stark-verifier
out="$project/workspace/forth"
PYTHONPATH=src:. python "$project/reference/verify.py" generate --output "$out"
PYTHONPATH=src:. python -m fourthgraph.workflow.protocol script-build \
  "$out/verifier.fth" --entry stark-lock --output "$out/lock.bin"
```

可用 `generate --public SEED_A SEED_B RESULT` 生成其他公开声明的锁。运行 `compare` 复测四个编译方案，用 `build --plan baseline` 复现 v0.1.0 锁字节。 [生成的验证器](../versions/v0.2.0/verifier.fth) · [迭代实测](../../../docs/optimization-paths.zh-CN.md#stark-验证器迭代)

## 重新生成上游证明

从仓库根目录运行，使用 Rust 1.95 及 Python 3.11 或更新版本。共用证明器在导出证明前调用 Plonky3 0.5.3 原生验证，接着用 Goldilocks Script 验证导出的证明。

```sh
project=projects/goldilocks-stark-verifier
out="$project/workspace/native"
mkdir -p "$out"
CARGO_TARGET_DIR="$project/workspace/target" cargo run --locked \
  --manifest-path projects/plonky3-stark-verifier/reference/prover/Cargo.toml \
  -- goldilocks 0 1 "$out/demo.proof"
PYTHONPATH=src:. python "$project/reference/verify.py" verify \
  --public 0 1 987 --proof "$out/demo.proof" --output "$out"
```

项目首页给出夹具构建和入金 regtest 命令。已记录的负例包括公开值相同而 AIR 不同的证明、另一声明的有效证明、篡改 Merkle 开口及错误格式的见证包。 [项目首页](../README.zh-CN.md) · [原生证明器源码](../../plonky3-stark-verifier/reference/prover/src/main.rs) · [夹具声明](../versions/v0.1.0/statements.json)
