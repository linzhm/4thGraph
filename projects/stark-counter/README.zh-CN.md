<!-- Generated from manifest.yaml with Copier. -->

# STARK 计数器 v0.1.0

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md) · [版本](versions/index.json)

## 开发入口

为公开计数器生成和验证透明 STARK，并与 4thGraph 编译出的 Script 做差分。

[算法与执行](#算法与执行) · [复现方法](#复现方法) · [实测数据](versions/v0.1.0/measurements.json)

| 入口 | 用途 |
| --- | --- |
| `counter-block` | 用证明计数器的类型化 u32 Forth 词编译连续 1,023 次递增。 |
| `fourthgraph-stark-counter` | 用 Winterfell 生成证明，或按显式提供的起始值和结果验证证明。 |

## 算法与执行

证明承诺 1,024 行 AIR 执行轨迹并使用 FRI。起始值与结果公开。两条 AIR 约束核验 u32 回绕，覆盖第一步或最后一步回绕。 [验证设计](docs/verification.zh-CN.md)

## 复现方法

在仓库根目录运行，使用 Rust 1.87 或以上及 Python 3.11 或以上。Cargo 使用仓库中的 lockfile。

```sh
cargo build --release --locked --manifest-path projects/stark-counter/reference/Cargo.toml --target-dir projects/stark-counter/workspace/target
PYTHONPATH=src:. python3 projects/stark-counter/reference/replay.py --binary projects/stark-counter/workspace/target/release/fourthgraph-stark-counter --check
```

复放将四份证明与 Forth 和 Script 结果核对，并检查 16 个拒绝用例。本版由宿主验证证明。 [夹具与证明大小](versions/v0.1.0/measurements.json)
