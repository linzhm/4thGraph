<!-- Generated from manifest.yaml with Copier. -->

# Winterfell SHA-256 STARK v0.2.0

[English](README.md) · [4thGraph](../../README.zh-CN.md) · [项目目录](../README.zh-CN.md) · [版本](versions/index.json)

## 开发入口

用 SHA-256 承诺和 SHA-256 Fiat–Shamir transcript 生成与验证透明 STARK，并在 BSV 编译与复放哈希原语和实际 Winterfell 轨迹开封。

[算法与执行](#算法与执行) · [复现方法](#复现方法)

| 入口 | 用途 |
| --- | --- |
| `fourthgraph-stark-sha256` | 用固定的 Winterfell SHA-256 配置为公开计数器出证并验证。 |
| `hashes.fth` | 编译带标签的 SHA-256 操作，包括轨迹行、有序 Merkle 父节点及 transcript 计数器。 |
| `verify-trace-opening` | 编译深度为 13 层的轨迹开封锁，在构建时固定预期根。 |

## 算法与执行

两个证明配置共用计数器 AIR、公开输入和 FRI 参数。本项目在构建时为 Winterfell 的 Merkle 承诺和随机币固定 SHA-256。 [哈希编码与集成](docs/verification.zh-CN.md)

## 复现方法

在仓库根目录运行，使用 Rust 1.87 或以上及 Python 3.11 或以上。Cargo 使用仓库中的 lockfile。

```sh
cargo build --release --locked --manifest-path projects/stark-winterfell-sha256/reference/Cargo.toml --target-dir projects/stark-winterfell-sha256/workspace/target
cargo test --release --locked --manifest-path projects/stark-winterfell-sha256/reference/Cargo.toml --target-dir projects/stark-winterfell-sha256/workspace/target
PYTHONPATH=src:. python3 projects/stark-counter/reference/replay.py \
  --binary projects/stark-winterfell-sha256/workspace/target/release/fourthgraph-stark-sha256 \
  --measurements projects/stark-winterfell-sha256/versions/v0.1.0/measurements.json \
  --output projects/stark-winterfell-sha256/workspace/build/replay.json --check
PYTHONPATH=src:. python3 projects/stark-winterfell-sha256/reference/hash_replay.py --check
PYTHONPATH=src:. python3 projects/stark-winterfell-sha256/reference/opening_replay.py \
  --binary projects/stark-winterfell-sha256/workspace/target/release/fourthgraph-stark-sha256 --check
```

复放使用同一计数器，覆盖四份公开证明及 16 个证明拒绝用例。Rust 测试覆盖两个方向的跨配置拒绝。BSV Node 与 chain-gang 独立核对五个编译后的哈希原语。 [证明大小](versions/v0.1.0/measurements.json) · [原生 Script 实测](versions/v0.1.0/hash-checks.json)

v0.2.0 从实际证明提取轨迹查询及开封。368 B 的锁核验 13 层路径。BSV 双引擎接受三份开封，拒绝 27 个反例。 [开封复放](versions/v0.2.0/opening-checks.json)

同一开封夹具对照中，锁脚本从 550 B 降至 368 B。 [测试方法与复现](docs/verification.zh-CN.md#开封锁对照) · [版本实测](versions/v0.2.0/opening-comparison.json)
