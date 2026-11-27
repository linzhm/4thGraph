# Plonky3 SHA-256 FRI 证明配置

[English](spec.en.md) · [项目](../README.zh-CN.md) · [Goldilocks 配置](../../goldilocks-stark-verifier/docs/spec.zh-CN.md)

## 公开声明

锁定脚本固定三个公开域元素 `(a, b, result)`。AIR 有两列、16 行。首行为 `(a, b)`，每步按域素数取模，把 `(L, R)` 转换为 `(R, L + R)`，末行右列等于 `result`。任何能提交该声明有效证明的人均可花费输出。这是初值与结果公开的固定 AIR 实验配置。

基域 BabyBear 的素数为 `2^31 - 2^27 + 1`。挑战扩域的基为 `1, u, u², u³`，且 `u⁴ = 11`。基域系数采用规范的四字节无符号小端编码。固定配置使用 128 点低度扩展、一个商分块、四轮二元 FRI、64 个可重复采样的查询，以及一个常数末轮多项式。两项工作量参数均为零。证明器在这些参数下调用 Plonky3 0.5.3 的 uni-STARK 和二进幂域 FRI API。 [固定依赖](../reference/prover/Cargo.toml) · [证明器源码](../reference/prover/src/main.rs)

## 验证

- Merkle 叶子为 `SHA256(00 || row)`，内部节点为 `SHA256(01 || left || right)`，前缀是单字节十六进制标签。每个承诺使用单个根，路径从叶子到根排列。
- Fiat–Shamir 初始状态为 ASCII 字符串 `4thgraph/fibonacci-stark/v1/babybear`。吸收基域元素 `(4, 4, 0)`、轨迹根及三个公开值，采样 AIR 挑战 `alpha`。吸收商根、采样 `zeta`，吸收声称的开口值，再采样 PCS 挑战 `rho`。逐个吸收 FRI 根并采样该轮折叠挑战。最后吸收末轮常数及表示二元折叠的四个基域元素 1，再采样查询索引。
- 每次挤出计算 `SHA256(02 || pending)`，用所得摘要替换 `pending`。扩域挑战的每个系数独立挤出一次，把摘要作为无符号小端整数按域素数取模。查询索引取摘要首字节的低七位。
- Script 按 Plonky3 的顺序用 `alpha` 霍纳折叠五条 AIR 约束，在 `zeta` 核对清除边界分母后的商等式，并检查 `zeta^16 - 1 != 0`。轨迹在 `zeta` 和 `omega * zeta` 开口，其中 `omega` 是 16 阶子群生成元。商在 `zeta` 开口，按基重组扩域商值。
- 对每个采样出的索引，Script 在位反序陪集点 `x` 认证两组 PCS 行。它按 `rho` 的递增幂批量合并开口差值，并把见证中的倒数乘以 `(zeta - x) * (omega * zeta - x)`，检查乘积为一。所得 DEEP 求值进入 FRI。Script 对照每轮根认证有序的成对值，并计算 `(v + s)/2 + beta * (v - s)/(2 * t)`。其中 `v` 是当前值，`s` 是兄弟值，`t` 是当前值对应的子群点。进入下一轮时对该点平方，末轮折叠值必须等于末轮常数。

[Script 发码](../../../src/fourthgraph/verification/stark/script.py) · [Transcript 与编码](../../../src/fourthgraph/verification/stark/proof.py) · [Forth 片段](../../../src/fourthgraph/stdlib/stark-sha256.fth)

## 证明包

原生证明按本配置固定布局导出。扩域元素按基的顺序序列化。解锁脚本压入一个完整字节包，布局与原生导出一致，并在每组查询之前插入一个由锁校验的扩域倒数。

| 顺序 | 内容 |
| --- | --- |
| 包头 | 轨迹根与商根、四个 FRI 根、两个当前行和两个下一行轨迹开口、四个商开口、一个末轮常数 |
| 每组 PCS 查询 | 两个基域轨迹系数和七个兄弟摘要，四个基域商系数和七个兄弟摘要 |
| 每组 FRI 查询 | 每轮一个扩域兄弟值和一条 Merkle 路径，各轮路径分别含六、五、四、三个摘要 |

该版的原生证明、锁定脚本和解锁脚本分别为 71,504 B、292,315 B 和 72,533 B。64 个扩域倒数占 1,024 B，Script 压栈头占 5 B。 [构建及回放命令](../README.zh-CN.md) · [回放回执](../versions/v0.2.0/replay.json)

## 生成与编译 Forth

在仓库根目录用 Python 工具链生成完整验证器，然后独立编译生成的 Forth 文件。

```sh
project=projects/plonky3-stark-verifier
out="$project/workspace/forth"
PYTHONPATH=src:. python "$project/reference/verify.py" generate --output "$out"
PYTHONPATH=src:. python -m fourthgraph.workflow.protocol script-build \
  "$out/verifier.fth" --entry stark-lock --output "$out/lock.bin"
```

可用 `generate --public SEED_A SEED_B RESULT` 生成其他公开声明的锁。运行 `compare` 复测四个编译方案，用 `build --plan baseline --output "$project/workspace/baseline"` 复现 v0.1.0 锁字节。更换声明、方案或证明时使用单独的输出目录。复用目录前，命令会核对已有产物与报告。目录中只有锁或见证的二进制文件时，请在新目录运行 `generate`。[生成的验证器](../versions/v0.2.0/verifier.fth) · [迭代实测](../../../docs/optimization-paths.zh-CN.md#stark-验证器迭代)

## 重新生成上游证明

从仓库根目录运行，使用 Rust 1.95 及 Python 3.11 或更新版本。原生生成器会先用 Plonky3 验证证明，并按顺序打印三个公开值。随后把应用预期的公开值交给本地 Script 验证入口。

```sh
project=projects/plonky3-stark-verifier
out="$project/workspace/native"
mkdir -p "$out"
CARGO_TARGET_DIR="$project/workspace/target" cargo run --locked \
  --manifest-path "$project/reference/prover/Cargo.toml" -- babybear 0 1 "$out/demo.proof"
PYTHONPATH=src:. python "$project/reference/verify.py" verify \
  --public 0 1 987 --proof "$out/demo.proof" --output "$out"
```

测试参数 `--test-shifted-air` 保持公开声明相同，将轨迹右列平移一，并用对应的 AIR 生成证明。原生标准验证器在 AIR 商等式处拒绝。入金回放也覆盖此反例、替换声明、异常包长度和篡改开口。 [夹具声明](../versions/v0.1.0/statements.json) · [入金回放回执](../versions/v0.2.0/replay.json)
