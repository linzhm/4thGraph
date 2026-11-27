# STARK 计数器验证

[English](verification.en.md) · [项目](../README.zh-CN.md) · [发布清单](../versions/v0.1.0/manifest.json)

## 声明与证明

验证器接收两个公开 `u32` 值 `[current, next]`，核验从 `current` 连续递增 1,023 次并按模 2³² 回绕后得到 `next`。Forth 入口导入证明计数器已有的 `advance`。Rust 的 AIR 在固定轨迹形状下实现同一词义。 [Forth 入口](../counter.fth) · [共享计数词](../../proof-counter/counter.fth) · [AIR](../reference/src/counter.rs)

Winterfell 0.13.1 使用其 128 位素数域、BLAKE3-256 Merkle 承诺与 transcript，以及 FRI。验证器固定两列、1,024 行轨迹及完整证明参数，包括 40 个查询、8 倍扩展、16 位 grinding 和 8 倍 FRI 折叠。AIR 与证明参数公开，无需可信设置。本公开夹具未对轨迹加掩码。 [固定依赖](../reference/Cargo.lock) · [Winterfell](https://docs.rs/winterfell/0.13.1/winterfell/)

设 `x` 为当前状态、`x'` 为下一状态、`M = 2^32`、`d = x' - x - 1`、`h = x - (M - 1)`。轨迹每行包含 `x` 和求逆提示 `v`。每次迁移在证明的域内核对以下两条约束。

```text
h * d = 0
M * (h * v - 1) = d
```

当 `h ≠ 0` 时，约束要求 `d = 0` 且 `h * v = 1`。当 `h = 0` 时，约束要求 `d = -M`，下一行的值回绕为零。验证器以 `u32` 读取公开值，并绑定首行与末行。由初始值的范围和每步规则可知，所有中间状态也保持在 `u32` 范围内。

## 构建与复放

从仓库根目录运行发布清单中的构建与验证命令。复放编译 Forth 词，求值生成的算术 Script，对同一组公开值核验 STARK 并检查记录的证明与 Script 摘要。 [构建与验证命令](../versions/v0.1.0/manifest.json)

构建后可单独生成并验证最后一步回绕的证明。

```sh
binary=projects/stark-counter/workspace/target/release/fourthgraph-stark-counter
proof=projects/stark-counter/workspace/wrap.proof
"$binary" prove 4294966273 "$proof"
"$binary" verify 4294966273 0 "$proof"
```

| 公开输入 | 预期结果 | 序列化证明 |
| ---: | ---: | ---: |
| 19 | 1,042 | 36,620 B |
| 4,294,966,272 | 4,294,967,295 | 34,806 B |
| 4,294,966,273 | 0 | 35,307 B |
| 4,294,967,295 | 1,022 | 36,232 B |

四个用例的 Forth、Script 与 STARK 验证均一致。反例覆盖错误的起始值与结果、把证明用于另一条合法计数声明、修改或截断证明、追加字节及越界公开输入。编译的算术入口为 8,198 B。此处的大小不含交易断言和交易封装，证明字节数对应宿主格式。 [复放证据](../versions/v0.1.0/measurements.json)

## 接入 BSV

当前参考验证器在宿主运行。差分测试中的 Script 由开发求值器直接执行计数关系。要用证明约束实际花费，链上 STARK 谓词和现有交易断言须在同一笔花费中执行。

1. SHA-256 项目已固定哈希配置并通过编译器生成的 Script 核验实际轨迹开封。后续在同一配置下接入链上 transcript 挑战、AIR 求值、FRI 折叠及次数上限。 [Winterfell SHA-256 STARK](../../stark-winterfell-sha256/docs/verification.zh-CN.md)
2. 复用直接 Script 后端的公开阶段接口。锁用现有 secp256k1 BIP143 ALL 原像机制认证真实前输出，把 `current` 与消费状态核对，把 `next` 与有序后继核对，再检查证明对应同一声明与已认证的原像绑定。锁仍检查业务要求的角色签名。
3. 用目标 BSV Node 和 chain-gang 对实际入金锁复放。拒绝跨 outpoint 复用证明、变更后继金额、调换输出顺序及错误的 transcript 或 FRI 数据。测量整路字节、栈峰值及验证成本后，再把链上 STARK 纳入 CPN 候选。

BLAKE3 与 SHA-256 各自保留对应的证明夹具。零知识策略还需要轨迹掩码，并审查公开声明会披露哪些信息。 [PELS 交易绑定](../../../docs/pels-locks.zh-CN.md) · [SHA-256 轨迹开封](../../stark-winterfell-sha256/docs/verification.zh-CN.md#在-bsv-核验轨迹开封)
