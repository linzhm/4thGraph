# P2PKH-R1-Deferred SDK 接入

[English](sdk.en.md)

三个源码 SDK 使用同一份[短锁模板](../template/template.hex)和[原有 R1 模板](../../p2pkh-r1/template/template.hex)。读取 `.hex` 时先去掉空白，再解码为从第一个 opcode 开始的字节。金额为整数聪。TypeScript 使用 `bigint`，Rust 使用 `u64`，Go 使用 `int64`。

| 接口 | TypeScript | Rust | Go |
|---|---|---|---|
| 从公钥哈希生成短锁 | `lockForOwner` | `lock_for_owner` | `LockForOwner` |
| 从完整公钥生成短锁 | `lockForKey` | `lock_for_key` | `LockForKey` |
| 完整识别 | `recognize` | `recognize` | `Recognize` |
| 编码启用解锁脚本 | `activationWitness` | `activation_witness`、`activation_witness_with_digest` | `ActivationWitness` |

生成接口接受两个模板、收款公钥哈希或完整公钥以及金额。两种接口均输出含 20 字节公钥哈希的短锁。识别接口接受 R1 模板、实际短锁及实际金额，返回经完整重建验证的公钥哈希、目标脚本 SHA-256 和目标输出 HASH256。旧版格式还会返回其内嵌公钥。钱包仍需按发票核对预期公钥哈希及金额。

组装启用交易时，先确定输入输出索引、手续费输入和找零。交易构造器根据实际交易和已认证的 prevout 生成 ForkID SINGLE 输出约束原像。直接使用 `0x43` 或 `0xc3` 时只传该原像。其他模式还需传 33 字节的 `typeByte || HASH256(selectedPreimage)`，并使用规范中双检查分支的 `scriptCode` 生成输出约束原像。SDK 检查原像字段及两种类型的组合，再编码解锁脚本。完整交易构造见 [Python 参考实现](../reference/README.md)。启用输出的后续付款使用[原有 R1 SDK](../../p2pkh-r1/docs/sdk.zh-CN.md)和外部签名器。

从各 SDK 目录运行 `npm test`、`cargo test` 和 `go test ./...`。三套测试使用相同的[生成和识别向量](../template/layout.json)及[十二种启用模式向量](../template/sighash-modes.json)。
