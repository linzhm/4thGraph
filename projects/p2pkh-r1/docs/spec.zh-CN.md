# P2PKH-R1 支付脚本模板

开发者征求意见稿 · 未分配 BRC 编号 · [English](./spec.en.md)

## 付款模型

付款人只需收款人的 P-256 公钥哈希即可创建输出。花费该输出时，持有人揭示公钥并签一次当前输入的摘要。钱包通过 outpoint 指定所花费的输出；节点从 UTXO 取得金额与锁定脚本。钱包可以在本地读取完整父交易来核对这些信息。链上的解锁栈只带当前授权材料。父交易有多少输入、用过什么签名、是否曾花费另一笔 R1 输出，都不改变这项接口。

例如，一笔普通 P2PKH 付款可以创建属于 A 的 R1 输出。A 付给 B 时，交易输入引用该输出，A 的设备签本次摘要。B 下次花费时，解锁脚本只含 B 的本次签名，A 的签名留在 A 签过的交易里。

## 创建与识别输出

1. 接受 65 字节 X9.63 编码 `04 || X_BE32 || Y_BE32`，验证该点属于 secp256r1，再对这 65 字节计算 HASH160。已知收款哈希的钱包可直接使用 20 字节值。
2. 复制 v0.2.0 锁定模板，将收款哈希填入从零起算的区间 `[208, 228)`。脚本总长 **46,302 字节**。
3. 返回收款哈希前，按实际版本核对长度和固定字节指纹。自第一个 opcode 起算，取 `SHA256(raw[:208] || raw[228:])`。v0.2.0 的指纹为 `52a1d9eb9e236403c66e845e18cf31d9c3a5f4c2e0ed7ca0270a60ba4e867ca6`。识别 v0.1.0 上一输出时按旧版布局核对。 [v0.2.0](../versions/v0.2.0/layout.json) · [v0.1.0](../versions/v0.1.0/layout.json)

将 `R1_OWNER_HASH160` 设为收款人 20 字节 HASH160 的十六进制值。

```sh
cd projects/p2pkh-r1/reference
python generate_lock.py --owner-hash160 "${R1_OWNER_HASH160:?请设置收款公钥哈希}" --format raw > scriptPubKey.bin
```

也可传入 `--public-key HEX`。省略 `--format raw` 会返回长度、所有者哈希及脚本 SHA-256。规范模板内置向量 C 的公开测试公钥哈希，对应输出仅用于本地测试。向量 C 的脚本 SHA-256 为 `b3acd6b92a23120bd24432ada2b1cac013fe06381d7ea96ac6c5a73c493f4287`。[生成器](../reference/generate_lock.py)

## 花费一个输入

钱包读取所引用输出并核对 txid、vout、金额、模板及公钥归属。组好含收款和找零的交易，对当前输入按所选类型构造签名原像 `P`。设备在 **SHA256d(P)** 上做一次 ECDSA P-256 摘要签名。使用签摘要接口时直接传 32 字节摘要；使用内部做一次 SHA-256 的消息接口时传 SHA256(P)。将返回值规范化为两个定宽 32 字节大端标量。钱包随后按下表从左至右构造 `scriptSig`。[钱包入口](../reference/wallet.py) · [原像及栈构造函数](../reference/signature.py)

| 顺序 | 写入项 | 含义 |
|---|---|---|
| 1 | push(P) | 当前输入选定路径的签名原像 |
| 2 | push(Q) | 当前所有者的 65 字节公钥 |
| 3 | push(r ∥ s) | 当前输入的 64 字节 R1 签名 |
| 4 | push(invS) | 32 字节小端的 s⁻¹ mod n，n 为 R1 曲线阶。锁验证 s × invS ≡ 1 mod n |
| 5 | OP_0 或 OP_1 | 普通路径或下述无配对 OTDA SINGLE 伴随路径 |

钱包必须根据已构造的交易及本输入请求的签名类型计算第 5 项。仅当类型为 0x63 或 0xe3，且从零起算的输入索引大于或等于输出数量时，写入 OP_1。其余受支持的情况一律写入 OP_0。普通付款接口固定使用 0x41，不提供分支位或签名类型参数。多输入协议如需显式使用其他签名类型，仍按同一规则计算分支位。[钱包实现](../reference/wallet.py) · [分支位计算](../reference/signature.py)

钱包识别收款时，应同时核对完整模板指纹和预期的收款公钥哈希。付款方可以构造任意输出脚本。如果额外要求收款人只能用 NONE，固定程序的字节就发生改变，模板检查会失败。付款方自己的签名类型只控制它所签的输入。收款人以后花费这个输出时，可以自行选择模板支持的签名类型。

锁核对 HASH160(Q)，验证 R1 签名，再通过 PUSHTX 的公开构造与原生 `OP_CHECKSIG` 将该授权绑定到节点正在验证的交易上下文。栈内既不含父交易原文，也不含前序签名。普通 BIP143 ALL 的 P 为 159 字节，其中序列化的 scriptCode 为 `02 68 ac`。五项编码合计 **326 字节**（161 + 66 + 65 + 33 + 1）。[锁定脚本汇编](../reference/asm/lock.asm) · [绑定检查](../reference/asm/binding.asm) · [nChain WP1605](https://nchain.com/wp-content/uploads/2022/03/WP1605_PUSHTX-and-its-Building-Blocks.pdf) · [BRC-21](https://github.com/bsv-blockchain/BRCs/blob/master/scripts/0021.md)

钱包先从实际交易和签名类型构造 P，再计算摘要，由所有者用 R1 私钥签一次。R1 验签证明所有者授权。随后 secp256k1 PUSHTX 复用这个摘要，按公开参数构造原生签名，节点用它核对自己正在验证的交易上下文。花费者只需持有 R1 私钥。两项检查共同绑定的是所选 SIGHASH 承诺的字段。[nChain PUSHTX 实现](https://github.com/nchain-innovation/zkscript_package/blob/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4/src/zkscript/transaction_introspection/transaction_introspection.py)

## 未确认的父交易输出

签署子交易前，应从可信链视图核对父交易达到应用要求的确认深度，并使用实际确认的
outpoint。允许不同解锁编码的规则可能导致未确认父交易的 txid 改变。
任何以不同 txid 确认的版本都会使引用原 outpoint 的子交易失效。如果实际确认的版本
仍含有预期的未花费输出，持有人可以用实际的 outpoint 重新授权子交易。
[未确认父交易](./chronicle.md#未确认父交易)

## 签名覆盖范围

每个输入独立选择类型。支持 BIP143 与 Chronicle OTDA 两种算法，每种支持 ALL、NONE、SINGLE，各自可加 ANYONECANPAY。普通付款接口固定使用 `0x41`。Chronicle 的 `0x20` 位与节点激活规则共同决定 OTDA 路径。此选择位于签名类型中。[Chronicle](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release) · [节点序列化与摘要](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L1894-L2124)

| 要求 | 交易摘要的承诺 |
|---|---|
| 所有输出 | ALL 覆盖有序的完整输出列表。BIP143 的 hashOutputs 对每个完整序列化输出连续哈希。OTDA ALL 在变换后的当前交易中直接序列化这些输出 |
| 任意选取输出 | NONE 对输出没有承诺。SINGLE 的输出承诺针对同索引输出。核对某个脚本或金额还需识别完整输出边界 |
| 其他输入的 outpoint | BIP143 未设 ANYONECANPAY 时，hashPrevouts 承诺所有输入的有序 outpoint；设置后该字段为零。OTDA 在变换的交易中选取输入集合 |
| 输入金额 | BIP143 原像直接包含当前输入金额。两种算法都不直接证明其他输入的金额；OTDA 原像也不序列化当前输入金额 |

BIP143 SINGLE 在当前输入没有同索引输出时，其 hashOutputs 为零，原像仍含当前 outpoint。OTDA SINGLE 在相同条件下使用节点规定的常量摘要 1。此时钱包自动写入 OP_1，设备签一次绑定当前输入的伴随 BIP143 SINGLE 原像，保留 ANYONECANPAY 选择。脚本内部另用公开构造验证原生 OTDA 常量摘要。此路径的 P 为 163 字节。普通 OTDA 路径的 P 可因本次输入输出而变长，例如 OTDA ALL 会包含本次创建的 R1 输出脚本。[原生节点规则](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L1894-L2124) · [路径构造](../reference/signature.py)

v0.1.0 的展开程序共 59,582 字节，其中四位窗口标量乘法占 57,224 字节（96.0%）。普通 k1 签名构造块本身占 394 字节，这个数字不含外围分支和原生 CHECKSIG 指令。这里统计的是序列化指令体积，执行时间需另外测量。[窗口运算](../reference/asm/window.asm) · [公开 k1 构造](../reference/asm/r1.asm)

## 签名消息与编码

普通 BIP143 路径按以下顺序拼接。scriptCode 前写 CompactSize 长度；交易版本、输出索引、sequence、locktime 和签名类型用 4 字节小端整数，金额用 8 字节小端聪。outpoint 由线序的前序 txid 和输出索引组成。最后组装的交易只写入一次解锁脚本。

```text
version || hashPrevouts || hashSequence || outpoint || 02 68 ac ||
amount || sequence || hashOutputs || locktime || typeLE32
```

普通原像为 159 字节。伴随路径将 `02 68 ac` 换为 `06 63 ad 67 ab 68 ac`。BIP143 在 NONE、SINGLE 或带 ANYONECANPAY 时将 hashSequence 置零。SINGLE 缺少同索引输出时，实际交易无需补输出。有配对的 OTDA SINGLE 在签名序列化中给更早的索引写空输出占位，这些占位只用于算摘要。按所在网络激活规则与当前花费上下文运行节点算法。普通付款 SDK 使用交易版本 2、最终 sequence 和零 locktime。[普通花费向量](../versions/v0.1.0/spend-all.json) · [参考原像构造器](../reference/signature.py)

## 安全与互操作

公钥必须是曲线上的有效点，签名标量均须位于 `[1,n)`。签名设备保护私钥和临时秘密数，解锁栈只含公开数据。钱包签名前核对完整前序输出、收款人、找零及手续费，返回交易前验证设备签名。签名服务可跨调用保存记录，发现同一公钥对不同摘要返回相同 r 时扣住签名。Python 参考钱包包含这项检查。NONE 授权允许更改输出；多输入协议如需保护收款人，应明确由哪个输入的签名约束输出。[参考钱包](../reference/wallet.py)

收款和普通付款接口、调用方提供的数据及互操作用例见 [SDK 指南](./sdk.zh-CN.md)。引擎互操作验收使用 BSV Node 1.2.3 和[chain-gang 的 OTDA 修复提交](https://github.com/linzhm/chain-gang/commit/8b60b71a12a69fdcb465d3e627dbf6f43d6ed081)，对同一份交易执行[完整输入验证](../reference/test_payment.py)。两个无配对 OTDA SINGLE 用例也必须整笔重放。scriptCode 由最后一个**实际执行**的分隔符决定，误删 BIP143 后缀中的另一分隔符会改变摘要。发布前还需真实设备签名回放、独立密码学审查，以及目标矿工策略与费用实测。[Chronicle 规则适用性](./chronicle.md)

## 致谢

感谢 Wei Zhang 在 nChain 白皮书《PUSHTX and its Building Blocks》（WP1605）中说明如何用公开参数构造 secp256k1 签名，并借助原生 `OP_CHECKSIG` 把签名原像绑定到实际交易。P2PKH-R1 沿用了这项技术来验证交易上下文。[WP1605 文献条目](https://github.com/bsv-blockchain/BRCs/blob/master/scripts/0021.md#references) · [nChain 的 PUSHTX 实现](https://github.com/nchain-innovation/zkscript_package/blob/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4/src/zkscript/transaction_introspection/transaction_introspection.py)

感谢 Xiaohui Liu 对 OP_PUSH_TX 在 Bitcoin Script 中的应用所作的公开讲解，也感谢 BRC-21 的贡献者记录了如何在解锁栈中提供签名原像。[Xiaohui Liu 的技术演讲](https://www.wearedevelopers.com/videos/146-op_push_tx-and-its-applications-in-bitcoin-smart-contracts) · [BRC-21](https://github.com/bsv-blockchain/BRCs/blob/master/scripts/0021.md)

感谢 BSV Node 和 chain-gang 的维护者。两套实现使我们能够对同一笔交易独立执行完整输入验证，并比较 Chronicle 分支的行为。[BSV Node](https://github.com/bitcoin-sv/bitcoin-sv) · [chain-gang](https://github.com/nchain-innovation/chain-gang)
