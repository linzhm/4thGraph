# P2PKH-R1 支付脚本模板

开发者征求意见稿 · 未分配 BRC 编号 · [English](./p2pkh-r1-proposal.en.md)

## 付款模型

付款人只需收款人的 P-256 公钥哈希即可创建输出。花费该输出时，持有人揭示公钥并签一次当前输入的摘要。钱包通过 outpoint 指定所花费的输出；节点从 UTXO 取得金额与锁定脚本。钱包可以在本地读取完整父交易来核对这些信息。链上的解锁栈只带当前授权材料。父交易有多少输入、用过什么签名、是否曾花费另一笔 R1 输出，都不改变这项接口。

例如，一笔普通 P2PKH 付款可以创建属于 A 的 R1 输出。A 付给 B 时，交易输入引用该输出，A 的设备签本次摘要。B 下次花费时，解锁脚本只含 B 的本次签名，A 的签名留在 A 签过的交易里。

## 创建与识别输出

1. 接受 65 字节 X9.63 编码 `04 || X_BE32 || Y_BE32`，验证该点属于 secp256r1，再对这 65 字节计算 HASH160。已知收款哈希的钱包可直接使用 20 字节值。
2. 从规范模板复制原始脚本，替换从零起算的区间 `[208, 228)` 为收款哈希。脚本总长 **59,582 字节**。任何所有者生成的脚本只在这 20 字节处有差异。
3. 识别时先核对原始脚本长度及开头十字节 `760052a569766b7c8201`。提取该区间后，要求 `SHA256(raw[:208] || raw[228:])` 等于 `2129d374594069d08a9b2127555f48ea21c75fb06d1ad5e77c68ad251e97f784`，才可报告类型和收款哈希。输入从第一个 opcode 开始。字段是公钥哈希，完整公钥在花费时揭示。[模板字节](./p2pkh-r1-current-input/template.hex) · [布局及三个互操作向量](./p2pkh-r1-current-input/layout.json) · [字节匹配与生成函数](../../research/secure-enclave-p256/p2pkh_r1.py)

```sh
cd research/secure-enclave-p256
python generate_lock.py --owner-hash160 4ceab2c8be16c1d4c6b4147d39aa449c2d63f184 --format raw > scriptPubKey.bin
```

也可传入 `--public-key HEX`。省略 `--format raw` 会返回长度、所有者哈希及脚本 SHA-256。向量 C 的脚本 SHA-256 为 `b3acd6b92a23120bd24432ada2b1cac013fe06381d7ea96ac6c5a73c493f4287`。[生成器](../../research/secure-enclave-p256/generate_lock.py)

## 花费一个输入

钱包读取所引用输出并核对 txid、vout、金额、模板及公钥归属。组好含收款和找零的交易，对当前输入按所选类型构造签名原像 `P`。设备在 **SHA256d(P)** 上做一次 ECDSA P-256 摘要签名。使用签摘要接口时直接传 32 字节摘要；使用内部做一次 SHA-256 的消息接口时传 SHA256(P)。将返回值规范化为两个定宽 32 字节大端标量。钱包随后按下表从左至右构造 `scriptSig`。[钱包入口](../../research/secure-enclave-p256/checked_wallet.py) · [原像及栈构造函数](../../research/secure-enclave-p256/universal.py)

| 顺序 | 写入项 | 含义 |
|---|---|---|
| 1 | push(P) | 当前输入选定路径的签名原像 |
| 2 | push(Q) | 当前所有者的 65 字节公钥 |
| 3 | push(r ∥ s) | 当前输入的 64 字节 R1 签名 |
| 4 | push(invS) | 32 字节小端的 s⁻¹ mod n，n 为 R1 曲线阶。锁验证 s × invS ≡ 1 mod n |
| 5 | OP_0 或 OP_1 | 普通路径或下述无配对 OTDA SINGLE 伴随路径 |

锁核对 HASH160(Q)，验证 R1 签名，再通过 PUSHTX 的公开构造与原生 `OP_CHECKSIG` 将该授权绑定到节点正在验证的交易上下文。栈内既不含父交易原文，也不含前序签名。普通 ForkID ALL 的 P 为 159 字节，其中序列化的 scriptCode 为 `02 68 ac`。五项编码合计 **326 字节**（161 + 66 + 65 + 33 + 1）。[锁定脚本汇编](../../research/secure-enclave-p256/current-input.asm) · [绑定检查](../../research/secure-enclave-p256/universal-core.asm) · [nChain WP1605](https://nchain.com/wp-content/uploads/2022/03/WP1605_PUSHTX-and-its-Building-Blocks.pdf) · [BRC-21](https://github.com/bsv-blockchain/BRCs/blob/master/scripts/0021.md)

## 签名覆盖范围

每个输入独立选择类型。支持 ForkID 的 BIP143 与 Chronicle OTDA 两种算法，每种支持 ALL、NONE、SINGLE，各自可加 ANYONECANPAY。普通付款钱包默认 `0x41`。Chronicle 的 `0x20` 位与节点激活规则共同决定 OTDA 路径。此选择位于签名类型中。[Chronicle](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release) · [节点序列化与摘要](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L1894-L2124)

| 要求 | 交易摘要的承诺 |
|---|---|
| 所有输出 | ALL 覆盖有序的完整输出列表。BIP143 的 hashOutputs 对每个完整序列化输出连续哈希。OTDA ALL 在变换后的当前交易中直接序列化这些输出 |
| 任意选取输出 | NONE 对输出没有承诺。SINGLE 的输出承诺针对同索引输出。核对某个脚本或金额还需识别完整输出边界 |
| 其他输入的 outpoint | BIP143 未设 ANYONECANPAY 时，hashPrevouts 承诺所有输入的有序 outpoint；设置后该字段为零。OTDA 在变换的交易中选取输入集合 |
| 输入金额 | BIP143 原像直接包含当前输入金额。两种算法都不直接证明其他输入的金额；OTDA 原像也不序列化当前输入金额 |

BIP143 SINGLE 在当前输入没有同索引输出时，其 hashOutputs 为零，原像仍含当前 outpoint。OTDA SINGLE 在相同条件下使用节点规定的常量摘要 1。此时选 OP_1，设备签一次绑定当前输入的伴随 BIP143 SINGLE 原像，保留 ANYONECANPAY 选择。脚本内部另用公开构造验证原生 OTDA 常量摘要。此路径的 P 为 163 字节。普通 OTDA 路径的 P 可因本次输入输出而变长，例如 OTDA ALL 会包含本次创建的 R1 输出脚本。[原生节点规则](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L1894-L2124) · [路径构造](../../research/secure-enclave-p256/universal.py)

## 验收与待完成工作

隔离的 BSV Node 1.2.3 通过十二种有配对类型，以及 BIP143 与 OTDA 的无配对 SINGLE（各含 ANYONECANPAY 变体）。模拟设备在 A、B 之间连续三次按 ForkID ALL 转付，每笔一个输入、一个 R1 输出，三次解锁均为 326 字节，完整子交易均为 59,972 字节。测试逐项核对解锁边界、outpoint 和每次的节点验签结果。[连续花费与签名类型用例](../../research/secure-enclave-p256/test_current_input.py) · [运行记录](https://github.com/linzhm/bsv-script-lab/actions/runs/44377194456/job/135059377149)

补丁版 chain-gang 对普通路径通过，对无配对 OTDA SINGLE 两个伴随用例的整输入验证与 BSV Node 结果不一致。发布前须解决该互操作差异、用实际 Secure Enclave 重放摘要签名、独立复核 R1 验签和交易绑定，并在目标矿工策略下测量费用与可接受性。本模板更改只能作用于新创建的输出；历史 UTXO 的首次迁移仍遵循它原有的锁定脚本。[chain-gang 固定版本](https://github.com/linzhm/chain-gang/tree/ffa7f0cc0797d8905655ca9dd0e5270d41daee50) · [签名器接口](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey)
