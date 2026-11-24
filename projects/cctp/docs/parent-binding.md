# 父交易绑定与共享验证器双预像

保留现有同密钥连续性电路、验证密钥和公开声明。新增独立的父交易绑定证明，后继交易从真实 `prevouts` 取得要消费的 `txid:vout`，每个直接父交易只提交一次绑定证明及有序输出向量。通用 BSV Groth16 验证构件可以复用。绑定关系使用独立电路及验证密钥。新增分支会改变 BSV 验证器锁哈希，首轮从新的隔离测试发行锚开始。

## 共享验证器的两种 ALL 预像

共享验证器支持两种 `SIGHASH_ALL`。绑定签名的实际签名类型确定解析器。Node 对实际候选花费高度应用 Chronicle 规则。激活后 `0x41` 继续使用 BIP143，`0x61` 选择 OTDA。首轮允许同笔交易的共享验证器使用 `0x61`，持币输入仍用 `0x41` 签名。[Chronicle 官方说明](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release) · [Node v1.2.3 签名哈希分派](https://github.com/bitcoin-sv/bitcoin-sv/blob/v1.2.3/src/script/interpreter.cpp#L1929-L1939)

| 签名类型 | 当前交易认证 |
|---|---|
| `0x41` BIP143 | Script 构造绑定签名，由 `CHECKSIG` 认证紧凑 preimage。`hashPrevouts` 和 `hashOutputs` 核对钱包提供的有序输入和输出向量。实际资金输出同时约束 preimage 内的金额。 |
| `0x61` Chronicle OTDA | Script 构造相同角色的绑定签名，由 `CHECKSIG` 认证 OTDA preimage。规范解析输入、顺序、脚本字段、输出、锁定时间和签名类型，耗尽编码。实际资金输出提供金额。 |

两条分支向同一代币关系提供有序 outpoints、规范 outputs 和实际 preimage 的认证摘要。连续性电路仍接收原有两个公开整数。版本、执行到的 `OP_CODESEPARATOR` 和对应的 `scriptCode` 清理规则都按节点编码处理。共享验证器的分支选择必须与构造并验签的 sighash 一致。持有人、铸造方及冻结方的权限签名分开处理。冻结和解冻的 `SINGLE` 继续使用现有 `0x43` 路径，`0x63` 另做验收。[仓库签名预像编码](../../../shared/transaction.py)

新版窄形状锁将验证器实际 vin 的 `nSequence` 固定为 `0x80000041` 或 `0x80000061`。钱包在角色签名和出证前写入。锁从预像读签名类型并核对实际序列值，父交易认证从原文的实际 verifier vin 重算类型。这样在 Chronicle 可执行的版本 2 `scriptSig` 中，见证字节重排不会改写父声明的类型。两个序列值都禁用相对锁定时间。使用非零绝对 `nLockTime` 时仍适用节点的绝对终结条件。[节点版本分派](https://github.com/bitcoin-sv/bitcoin-sv/blob/v1.2.3/src/script/interpreter.cpp#L31-L39) · [节点 scriptSig 规则](https://github.com/bitcoin-sv/bitcoin-sv/blob/v1.2.3/src/script/interpreter.cpp#L2120-L2132)

用户的离线布置测量只计算共享验证器输入的数据及 push 开销。`0x61` 在已入块的部分销毁样例少 136 字节，在 64→64 和 256→256 的模拟布局多 182 和 1,146 字节。持币输入若也解析 OTDA，则需另测各输入重复携带有序输出的成本。

## 独立父交易绑定声明

绑定针对父交易定稿后的实际 `txid`。证明由后继交易消费。证明关系从规范原文重新计算 SHA256d `txid`，按实际 vin 的 CompactSize 长度和字段找到真实输出区，核对完整输出数和 `hashOutputs`。父交易实际 verifier vin 必须花费经认证的资金输出，其 outpoint、锁身份及金额必须匹配。根据该 vin 的实际认证签名类型和 `scriptCode` 重建上下文，再从真实回执与上下文导出原连续性摘要。

第一版绑定声明以以下字节的 SHA256d 作为两个大端 uint128 公开值。

```text
BSV/CCTP/parent-binding/v1\0
  || asset_id[32] || verifier_script_field_hash[32] || sighash_type[u8]
  || parent_txid_wire[32] || hashOutputs[32] || output_count[u32le]
  || continuity_digest[32]
```

`verifier_script_field_hash` 是实际验证器锁的 CompactSize 加脚本的 SHA-256。后继验证器从已认证的资产策略取得父锁身份，避免在新共享锁中硬编码它自身的哈希。输出向量采用 ALL 的逐输出规范序列化拼接。后继 Script 以真实当前 vin 的 `txid`、实际披露向量的摘要和计数、经过认证的父连续性摘要重建绑定声明。每个被消费 vout 仍需解析和核对资产、金额、锁及状态。参考提取器对 v3 旧锁重算固定 `0x41`，对双预像锁从实际 verifier vin 的 `nSequence` 重建签名类型及对应预像。

## 前缀状态与实现顺序

SHA-256 前缀检查点可以减少需要披露的字节。证明必须从初始 IV 绑定实际前缀、已处理长度、规范输出边界及后续填充。公开 midstate 和长度的哈希续算可用于交叉检查。`scriptSig` 的对齐 padding 可作为后续选项，由新锁的规范见证消费。最终 txid 必须按包含 padding 的实际父交易计算。[SHA-256 分块与填充](https://www.rfc-editor.org/rfc/rfc6234.html#section-4.1)

实际合并交易原文 22,572,492 字节。按输出计数前的整块检查点，前缀有 352,655 块，状态、长度和后缀共 2,612 字节。探针已对一个填充分块完成 Groth16 出证和验证。按 2 至 8 块实测斜率外推，整段前缀的 SHA-256 单电路约为 124.4 亿个约束，完整关系还要认证长度、输出边界和回执。首版需先评估可组合分段方案或其他 SHA-256 证明构件，再对真实长前缀出证。[原始双链记录](../fixtures/v3-certified-cross-chain-regtest-summary.json) · [SHA-256 电路实测](../recursion/parentbinding/README.md)

当前共享验证器的 `0x41` 见证携带 192 字节的完整紧凑签名预像。紧凑来自 `OP_CODESEPARATOR` 后固定的 35 字节 `scriptCode`，有序 prevouts 和 outputs 另行核对。上面的 2,612 字节来自链下父交易原文的 SHA-256 续算实验，未替换签名预像，也未接入链上父证明。验收分别记录实际签名预像字节、直接父披露及其认证证明。[现有 Preimage 构造](../../groth16/reference/transfer.py) · [父前缀参考](../recursion/parent_prefix.py)

1. 使用独立绑定证明和 `0x41` 重跑单父铸造、拆分、冻结、解冻、合并及销毁。记录每笔字节、父证据、出证和节点验收耗时，核对直接父数量固定时见证对历史深度保持稳定。
2. 将 `0x61` 接入同一共享验证器，并让父交易绑定证明重建实际分支摘要。在独立 BSV Node 的真实激活配置下，验收激活前一块、激活块、激活后一块。对链上可构造的样例交叉覆盖旧与新 UTXO、花费交易版本 1 和 2。新 UTXO 从其真实创建高度开始参与花费测试。同笔交易混用、错配预像解析器、不同执行 `OP_CODESEPARATOR` 的路径均需实测。分别记录实际花费高度的签名可用性、UTXO 创建高度的脚本规则及花费版本相关的延展性规则。`0x43` 与 `0x63` 配对资金与后继输出另验。已有差分记录经节点 `verifyscript` 取得，本项目仍需记录实际付款的内存池及区块结果。[已有 Chronicle 差分证据](../../../shared/chronicle-regression.md)
3. 对父 `txid`、vout、复制代币锁、错序输出、改量、换验证器、错误 padding 或 midstate 和旧证明复用逐项记录拒绝层。然后同一绑定接口覆盖 64→64、256→256 的共父与多父原生证明、钱包和费用。原文见证基线记录在 [容量验收](capacity.md)。

## Chronicle 独立节点边界记录

BSV Node 1.2.3 在激活高度 105 的隔离 regtest 运行 60 组原始交易。50 组通过 RPC 准入和原始候选区块验证，10 组在两层均被拒绝。用例覆盖旧与新 UTXO、激活当块创建后花费、交易版本 1 和 2、同笔混用 `0x41/0x61` 和 `0x43/0x63`，以及多个 `OP_CODESEPARATOR` 和错选分隔符。此边界矩阵使用独立的 PUSHTX 夹具锁。完整 CCTP 共享锁用 `run_certified_lifecycle.py --chronicle-all` 在启用 Chronicle 的隔离节点跑原生证明和双链生命周期。[节点验收摘要](../fixtures/chronicle-activation-regtest-summary.json) · [复现脚本](../recursion/run_chronicle_regtest.py)
