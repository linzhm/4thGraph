# 父交易绑定与共享验证器双预像

保留现有同密钥连续性电路、验证密钥和公开声明。新增独立的父交易绑定证明，后继交易从真实 `prevouts` 取得要消费的 `txid:vout`。首轮每个 Token 输入槽独立验证绑定证明和对应输出披露。通用 BSV Groth16 验证构件可以复用。绑定关系使用独立电路及验证密钥。新增分支会改变 BSV 验证器锁哈希，首轮从新的隔离测试发行锚开始。

B2G 指从实际 Token 来源追溯到发行锚点。既有递归连续性证明负责归纳这条历史，父绑定只负责把实际 `txid:vout` 和其前序连续性声明接起来。将来若将父绑定并入每笔现有递归证明，电路需一起校验已定稿的实际父交易及该父的前序证明。此方案使用新电路及密钥，本笔证明仍以可认证的本笔交易字段为公开声明，避免在定稿前引用自身 txid。

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

同曲线普通 Groth16 的 332 字节探针已让后继 Script 用中间态证明认证实际父 outpoint 和指定 vout。最小样例的父披露与证明合计净增 854 字节，专用验证器资金还需单独计入。[独立节点记录](../fixtures/parent-checkpoint-regtest-summary.json)

采用前以真实已定稿的 Token 父交易衡量。v2 实验用锚定测试铸造、原生冻结和解冻创建真实父交易，持有人再经策略指定验证器消费该 Token。原文对照的父交易 3,433 字节，子交易和验证器资金合计 9,035 字节。v3 仍需证明父验证器资金身份、实际 vin、签名类型和前序连续性摘要。另一笔已入块的 2→2 守恒父交易为 482,360 字节，Python 已从 478,656 字节处续算同一 txid。其 3,744 字节披露仍是链下记录。 [真实 Token 对照](../fixtures/token-raw-parent-regtest-summary.json) · [2→2 实测](../fixtures/conservation-2x2-regtest-summary.json)

2→2 的实际后继为 961,015 字节。除 482,360 字节父原文，协同输入见证另有 455,207 字节，其中含 454,182 字节验证器资金交易。若该父披露按实测小样的证明尺寸编码，则 482,365 字节的原文 push 可换成约 4,827 字节的披露与证明，单项差 477,538 字节。这个字节估算未给 482,360 字节父交易出证。采用条件还包括完整父绑定、资金交易与重复见证的实测总成本。 [2→2 原始费用和字节记录](../fixtures/conservation-2x2-regtest-summary.json)

## 固定见证的验收

同一交易形状固定所选 vout 数量和当前输出布局。历史深度引入的字节增量必须为零。允许为固定结构支付更大的单笔开销，也可以为签名等本笔字段保留固定长度的槽位。祖先序列化和逐代证明列表在后继见证中占零字节。首轮从真实认证铸造接两笔相邻的同形状普通转账，第二笔必须消费第一笔实际产出的 Token 输出。核对节点准入、区块收录、父材料和整笔尺寸。两笔用于验证实际接线，见证格式限定长期上界。 [铸造基例](mint.md#铸造如何进入连续性证明)

已复核字典对照中的相邻两级。父原文分别为 519,680 和 541,309 字节，对应后继实际推入 46,981 和 68,612 字节父材料，差 21,631 字节。两份父交易的规范有序输出向量都为 3,674 字节，包含两个 Token 输出及一个回执。字典去掉了可复用的锁，仍把父交易里的上一代记录按字面保留。输出向量是定长父披露的候选，现有两笔记录只验证了字典及链下输出提取。 [独立节点原始记录](../fixtures/conservation-repeat-regtest-summary.json)

已有输出向量版可用同一父证据独立验证各槽位。定长生产候选按所选 vout 出证，以兼容父交易为铸造或付款的情况。公开声明绑定实际父 `txid:vout`、所选规范 TxOut 摘要、资产策略、实际父验证器身份与前序连续性摘要。证明内部从定稿父交易提取所选输出，并从真实验证器资金及完整输出向量重建前序摘要，SHA-256 中间态可以留在证明内部。后继只向 Script 提供固定槽位的父证明、所选 Token 输出及前序摘要。每槽分别验证，钱包按定稿 `txid:vout` 缓存制品。沿用发行锚的认证规则和现有连续性密钥。

当前可出证并入块的 Token 检查点仅覆盖 3,433 字节的原生解冻父交易。对上述 519,680 和 541,309 字节的真实普通转账，按现有 SHA-256 分块斜率外推，仅父 txid 的第一重 SHA-256 就约有 2.86 亿和 2.98 亿条约束，尚未计入真实验证器资金和完整解析。将 SHA-256 和规范交易解析做分段时，要约束分段的顺序、进出状态、已处理长度与填充，最后对后继只输出固定大小的聚合证明。两笔普通转账的定长证明和独立节点验收仍待完成。 [已出证的解冻小样](../fixtures/token-checkpoint-regtest-summary.json) · [分块成本](../recursion/parentbinding/README.md)

### Chronicle 新锁的预像和父哈希

可从新的发行锚验证仅支持 Chronicle 的锁。将本笔签名认证与父 txid 开口分别实现。`0x61` OTDA 直接包含本笔有序 outpoint、序列和输出，其他输入的脚本字段为空，执行验签的输入放清理后的 `scriptCode`，不含该输入的金额。最终 txid 仍计算定稿交易的 SHA256d，覆盖每个输入实际的 `scriptSig`。对两笔已入块普通转账做离线复算，改变一个 `scriptSig` 字节串后 txid 改变，`0x61` 和原 `0x41` 锁内预像均保持一致。新锁因此可以简化本笔关系，但父 txid 与父输出的绑定仍需单独验证。 [节点 OTDA 序列化](https://github.com/bitcoin-sv/bitcoin-sv/blob/v1.2.3/src/script/interpreter.cpp#L1725-L1786) · [节点 txid 计算](https://github.com/bitcoin-sv/bitcoin-sv/blob/v1.2.3/src/primitives/transaction.cpp#L61-L74)

Chronicle 签名类型与交易版本可分别选择。独立节点的版本 1 向量已通过激活后的 `0x61` 签名与区块校验。新锁若只使用数据推入，可先选择版本 1，沿用节点的严格编码规则。需要可执行解锁脚本的设计另测版本 2，并重新检查有效见证体积和定稿 txid 的边界。 [激活边界实测](../fixtures/chronicle-activation-regtest-summary.json) · [节点按版本应用规则](https://github.com/bitcoin-sv/bitcoin-sv/blob/v1.2.3/src/script/interpreter.cpp#L31-L39)

首轮固定形状可让父证明从同一条已认证的 SHA-256 序列按固定偏移取字段，同时检查实际 CompactSize 与输出数量。父电路用选出的实际 outpoint、序列、输出和固定 `scriptCode` 重建较短的 OTDA 摘要，和父原文 txid 的分段哈希分开验证。该方案需要同时约束各段间状态、字段所属偏移和最终填充。仅证明哈希段连接无法认证字段边界。

同一两笔转账的离线字节对照计入 push 编码，保留原执行位置和 `scriptCode` 长度。用一个 OTDA ALL 预像代替相应的 ForkID 预像、独立 prevouts 和已有 outputs push，验证器省 127 字节，两枚 Token 输入各省 128 字节。协同输入原先不读取输出，用 ALL 会多 3,549 字节，四输入合计增加 3,166 字节。若协同职责只认证输入位置和锁，可单测 `0x62` OTDA NONE。它绑定有序 outpoint，但不会绑定输出和其他输入的序列，完整输出及序列的规则继续由 `0x61` 的验证器和持有人路径执行。该组合按现有布局估算每笔省 508 字节。新版锁仍须用独立节点验收。 [2→2 实际布局](../fixtures/conservation-repeat-regtest-summary.json)

大项是普通转账协同输入重复披露约 450 kB 的验证器资金原文。可在新锚点下先验证两笔普通转账使用预先确认的验证器 UTXO，锁只认证实际 verifier `txid:vout` 是否属于已固定的集合。这样可把资金原文移出每笔见证，也避免父绑定证明重算该笔重资金交易的 txid。需要单列创建这些 UTXO 的资金交易字节。固定集合只适合有界试验，开放补充资金的认证须另有可验证规则。父交易证明仍需把父自身的最终 txid 与规范输出向量绑定。

1. 使用独立绑定证明和 `0x41` 重跑单父铸造、拆分、冻结、解冻、合并及销毁。记录每笔字节、父证据、出证和节点验收耗时，核对直接父数量固定时见证对历史深度保持稳定。
2. 将 `0x61` 接入同一共享验证器，并让父交易绑定证明重建实际分支摘要。在独立 BSV Node 的真实激活配置下，验收激活前一块、激活块、激活后一块。对链上可构造的样例交叉覆盖旧与新 UTXO、花费交易版本 1 和 2。新 UTXO 从其真实创建高度开始参与花费测试。同笔交易混用、错配预像解析器、不同执行 `OP_CODESEPARATOR` 的路径均需实测。分别记录实际花费高度的签名可用性、UTXO 创建高度的脚本规则及花费版本相关的延展性规则。`0x43` 与 `0x63` 配对资金与后继输出另验。已有差分记录经节点 `verifyscript` 取得，本项目仍需记录实际付款的内存池及区块结果。[已有 Chronicle 差分证据](../../../shared/chronicle-regression.md)
3. 对父 `txid`、vout、复制代币锁、错序输出、改量、换验证器、错误 padding 或 midstate 和旧证明复用逐项记录拒绝层。然后同一绑定接口覆盖 64→64、256→256 的共父与多父原生证明、钱包和费用。原文见证基线记录在 [容量验收](capacity.md)。

## Chronicle 独立节点边界记录

BSV Node 1.2.3 在激活高度 105 的隔离 regtest 运行 60 组原始交易。50 组通过 RPC 准入和原始候选区块验证，10 组在两层均被拒绝。用例覆盖旧与新 UTXO、激活当块创建后花费、交易版本 1 和 2、同笔混用 `0x41/0x61` 和 `0x43/0x63`，以及多个 `OP_CODESEPARATOR` 和错选分隔符。此边界矩阵使用独立的 PUSHTX 夹具锁。完整 CCTP 共享锁用 `run_certified_lifecycle.py --chronicle-all` 在启用 Chronicle 的隔离节点跑原生证明和双链生命周期。[节点验收摘要](../fixtures/chronicle-activation-regtest-summary.json) · [复现脚本](../recursion/run_chronicle_regtest.py)

该 CCTP 共享锁已完成独立 BSV regtest 与 Anvil 双链闭环。实际验证器签名类型为 3 笔 `0x41`、7 笔 `0x61`，两个签名类型共用原连续性密钥。两笔释放后，源链实际储备和 BSV 流通均为 384 个最小单位。撤销已释放对应的 BSV 销毁块后，账本重开仍保持挂起。此记录覆盖激活后的完整锁，激活边界仍由上面的专用夹具提供，公开测试网需要单独验收。[实测双链闭环](../fixtures/v3-dual-all-cross-chain-regtest-summary.json)
