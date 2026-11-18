# PELS 如何支持可变数量的输入和输出

**结论。** 如果规则只是“花费一个合约 UTXO 时，在花费交易的同索引输出延续该合约”，锁定脚本只需验证一个完整输出。用 ForkID 的 `SIGHASH_SINGLE`，节点负责选择对应输出，脚本负责规定该输出应有的金额和锁定脚本。输入、输出总数可以在构造交易时确定。只有当规则涉及其他输入或全部输出时，才增加对应的核验。

普通付款可以由持有人签署全部输出，后继输出无需复刻原锁。Apple Secure Enclave 的 P-256 付款脚本已单独给出，默认采用 `ALL|FORKID`。[脚本形态、签名接口与验收](../../research/secure-enclave-p256/README.md)

## 交易与证据

记花费交易为 `T`，当前正在验证的输入在 `T.vin` 中的位置为 `i`，索引从零开始。`vin[i].prevout.n` 是被花费输出在**父交易**里的位置，可以不同于 `i`。PELS（Perpetually Enforcing Locking Script）的延续关系是：旧 UTXO 的脚本约束这一次花费，新 UTXO 携带同一规则，于是下一次花费仍须满足它。指定一条延续链，并不赋予该链对交易其余资金的控制权。[nChain 的 PELS 实例，图 6、7](https://patents.google.com/patent/US20250088370A1/en)

花费者在链下选择输入、排列输出，生成本输入的 ForkID 签名原像，并提供业务规则要检查的材料。锁定脚本按照约定的字段宽度与序列化规则构成候选原像；PUSHTX 用固定验证参数、从该候选消息导出的签名和 `OP_CHECKSIG`，把消息与节点针对实际 `(T,i)` 计算的摘要联系起来。只有通过绑定的那份数据才能用于后续检查。PUSHTX 是脚本组合；它使用的公开签名参数不代表持有人的花费授权。有授权要求的合约还须执行自己的授权条件。[BRC-21 的 Specification](https://bsv.brc.dev/scripts/0021) · [BSV 节点 CheckSig 调用路径](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L2112-L2164)

**白皮书原文（2026-11-18 核对）。** Wei Zhang 的《PUSHTX and its Building Blocks》，编号 WP1605，封面修订日期为 2021-12-14，共 25 页。§1.1（第 4–5 页）区分消息绑定和持有人授权；§1.2 表 1（第 6 页）列出签名消息的 11 项，随后在第 6–7 页用花费者提交的序列化输出重建第 9 项。表中的“不可预先固定”指父 txid 等自引用字段无法在创建锁时写死，花费时仍可验证其原像。旧官网链接跳转首页，章节和页码以用户资料库中的同名原文为准。[WP1605 出版方原址](https://nchain.com/wp-content/uploads/2022/03/WP1605_PUSHTX-and-its-Building-Blocks.pdf) · [nChain 对照实例](https://patents.google.com/patent/US20250088370A1/en)

**实例与本文推荐的区别。** §1.3 图 1、图 2（第 8–9 页）采用一入一出，强制 Bob 的完整锁定脚本与 1,000 聪一同延续。第 11 页单独讨论另加输入付费，以及在 `SINGLE|ANYONECANPAY` 下追加找零。§1.4（第 12 页）直接从旧输出的脚本和金额重建期望的新输出，省去重复提交。§2（第 15–17 页）把消息完整性和 Bob 的授权签名分开，并讨论固定公钥和签名类型。本文的一般化依据是 BSV 节点 v1.2.3 的 ForkID 路径；越界取零、outpoint 的定宽切片、变长输出的边界证明均按源码分析。BIP143 用来对照摘要结构及配对语义。[BSV v1.2.3](https://github.com/bitcoin-sv/bitcoin-sv/releases/tag/v1.2.3) · [BIP143 原规范](https://bips.dev/143/)

## 节点实际承诺的字段

令 `H(x) = SHA256(SHA256(x))`，`||` 表示字节拼接。以下均为 ForkID 已启用、带 `FORKID=0x40`、未置 `CHRONICLE` 位时的 BIP143 式分支。业务分支应固定完整的签名类型，同时约束原像末尾四字节小端类型和用于核验的签名末尾类型字节。[节点选择摘要算法](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L2112-L2158) · [标志位定义](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/sighashtype.h#L12-L22)

| 本输入的签名类型（均含 ForkID） | hashPrevouts | hashSequence | hashOutputs |
| --- | --- | --- | --- |
| `ALL`（0x41） | 全部输入的有序 outpoint 摘要 | 全部输入的有序 sequence 摘要 | 全部输出的有序摘要 |
| `SINGLE`（0x43） | 全部输入的有序 outpoint 摘要 | 32 字节零 | 同索引输出摘要，越界为 32 字节零 |
| `ALL + ANYONECANPAY`（0xc1） | 32 字节零 | 32 字节零 | 全部输出的有序摘要 |
| `SINGLE + ANYONECANPAY`（0xc3） | 32 字节零 | 32 字节零 | 同索引输出摘要，越界为 32 字节零 |

`NONE` 的 `hashOutputs` 为零，无法支撑这里的延续规则。持有人付款可以显式选择这种授权：`0x42` 保留全部输入 outpoint，`0xc2` 只绑定当前输入，两者均允许替换全部输出。[手写 P-256 付款锁的六种模式](../../research/secure-enclave-p256/README.md)表中的“零”指字段取全零常量。每一行还直接写入交易版本、当前 outpoint、当前执行的 `scriptCode`（含序列化长度）、当前所花 UTXO 的金额、当前 sequence、交易锁定时间及签名类型。金额是当前输入单独的 8 字节字段。原像没有独立的输入位置、输入总数或输出总数字段；其他输入的解锁脚本、签名和逐项金额也不在其中。[节点聚合和原像构造](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L1960-L1982) · [字段写入顺序](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L2034-L2084)

节点对 outpoint 逐项写入 32 字节交易标识（线序）和 4 字节小端输出序号。节点对输出逐项写入 `E(v,s) = LE64(v) || CompactSize(len(s)) || s`，其中金额以聪计，脚本长度以字节计。两种聚合都**不带向量开头的数量前缀**，每个输出内部仍有脚本长度前缀。完整交易序列化则包含输入和输出向量的数量。下文的摘要等式假设双 SHA-256 具有相应的抗碰撞及抗第二原像性。[BSV 交易类型与序列化](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/primitives/transaction.h) · [CompactSize 编解码规则](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/serialize.h#L296-L340)

## 四类要求分别需要什么证据

### 1. 延续同索引的一个输出

最小示例要求“脚本完全相同、金额原额延续”。为使含义明确，选无 `OP_CODESEPARATOR` 的合约模板，以经绑定的当前完整锁定脚本和当前输入金额构造预期 `E`；直接复用已序列化的 `scriptCode` 时，其长度前缀只计一次。对于带分隔符的模板，需要另证完整规则的来源，不能把执行后缀当成整个锁定脚本。如果业务允许更新状态，应由旧脚本验证转换条件，并由验证过的状态及既定模板导出后继脚本。让花费者自由选择“预期脚本”会使延续条件失效。[BIP143 对 scriptCode 的定义](https://bips.dev/143/) · [nChain 延续示例](https://patents.google.com/patent/US20250088370A1/en)

固定 `0x43`，要求已绑定的 `hashOutputs` 不等于 32 个零字节，且 `hashOutputs = H(E)`。节点用真实的 `i` 选取 `vout[i]`，脚本无需接收 `i` 或扫描其他输出。越界时该字段留零，ForkID 分支仍计算整个原像的摘要，不走旧算法返回整数一的分支。其他位置可以有找零、普通付款，甚至相同脚本的副本；若要求全交易恰有一个副本，就要核验全部输出。[BSV 的两个 SINGLE 分支](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L2053-L2110)

`0x43` 允许构造时选择任意可接受的输入数，生成签名后改变输入列表则会改变 `hashPrevouts`。如果业务明确允许他人事后补费，并且不关心其他输入身份，可固定 `0xc3`。保持其他已承诺字段相同，本输入与对应输出可以**成对移动**；该签名没有固定绝对槽号。补费输入的花费仍须通过自身验证，交易其余签名也可能约束编排。[BIP143 的 SINGLE 与 ANYONECANPAY 配对示例](https://bips.dev/143/#example) · [nChain 关于手续费和找零的实例](https://patents.google.com/patent/US20250088370A1/en)

### 2. 约束其他输入引用的 outpoint

保留 `0x43` 或 `0x41`。花费者给出按实际顺序拼接的全部 outpoint 字节 `P`，脚本要求 `H(P) = hashPrevouts`。要检查槽 `j`，验证 `len(P)` 是 36 的倍数、`0 ≤ j < len(P)/36`，然后把从 `36j` 开始的 36 字节与规则要求的 outpoint 比较。指定位置时由规则给出 `j`；只要求存在时可由花费者给出 `j`。若语义要求**另一个**输入，还须排除当前 outpoint。预期引用应来自锁定条件、经验证的旧状态或可验证的派生关系；花费者同时自报目标和证据只能证明其选中的引用确实存在。

这个检查可用于未知最终交易模板：锁定时写下关系，花费时才补齐 `P`。固定宽度使脚本只需一次摘要和一个对齐切片，无须逐项执行 Script。证据长度及哈希工作仍随输入数增长。`ANYONECANPAY` 清空 `hashPrevouts`，在该模式下，外加一份输入列表不能支持这项保证。[BSV 的 GetPrevoutHash 和标志分支](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L1960-L1966) · [COutPoint 的线序结构](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/primitives/transaction.h#L51-L69)

### 3. 验证其他输入的金额

outpoint 在交易历史中唯一指定一笔父输出，父输出决定了金额；但把 outpoint 与 `hashPrevouts` 对上，只给脚本提供了引用。即使用 `ALL`，当前原像也只直接写入当前输入的金额。花费者自报的金额表、钱包查询结果或另一输入附带的一段签名，均不足以让当前脚本验证指定父输出的金额。[BSV 原像金额字段](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L2063-L2084)

有此硬性需求时，优先看规则能否放在该输入自己的既有锁定条件中，由它验证本输入金额，并用前述经绑定的 outpoint 关系保证它参与同一笔交易。对任意第三方 UTXO，若必须由当前脚本独立核对，则需要另一条证据链：先绑定目标 outpoint，再提供父交易的规范序列化，核对其双 SHA-256 与目标 txid（按线序比较），并证明从父交易的真实输出向量起点沿合法边界走到 `vout[n]`，读取该条目的金额。此处的 `n` 是 outpoint 内的父输出序号，与花费输入槽 `j` 分开。固定父交易模板可简化边界证明；任意父交易的长度、输入和前置输出均会增加验证成本。若事先已经在可信旧状态中绑定了**同一个** outpoint 和金额，可复用该事实。最小延续方案没有跨输入金额需求，故不要求这些材料。[BSV 对父交易标识的计算](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/primitives/transaction.cpp#L67-L81) · [父输出结构](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/primitives/transaction.h#L175-L194)

### 4. 限制所有变长输出

使用 `ALL`。若业务已唯一决定了整份有序输出清单，锁定脚本只需用独立确定的预期摘要比对 `hashOutputs`，或从既定模板和已核验的参数规范重建清单后计算摘要。不必解析原始交易。若规则是“由花费者选取若干输出，**每个**输出都满足谓词”，花费者须为每项给出金额和脚本。脚本逐项执行谓词，用真实脚本长度生成最短 CompactSize，从第一个金额字节开始顺序拼接各项 `E`，恰好用完全部记录，以 `H(E₀ || … || Eₘ₋₁) = hashOutputs` 封闭清单。由脚本固定可接受的最大项数并展开检查，超限就拒绝。核对完整覆盖时，把输出向量的计数前缀加进摘要同样会出错。[BSV 的 GetOutputsHash](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L1976-L1982) · [CompactSize 的规范编码](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/serialize.h#L296-L340)

**边界反例。** 某个真实输出的长脚本可以包含一段恰好形似“8 字节金额 + 长度 + 短脚本”的数据。`H(前缀 || 目标片段 || 后缀) = hashOutputs` 完全可以成立，而该片段仍位于脚本内部。字节串匹配、花费者画出的分段、长度合计正确，均不足以证明输出成员关系。上面的规范重建法从已知起点建立第一项边界，其编码决定下一项起点，最后又核对全串，因此可以逐项应用规则。只验证单个同索引输出时，`SINGLE` 已由节点给出该边界。

## 选型与最小方案

| 设计 | 适用规则 | 脚本和材料的代价 | 审阅要点 |
| --- | --- | --- | --- |
| 固定槽位 | 一个同索引后继；或布局已知的少数角色 | 同索引检查一个输出，与额外输入、输出的数量无关。固定 outpoint 槽仍要打开 `hashPrevouts` 才能核对该槽 | 固定角色可以与任意数量的外围项共存；变长输出中的任意第 j 项仍须证明起点 |
| 按需有界展开 | 至多 K 个受规则约束的项，每项谓词相同或由角色决定 | 模板预置最多 K 次检查或有限分支。花费者提交实际项数和各项字段；脚本规模随 K 增长 | 若谓词覆盖全部输出，实际记录必须连续、无遗漏并与 `ALL` 摘要一致；第 K+1 项应触发拒绝 |
| 全量承诺并验证 | 精确输出清单，或确实需要检查每一项 | 已知整表摘要时比较一次即可；开放清单要携带并验证全部有序记录，开销随总字节数增长 | 全量承诺和有界展开可以组合。单凭花费者自选的整表哈希无法证明逐项性质；无界通用谓词没有从该摘要直接推导的常数次验证 |

**推荐采用第一个方案。** 以“完整脚本相同、保留本输入金额、外部输入支付手续费”为最小研究模板，默认固定 `SINGLE|FORKID`；构造端编排真实的输入输出，验证端只绑定本输入原像、核对完整预期输出，并执行既定授权条件。只有出现明确的协作补费、指定共同输入或全局输出规则时，才分别选择 `ANYONECANPAY`、打开 `hashPrevouts`、或改用 `ALL` 与完整输出证据。是否需要全局上限，取决于合同对多少个对象作断言，不取决于交易本身可以有多少项。

## 离线验收用例

下表是后续验收的预期判定，未运行 PELS 实现。“通过”只指所列规则满足，前提是其他输入及常规交易验证也通过。改变已承诺字段后重建材料时，业务谓词仍应独立成立。

| 条件与变更 | 预期判定 |
| --- | --- |
| 合约位于输入 1，输出 0 为普通付款，输出 1 为原额同脚本，之后可有找零；用真实布局生成 0x43 材料 | 通过。把合约副本仅放到输出 0，或把输出 1 减少 1 聪，拒绝 |
| 两入一出，合约位于输入 1；其他条件均可满足 | 拒绝。该输入没有同索引输出，真实 `hashOutputs` 为 32 字节零 |
| 保持后继输出不变，在末尾增加补费输入；复用原来的本输入材料 | 0x43 的材料失配；明确允许 0xc3 的分支可通过。0xc3 下等同地移动整对输入输出也可通过；只移一侧使配对变错则拒绝 |
| 分支固定 0x43，花费者改用 0xc3 并连同原像类型重算候选签名 | 拒绝。类型本身是锁定条件 |
| 指定另一 outpoint 出现在槽 2，使用绑定的全表；尝试替换该槽、给出跨 36 字节边界的片段或指向当前输入 | 正确槽通过，其余拒绝。若只要求存在，可换到另一个合法槽并提供其新位置及真实全表 |
| 目标父交易输出 0、1 的金额不同，目标 outpoint 指向 1；分别提供真实的输出 1 金额、输出 0 金额、仅自报的金额 | 父交易标识、序号、边界和金额全部一致时通过；其余拒绝 |
| 全输出规则允许 1 至 K 项，给出 K 个合规输出；再增加一个输出，或让清单漏掉末项 | 完整 K 项通过；K+1 和漏项均拒绝。即使总项数合规，末项违反谓词也应拒绝 |
| 按序验证两个变长输出，脚本长分别为 252、253 字节 | 合规长度前缀分别为 `fc`、`fd fd 00`。非最短长度编码、截断、在脚本数据内部声称发现额外输出，均应拒绝 |
