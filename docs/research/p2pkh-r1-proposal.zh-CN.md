# P2PKH-R1：支付给 P-256 公钥哈希

**状态**　首次征求意见草案　·　**类别**　Bitcoin Script 模板　·　**维护仓库**　linzhm/bsv-script-lab  
[English text](./p2pkh-r1-proposal.en.md) · [规范模板字节](./p2pkh-r1/template.hex)

## 摘要

P2PKH-R1 定义一种 BSV 锁定脚本模板。付款人把收款人的 P-256 公钥哈希和允许的交易签名类型写入输出。花费者揭示公钥，并用对应私钥对当前输入的交易摘要签署一次。本文规定如何生成和识别输出、如何构造解锁栈，以及如何验证不同钱包产生的字节是否兼容。

## 动机与适用范围

常规 P2PKH 让付款人只凭收款人的公钥哈希创建输出。BSV 原生签名检查使用 secp256k1，而 Apple Secure Enclave 等签名器提供 NIST P-256（secp256r1）。P2PKH-R1 保留按公钥哈希收款的方式，在 Script 中验证 P-256 签名，并用 Push TX 将授权绑定到节点实际验证的交易。收款方可以使用任何满足本文接口的 P-256 签名器，链上无需识别设备品牌。本草案定义输出模板和解锁约定；地址编码、收款请求传输、硬件证明以及后继输出延续规则均在范围之外。[BRC-16](https://github.com/bsv-blockchain/BRCs/blob/master/scripts/0016.md) · [BRC-21](https://github.com/bsv-blockchain/BRCs/blob/master/scripts/0021.md) · [Apple 签名接口](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey)

## 规范

本节的“必须”表示字节级互操作要求，“应”表示钱包的推荐行为。所有偏移均从原始脚本的第一个字节起算，起点为 0。十六进制字段按写出的字节顺序解释。

### 1. 创建和识别输出

收款参数为 `ownerHash160`（20 字节）及 `allowedTypes`（下表类型的非空子集）。若收款人提供公钥 Q，钱包必须验证它是 P-256 上的有效非无穷远点，并对恰好 65 字节的 `04 || x_BE32 || y_BE32` 计算 `RIPEMD160(SHA256(Q))`。若直接接受哈希，付款人应通过可信收款请求确认模板名、哈希和许可集合。普通付款推荐 `{41,61}`，使持有人可在两种算法下对全部输出签名。

1. 读取[规范模板字节](./p2pkh-r1/template.hex)，去掉 ASCII 空白并按十六进制解码。所得 59,811 字节为下文向量 A 的完整程序。
2. 将 `[437,457)` 的 20 字节换为 `ownerHash160`。对下表中每一种类型，允许时在其偏移写 `51`（`OP_1`），否则写 `00`（`OP_0`）。十二个偏移各占一字节。
3. 结果即原始 `scriptPubKey`，其余字节必须与规范模板逐字节相同。序列化交易输出时依次写聪数的 8 字节小端整数、脚本长度 `fd a3 e9`、原始程序。
4. 识别器必须检查完整长度、全部固定字节、十二个许可值及集合非空，再返回模板名、所有者哈希及许可集合。字节正则可以实现这项检查。输入是已解析出的单个输出脚本。辅助验签公钥是固定程序的一部分；此模板的所有者公钥在解锁时提供。

| 类型 | ForkID / 偏移 | ForkID + ANYONECANPAY / 偏移 | OTDA / 偏移 | OTDA + ANYONECANPAY / 偏移 |
| --- | --- | --- | --- | --- |
| ALL | `41` / 307 | `c1` / 316 | `61` / 366 | `e1` / 376 |
| NONE | `42` / 326 | `c2` / 336 | `62` / 386 | `e2` / 396 |
| SINGLE | `43` / 346 | `c3` / 356 | `63` / 406 | `e3` / 416 |

### 2. 构造交易授权

签名类型按输入选择，必须属于该输出的许可集合。表中各值都含 ForkID 位 `40`。在启用 Chronicle 规则的节点上，额外的 `20` 位选择 OTDA。以下将不含该位的类型称为 BIP143 路径。混用发生在各输入的签名中，交易自身的 `nVersion` 另行序列化。[Chronicle 规范](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release) · [节点摘要算法](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L1894-L2124)

| 当前输入的情形 | 钱包必须构造的原像 P | 分支值 |
| --- | --- | --- |
| BIP143，含无配对 SINGLE | 按请求类型作 ForkID 序列化，`scriptCode = 68 ac`。原像 159 字节 | 0 |
| OTDA ALL、NONE 或有配对 SINGLE | 按请求类型作 OTDA 序列化，当前输入的 `scriptCode = 68 ac`。原像随交易变化 | 0 |
| OTDA SINGLE 且当前输入索引 ≥ 输出数 | 保留请求类型 `63/e3` 的原生检查。构造伴随 BIP143 原像，类型分别为 `43/c3`，`scriptCode = 63 ad 67 ab 68 ac`，`hashOutputs` 为 32 个零字节。原像 163 字节 | 1 |

这里列出的 `scriptCode` 是实际执行相应 `OP_CODESEPARATOR` 后的原始脚本后缀，序列化时须按算法编码长度。原像末尾包含该原像实际使用的四字节小端签名类型。钱包必须用真实父交易取得当前 outpoint 指向的输出，核对所有者与权限，BIP143 路径必须使用该输出的金额。手机对 `SHA256(SHA256(P))` 签一次 ECDSA P-256。摘要签名接口的输入为 32 字节；使用会再次哈希输入的消息签名接口将得到不同结果。[原像与路径参考](../../research/secure-enclave-p256/universal.py)

**输出覆盖范围。** ALL 承诺全部序列化输出的顺序、金额及脚本。NONE 允许更换全部输出。有配对 SINGLE 承诺当前输入同索引的输出。BIP143 无配对 SINGLE 将 `hashOutputs` 置零，仍有当前输入专属的摘要。OTDA 无配对 SINGLE 由节点直接返回 `uint256(1)`；本模板的分支 1 用伴随摘要取得持有人对当前输入的授权。请求类型的许可独立于伴随类型。两条路径都只需一次持有人签名。

**输入覆盖范围。** BIP143 的 `hashPrevouts` 承诺顺序排列的全部 outpoint，ANYONECANPAY 将其置零。当前 outpoint、金额和 sequence 仍直接写入原像。完整 `hashSequence` 仅用于不带 ANYONECANPAY 的 ALL。OTDA 使用按签名类型变换后的交易序列化，没有这些独立的哈希字段或前序输出金额字段。钱包核算费用时应取得所有相关前序输出。例如，输入 A 用 NONE 并依赖 B 的 ALL 来决定收款输出，A 应核对 B 的 outpoint 并关闭 ANYONECANPAY；否则 A 的授权允许省略 B。[节点序列化规则](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L1894-L2124)

### 3. 构造与验证解锁脚本

花费者必须按下表顺序推入六个字节串，再推入分支操作码。父交易为当前 outpoint 引用的完整直接父交易。P-256 群阶记为 n。[P-256 参数](https://doi.org/10.6028/NIST.SP.800-186)

| 顺序（栈底至栈顶） | 编码 |
| --- | --- |
| 1 | 父交易的完整 wire 序列化 |
| 2 | 上节所选原像 P |
| 3 | 65 字节公钥 Q，包含 `04` 前缀 |
| 4 | 64 字节 `r_BE32 || s_BE32`，满足 `1 ≤ r,s < n`。不附加类型字节，DER 签名须先转换 |
| 5 | 4 字节小端无符号整数。普通 OTDA 且不带 ANYONECANPAY 时为实际输入索引，其余为零 |
| 6 | 32 字节小端无符号整数 `w = s⁻¹ mod n` |
| 7 | 普通路径 `OP_0`，伴随路径 `OP_1` |

锁验证 Q 的哈希、曲线点和签名标量，验证 `1 ≤ w < n` 及 `s·w mod n = 1`，并检查标准 ECDSA 验签等式。它还检查父交易哈希与原像中当前 outpoint 的 txid 一致，用原生 `OP_CHECKSIG` 把所提供的材料绑定到实际交易。普通 OTDA 路径按输入数量和位置提示定位当前输入，并核对脚本标记。没有按输入输出数量执行的 Script 循环。钱包应从原始交易独立推导上述材料，并在签名前向用户展示金额、费用和签名允许改变的字段。[验签汇编](../../research/secure-enclave-p256/payment.asm) · [交易绑定汇编](../../research/secure-enclave-p256/universal.asm)

## 互操作向量

以下 SHA-256 对原始锁定脚本只哈希一次。两个输出长度均为 59,811 字节，哈希输入不含金额、CompactSize 长度或十六进制文本中的换行。测试用所有者哈希仅用于比对字节。

| 向量 | ownerHash160（十六进制） | allowedTypes | 原始脚本 SHA-256 |
| --- | --- | --- | --- |
| A | `000102030405060708090a0b0c0d0e0f10111213` | `41,61` | `6ac6c4dbbf77bb0a73cf2136338c5d81a3c2674f71929f9c2dd196064be6b952` |
| B | 字节 `11` 重复 20 次 | `42,e3` | `92599b5ff408dbbeb92241bc89e7ce932bdddfd318907c8099db5ba348ef8d52` |

实现应对两个向量均能先生成、再识别并读回精确参数。识别器应拒绝全部许可关闭、固定指令改变、截短或追加字节的脚本。花费验收应覆盖同一个 UTXO 上两种摘要算法、NONE、有配对与无配对 SINGLE、错误父交易和错误求逆值。[识别用例](../../research/secure-enclave-p256/test_lock_identity.py) · [原生节点用例](../../research/secure-enclave-p256/test_universal.py)

## 参考实现与验证状态

参考程序直接以 Bitcoin Script 汇编定义，装配器展开命名块及固定次数的重复。四位窗口是参考实现进行 P-256 验签的方式。钱包可直接按第 1 节实例化规范模板。以下命令在仓库的 `research/secure-enclave-p256` 目录下运行，使用 Python 3.12 和 `tx-engine==0.13.1`。[生成器](../../research/secure-enclave-p256/generate_lock.py) · [四位窗口汇编](../../research/secure-enclave-p256/window-4.asm)

```sh
python generate_lock.py --owner-hash160 000102030405060708090a0b0c0d0e0f10111213 --allow 41,61 --format raw > scriptPubKey.bin
sha256sum scriptPubKey.bin
```

已有离线验收覆盖全部十二种类型、同笔交易混用及无配对路径。参考实现的既有运行通过 52 项 Python/chain-gang 测试、8 项 BSV Node 1.2.3 测试和 2 项 nChain 对照。该运行的输出字节与向量 A 的指纹一致。[验收记录](https://github.com/linzhm/bsv-script-lab/actions/runs/44356580922/job/134986197432) · [nChain PUSHTX 参考实现](https://github.com/nchain-innovation/zkscript_package/blob/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4/src/zkscript/transaction_introspection/transaction_introspection.py)

## 安全与部署考虑

收款锁只公开所有者哈希，花费公开公钥、签名及可由 s 计算的逆元。私钥和 ECDSA nonce k 必须留在签名器内。同钥在不同摘要上复用 k 可能泄露私钥。参考钱包在释放签名之前观察同一公钥的 r 与摘要，检测到冲突时阻断。该机制只覆盖共享完整历史的签名调用。设备来源证明属于钱包与签名器之间的信任问题。[ECDSA 规范](https://doi.org/10.6028/NIST.FIPS.186-5) · [钱包实现](../../research/secure-enclave-p256/checked_wallet.py)

每笔此类输出携带约 60 KB 程序，花费还必须携带完整父交易，连续花费会把更早的解锁数据带入下一笔父交易。钱包应按实际序列化长度评估费用，并确认目标节点或服务的接收限制。

## 尚待完成

| 工作 | 可验收结果 |
| --- | --- |
| 独立实现与可移植的花费向量 | 发布包含父交易、子交易、原像、摘要、签名和预期结果的固定数据；由第二个钱包实现复现普通及伴随路径 |
| 设备联调 | 在真实 Secure Enclave 上完成摘要签名，将设备输出转换为规定的 64 字节格式，离线节点验证完整花费 |
| 部署评估与独立审查 | 记录代表性交易大小、费用和接收策略；完成对原像绑定、分支隔离、曲线运算及钱包签名前展示的独立审查 |

本草案借鉴 BRC 的脚本模板提案结构，尚未分配 BRC 编号。[BRC 提案格式](https://github.com/bsv-blockchain/BRCs/blob/master/EXAMPLE.md) · [Wei Zhang，WP1605《PUSHTX and its Building Blocks》（出版方原址）](https://nchain.com/wp-content/uploads/2022/03/WP1605_PUSHTX-and-its-Building-Blocks.pdf)
