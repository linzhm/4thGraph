# P2PKH-R1：支付给 P-256 公钥哈希

**状态**　首次征求意见草案　·　**类别**　Bitcoin Script 模板　·　**维护仓库**　linzhm/bsv-script-lab  
[English text](./p2pkh-r1-proposal.en.md) · [规范模板字节](./p2pkh-r1/template.hex)

## 摘要

P2PKH-R1 定义一种 BSV 锁定脚本模板。付款人把收款人的 P-256 公钥哈希写入输出。花费者揭示公钥，并用对应私钥对当前输入的交易摘要签署一次。本文规定如何生成和识别输出、如何构造解锁栈，以及如何验证不同钱包产生的字节是否兼容。

## 动机与适用范围

常规 P2PKH 让付款人只凭收款人的公钥哈希创建输出。BSV 原生签名检查使用 secp256k1，而 Apple Secure Enclave 等签名器提供 NIST P-256（secp256r1）。P2PKH-R1 保留按公钥哈希收款的方式，在 Script 中验证 P-256 签名，并用 Push TX 将授权绑定到节点实际验证的交易。收款方可以使用任何满足本文接口的 P-256 签名器，链上无需识别设备品牌。本草案定义输出模板和解锁约定；地址编码、收款请求传输、硬件证明以及后继输出延续规则均在范围之外。[BRC-16](https://github.com/bsv-blockchain/BRCs/blob/master/scripts/0016.md) · [BRC-21](https://github.com/bsv-blockchain/BRCs/blob/master/scripts/0021.md) · [Apple 签名接口](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey)

## 快速上手：花费一笔普通付款

假设钱包收到一笔 100,000 聪的 P2PKH-R1 输出，位于父交易的 `vout=0`。现在向一个普通 P2PKH 收款脚本付 99,000 聪，剩余 1,000 聪作为本例手续费，找零为零。这笔花费只有一个输入和一个输出。

1. 钱包取回**完整父交易**，准备收款输出并显示金额、找零和手续费。用户确认后，调用下面的接口。
2. 接口从父交易核对 outpoint、前序输出金额及所有者。它构造 BIP143 ALL（`0x41`）原像，将双 SHA-256 后的 32 字节摘要交给签名器。签名器只签一次，返回 64 字节大端 `r || s`。
3. 接口填入解锁栈的全部七项，验证子交易，返回完整签后交易。调用方可用 `signed.serialize()` 取得 wire 字节。有找零时应在签名前把找零输出一并放进 `outputs`；输入金额必须等于输出总额加已确认的费用。

```python
from checked_wallet import sign_payment
from tx_engine import TxOut

outputs = [TxOut(99_000, recipient_script)]
signed = sign_payment(parent, 0, outputs, 1_000, owner_public_key,
                      hardware_sign_digest, wallet_history_path)
```

`recipient_script` 来自收款请求，`owner_public_key` 是所花费旧输出对应的 65 字节 R1 公钥。`hardware_sign_digest` 是钱包与设备之间的摘要签名回调。`wallet_history_path` 指向钱包共用的持久化签名历史。本入口用于单输入普通付款；多输入或其他签名类型使用下文的逐输入接口。[钱包实现](../../research/secure-enclave-p256/checked_wallet.py)

**离线复现。** 从仓库根目录，在已安装 Python 3.12 和 `tx-engine==0.13.1` 的环境中运行：

```sh
python research/secure-enclave-p256/replay_payment.py
```

程序读取公开向量，只对该向量的固定摘要返回已记录的测试签名。它本地验证交易，并与发布的签后字节逐字节比对。预期输出为 `62b466ac14c69de5fb2ea8b743f4b7dfba63ac9af12588f844db2217ca03efa7  (60189 bytes)`。该交易引用合成的前序输出，金额和费用只作演示。BSV Node 1.2.3 的无对等连接 regtest 使用同一份前序数据验证输入 0。[完整父交易](./p2pkh-r1/spend-all/parent.hex) · [待签子交易、原像、摘要及签名](./p2pkh-r1/spend-all/vector.json) · [完整签后交易](./p2pkh-r1/spend-all/signed.hex) · [回放程序](../../research/secure-enclave-p256/replay_payment.py)

## 规范

本节的“必须”表示字节级互操作要求，“应”表示钱包的推荐行为。所有偏移均从原始脚本的第一个字节起算，起点为 0。十六进制字段按写出的字节顺序解释。

### 1. 从公钥创建输出

唯一的模板参数为 `ownerHash160`（20 字节）。输入公钥 Q 时，钱包必须验证它是 P-256 曲线上的有效非无穷远点，对恰好 65 字节的 `04 || x_BE32 || y_BE32` 计算 `RIPEMD160(SHA256(Q))`。若直接接受哈希，付款人应通过可信收款请求确认模板名与哈希。

1. 读取[规范模板字节](./p2pkh-r1/template.hex)，去掉 ASCII 空白并解码为 59,706 字节。此文件是下文向量 C 的完整脚本。
2. 用所有者哈希替换零起算的 `[332,352)`，其余字节按原序复制。结果就是原始 `scriptPubKey`。对相同公钥，任何钱包都应生成完全相同的字节。
3. 序列化交易输出时，写聪数的 8 字节小端整数、脚本长度 `fd 3a e9` 和原始程序。此时无需私钥、随机数、签名或待花费交易。

以下代码可在仓库 `research/secure-enclave-p256` 目录运行。示例公钥为公开测试点。生成与识别接口使用 Python、`cryptography` 及随仓库提供的模板文件。[开发者接口](../../research/secure-enclave-p256/p2pkh_r1.py)

```python
from hashlib import sha256
from p2pkh_r1 import locking_script_from_public_key, recognize

q = bytes.fromhex(
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)
raw = locking_script_from_public_key(q)
assert recognize(raw).hex() == "4ceab2c8be16c1d4c6b4147d39aa449c2d63f184"
assert sha256(raw).hexdigest() == "bef784e131b6095c604523f9b4d2d1a5af8b9eb548353f971bece7695631f9b3"
```

### 识别模板并提取公钥哈希

识别器输入为单个输出的原始脚本字节。对显示用的十六进制文本，应先解码。完整 R1 公钥在解锁栈第 3 项，锁内可以提取的是它的 HASH160。[机器可读布局](./p2pkh-r1/layout.json)

| 检查项 | 规则 |
| --- | --- |
| 长度与开头 | 恰好 **59,706 字节**，前十字节 `76 00 52 a5 69 6b 82 01 20 9d` |
| 所有者字段 | 对完整字节串用以下正则、`re.DOTALL` 和 `fullmatch`；命名组捕获偏移 332 起的 20 字节 |
| 固定部分 | 计算 `SHA256(raw[:332] + raw[352:])`。输入为按原序拼接的 **59,686 字节**，期望指纹为 `95bebb421328f7710133c35925231673e7f3f921b31203ce0f02fe1c6825e892` |

```python
rb"\x76\x00\x52\xa5\x69\x6b\x82\x01\x20\x9d.{322}(?P<owner_hash160>.{20}).{59354}"
```

只有三项均通过，才返回捕获的哈希。若要确认付给特定收款人，再与预期公钥哈希比较。固定指纹由 SDK 随规范固定。哈希计算可以连续更新两段字节，省去拼接缓冲区。向量中的整锁指纹则包含收款人哈希。

### 2. 构造交易授权

普通 P2PKH-R1 固定支持下列十二种签名类型。付款时只写收款人哈希；类型由花费钱包按输入选择。普通付款的签名界面宜默认选择 ALL，并在用户选择 NONE、SINGLE 或 ANYONECANPAY 时解释放开的字段。钱包的默认值不限制 UTXO 的后续花费。[常规 P2PKH 模板](https://github.com/bsv-blockchain/BRCs/blob/master/scripts/0016.md)

| 类型 | BIP143 | BIP143 + ANYONECANPAY | OTDA | OTDA + ANYONECANPAY |
| --- | --- | --- | --- | --- |
| ALL | `41` | `c1` | `61` | `e1` |
| NONE | `42` | `c2` | `62` | `e2` |
| SINGLE | `43` | `c3` | `63` | `e3` |

表中各值都含 ForkID 位 `40`。在启用 Chronicle 规则的节点上，额外的 `20` 位选择 OTDA。以下将不含该位的类型称为 BIP143 路径。混用发生在各输入的签名中，交易自身的 `nVersion` 另行序列化。[Chronicle 规范](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release) · [节点摘要算法](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L1894-L2124)

| 当前输入的情形 | 钱包必须构造的原像 P | 分支值 |
| --- | --- | --- |
| BIP143，含无配对 SINGLE | 按请求类型作 ForkID 序列化，`scriptCode = 68 ac`。原像 159 字节 | 0 |
| OTDA ALL、NONE 或有配对 SINGLE | 按请求类型作 OTDA 序列化，当前输入的 `scriptCode = 68 ac`。原像随交易变化 | 0 |
| OTDA SINGLE 且当前输入索引 ≥ 输出数 | 保留请求类型 `63/e3` 的原生检查。构造伴随 BIP143 原像，类型分别为 `43/c3`，`scriptCode = 63 ad 67 ab 68 ac`，`hashOutputs` 为 32 个零字节。原像 163 字节 | 1 |

这里列出的 `scriptCode` 是实际执行相应 `OP_CODESEPARATOR` 后的原始脚本后缀，序列化时须按算法编码长度。原像末尾包含该原像实际使用的四字节小端签名类型。钱包必须用真实父交易取得当前 outpoint 指向的输出，核对模板和所有者，BIP143 路径必须使用该输出的金额。手机对 `SHA256(SHA256(P))` 签一次 ECDSA P-256。摘要签名接口的输入为 32 字节；使用会再次哈希输入的消息签名接口将得到不同结果。[原像与路径参考](../../research/secure-enclave-p256/universal.py)

**输出覆盖范围。** ALL 承诺全部序列化输出的顺序、金额及脚本。NONE 允许更换全部输出。有配对 SINGLE 承诺当前输入同索引的输出。BIP143 无配对 SINGLE 将 `hashOutputs` 置零，仍有当前输入专属的摘要。OTDA 无配对 SINGLE 由节点直接返回 `uint256(1)`；本模板的分支 1 用伴随摘要取得持有人对当前输入的授权。两条路径都只需一次持有人签名。

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

三个向量均为 59,706 字节，对原始脚本做一次 SHA-256。哈希输入不含金额、长度前缀或 hex 文件的换行。

| 向量 | ownerHash160 | 整锁 SHA-256 |
| --- | --- | --- |
| A | `000102030405060708090a0b0c0d0e0f10111213` | `4047136fffb756ffe667bd5329f3990f16acc876649d33bb96c387820717e72f` |
| B | `1111111111111111111111111111111111111111` | `9832bb1a757075188281c4f21f4666c95cb574821f1741914adcbe3f5538d951` |
| C | `4ceab2c8be16c1d4c6b4147d39aa449c2d63f184` | `bef784e131b6095c604523f9b4d2d1a5af8b9eb548353f971bece7695631f9b3` |

实现应复现三个向量并能读回所有者哈希。改变任一固定字节、截短或追加内容均应识别失败。花费验收应覆盖全部十二种类型、混用输入和两种无配对 SINGLE 路径。[识别用例](../../research/secure-enclave-p256/test_generate_lock.py) · [节点用例](../../research/secure-enclave-p256/test_universal.py)

## 参考实现与验证状态

参考程序直接以 Bitcoin Script 汇编定义，装配器展开命名块及固定次数的重复。四位窗口是参考实现进行 P-256 验签的方式。钱包可直接按第 1 节实例化规范模板。以下命令在仓库的 `research/secure-enclave-p256` 目录下运行，使用 Python 3.12 和 `tx-engine==0.13.1`。[生成器](../../research/secure-enclave-p256/generate_lock.py) · [四位窗口汇编](../../research/secure-enclave-p256/window-4.asm)

```sh
python generate_lock.py --owner-hash160 000102030405060708090a0b0c0d0e0f10111213 --format raw > scriptPubKey.bin
sha256sum scriptPubKey.bin
```

已有离线验收覆盖全部十二种类型、同笔交易混用及无配对路径。参考装配器与钱包字节接口复现了上述三个向量。本次通过 53 项 Python/chain-gang 测试、8 项离线 BSV Node 1.2.3 测试和 2 项 nChain 对照。[验收记录](https://github.com/linzhm/bsv-script-lab/actions/runs/44364686046/job/135015159182) · [nChain PUSHTX 参考实现](https://github.com/nchain-innovation/zkscript_package/blob/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4/src/zkscript/transaction_introspection/transaction_introspection.py)

## 安全与部署考虑

收款锁只公开所有者哈希，花费公开公钥、签名及可由 s 计算的逆元。私钥和 ECDSA nonce k 必须留在签名器内。同钥在不同摘要上复用 k 可能泄露私钥。参考钱包在释放签名之前观察同一公钥的 r 与摘要，检测到冲突时阻断。该机制只覆盖共享完整历史的签名调用。设备来源证明属于钱包与签名器之间的信任问题。[ECDSA 规范](https://doi.org/10.6028/NIST.FIPS.186-5) · [钱包实现](../../research/secure-enclave-p256/checked_wallet.py)

每笔此类输出携带约 60 KB 程序，花费还必须携带完整父交易，连续花费会把更早的解锁数据带入下一笔父交易。钱包应按实际序列化长度评估费用，并确认目标节点或服务的接收限制。

## 开发顺序与验收条件

当前已有公钥到锁的确定性接口、模板识别接口、收款向量 A/B/C，普通 BIP143 ALL 完整花费向量，以及在原生节点上执行的花费测试。建议先让另一个钱包只凭规范完成一次离线花费。下列事项按依赖排列，均为尚待交付的工作。

| 阶段 | 交付物 | 完成条件 |
| --- | --- | --- |
| 1. 扩充固定花费向量 | 以已发布的普通 BIP143 ALL 向量为基准，为其他路径提供可直接读取的父交易、待签子交易、输入索引、真实前序金额、请求类型、实际原像类型、`scriptCode`、原像、32 字节摘要、公开测试签名、完整解锁和节点预期结果。大段交易字节可放在按哈希引用的文件中。 | 至少覆盖普通 BIP143 ALL、普通 OTDA ALL、有配对 SINGLE、两种无配对 SINGLE 和两输入混用 NONE/ALL。逐项比对序列化字节，给出节点版本和脚本标志；区分整笔交易有效性与指定输入的脚本验证。 |
| 2. 独立钱包复现 | 另一套 SDK 只使用本文、规范模板和固定向量，独立构造原像、识别收款人哈希并组装解锁栈。 | 复现 A/B/C 及阶段 1 的摘要；使用向量内签名时应复现解锁字节。让离线节点验证普通和伴随路径，记录任何需要查阅参考源码才能解决的歧义并回补规范。 |
| 3. 真实签名器 | 接入 Secure Enclave 的公钥导出、摘要签名和签名格式转换，记录设备、系统版本及所选 API。可与阶段 2 并行。 | 普通及伴随路径分别只调用一次签名，验证设备实际返回的签名并通过离线节点检查。单独检查用户取消时不返回解锁脚本。真机验收比较签名的有效性，ECDSA 不要求重签得到相同字节。 |
| 4. 成本与可用性 | 测量一次收款、一次花费、连续两次花费时的锁、父交易、解锁和整笔交易字节数，分别记录本地脚本验证与目标服务接收策略的证据。 | 记录费率和适用条件，按实际交易大小估费；说明钱包怎样保留或重新获取完整父交易，并在资料缺失时给出可恢复的错误。 |
| 5. 独立安全审查 | 审查持有人授权、原像绑定、无配对分支、P-256 运算、可变字段的签名前展示。 | 交付逐项结论、所用实现提交、剩余假设及需要复验的事项。对任何修订重新运行字节向量与节点用例。 |

**建议的简化。** 付款端只处理“公钥 → 锁”，索引器只处理“锁 → 所有者哈希”。花费端由钱包根据真实交易及用户选定的类型推导分支、位置和逆元，硬件签名器只接收一个已确认的 32 字节摘要。调用方无需自行选择伴随路径。三者可以独立测试。保留这一接口时，普通付款只需传一个公钥，复杂性集中在确实需要它的花费路径。

体积优化应按完整花费核算。采用参考构造器的最短数据推送时，普通 BIP143 解锁脚本长度为 `push(父交易) 的字节数 + 331`，无配对 OTDA 为 `push(父交易) 的字节数 + 335`。差异来自 159 和 163 字节的原像。这两个公式均只计解锁脚本本身。下一轮若考虑把更多运算移到解锁侧，先用阶段 4 的样例报告锁、解锁和连续花费的合计变化，再决定是否值得定义另一种字节模板。[解锁构造](../../research/secure-enclave-p256/universal.py)

本草案借鉴 BRC 的脚本模板提案结构，尚未分配 BRC 编号。[BRC 提案格式](https://github.com/bsv-blockchain/BRCs/blob/master/EXAMPLE.md) · [Wei Zhang，WP1605《PUSHTX and its Building Blocks》（出版方原址）](https://nchain.com/wp-content/uploads/2022/03/WP1605_PUSHTX-and-its-Building-Blocks.pdf)
