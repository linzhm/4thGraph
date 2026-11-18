# P2PKH-R1 付款锁

当前付款模板在 ForkID ALL 下只需 326 字节解锁数据。使用 `generate_lock.py` 生成新输出，使用 `checked_wallet.sign_payment` 花费。规范、字节向量与验收结果见[中文 RFC](../../docs/research/p2pkh-r1-proposal.zh-CN.md) 或 [English RFC](../../docs/research/p2pkh-r1-proposal.en.md)。

## 早期研究记录

**v7 通用锁**可从同一个 UTXO 选择 BIP143 或 OTDA。显式传入 `version=7`，用 `universal.authorization` 构造花费时应签的摘要。本文后续的四项解锁、固定 158 字节和标签签名描述 v2–v4。[通用锁接口、无配对 SINGLE、原生测试及字节对照](../../docs/research/p2pkh-r1-universal.md)

这个研究模板实现普通持有人付款。付款人把收款人的 P-256 公钥哈希写入锁定脚本。收款人可签署带多个输入、多个收款输出及找零的交易；新输出可使用其他锁定脚本。默认签名类型是 `ALL|FORKID`（0x41）。[手写 Bitcoin Script](./payment.asm) · [Python 装配入口](./handwritten.py) · [交易测试](./test_handwritten.py)

**实测大小是主要取舍。** 默认 v2 锁定脚本为 **88,188 字节**，v1 为 214,973 字节。BSV 节点的原生 `CHECKSIG` 使用 secp256k1，Secure Enclave 使用 NIST P-256（secp256r1）。本模板把 P-256 验签展开为 BSV 整数运算，用原生 `CHECKSIG` 绑定当前交易。标准 P2PKH 的所有者模型得以保留，但不能沿用其 25 字节脚本或标准地址编码。此大小是本参考实现的测量值，并非 P-256 验签的理论下限。[BSV 节点 CPubKey::Verify](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/pubkey.cpp#L183-L214) · [Apple SecureEnclave.P256.Signing.PrivateKey](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey)

## 钱包识别与替换 P2PKH-R1

本仓库用 `P2PKH-R1` 指“支付给 P-256 公钥哈希”的手写模板。该名称是钱包的本地分类。输入识别器的字节是单个输出的完整 `scriptPubKey`，已去掉输出金额和脚本长度。返回值给出模板版本、所有者的 20 字节哈希、允许的全部签名类型。完整公钥由花费者在解锁栈中提供。

v2 的前 24 字节为 `78 a9 14 <ownerHash160 的 20 字节> 88`，对应 `OP_OVER OP_HASH160 PUSH20 <hash> OP_EQUALVERIFY`。无论哈希中是否出现换行、空字节或操作码字节，原始脚本的半开区间 `[3,23)` 都是同一个字段。钱包用短前缀筛选候选，用固定长度二进制正则完整匹配模板头部，要求六个许可位分别为 `OP_0` 或 `OP_1` 且至少一位开启，并逐字节比较其余固定程序。更改末尾的验签指令、追加操作码或采用其他推送编码都会使识别失败。v1 使用原有字节布局和单独的匹配模板。[识别与装配](./handwritten.py) · [v1 固定汇编](./payment-v1.asm)

```python
from handwritten import match_locking_script, replace_owner_hash160

lock = match_locking_script(script_pubkey_bytes)
if lock is not None:
    print(lock.version, lock.owner_hash160.hex(), lock.allowed_types)
    new_output_script = replace_owner_hash160(script_pubkey_bytes, next_owner_hash160)
```

替换函数返回一份可用于**新输出**的原始锁定脚本，版本和签名权限沿用原值。已有 UTXO 的控制权仍由它创建时的那份脚本决定。若用十六进制文本建立索引，可先检查 v2 的长度和开头 `78a914`，解码后再调用完整识别器。

### 从原始锁定脚本识别付款类型

钱包或索引器可将单个输出的原始 `scriptPubKey` 字节交给 `identify_locking_script`。十六进制输入先用 `bytes.fromhex` 解码，交易序列化中脚本前面的 CompactSize 长度由交易解析器去除。匹配结果区分脚本类型、曲线和所有者字段。[识别器](./lock_identity.py) · [验收](./test_lock_identity.py)

| 识别类型 | 所有者字段 | 提取规则 |
| --- | --- | --- |
| P2PK | `owner_public_key` | 全脚本匹配规范的直接推送及尾部 CHECKSIG，并在 secp256k1 上验证 SEC1 公钥 |
| P2PKH | `owner_hash160` | 全脚本匹配 `76 a9 14 <20字节> 88 ac` |
| P2PKH-R1 | `owner_hash160` | 逐版本匹配完整模板，包括固定后缀；同时返回 `template_version` 与 `allowed_types` |

v7 的快速筛选条件为**长度 59,811 字节**且开头为 `76 00 52 a5 69 6b 82 01 20 9d`。这十个字节是已有操作码。输出类型应以完整匹配结果为准。正则按二进制运行并用 `fullmatch` 锚定边界，例如 P2PKH 使用 `rb"\x76\xa9\x14(?P<owner_hash160>.{20})\x88\xac"` 并启用 `re.DOTALL`。R1 的正则从汇编槽位生成，固定尾部直接比较字节。

```python
from lock_identity import identify_locking_script, matches_owner_key

lock = identify_locking_script(script_pubkey_bytes)
if lock is not None:
    print(lock.script_type, lock.template_version, lock.owner_hash160, lock.owner_public_key)
    # candidate_pubkey 是从钱包或已解析的解锁数据另外取得的公钥。
    is_owner = matches_owner_key(lock, candidate_pubkey)
```

R1 锁中 PUSHTX 的固定公钥属于验证程序。只有模板声明的所有者槽位参与提取。接口只返回公开字段，不扫描、提取或记录私钥；单独的私钥标量、公钥字节串或未知脚本作为锁定脚本输入均返回 `None`。公钥是否为业务上的一次性钥匙需要钱包元数据；曲线点编码本身不包含该角色。识别脚本类型也不证明提交者控制相应钥匙。

## 两种窗口候选与计时

显式选择 `locking_script(owner_hash160, version=3)` 使用 2 位联合表，选择 `version=4` 使用 4 位分表。两个版本都沿用 4 项解锁、相同的消息标签、6 种可配置的 ForkID 类型及完整模板识别。原有调用默认产生 v2。[2 位联合表](./window-2.asm) · [4 位分表](./window-4.asm)

v3 在脚本中建立 16 个点的联合表，随后执行 128 轮。v4 读取 16 个固定基点倍数、建立 16 个公钥倍数，随后执行 64 轮。两个主循环都做 256 次倍点和 128 次点加。前者每轮取一个表项，后者每轮取两个。

计时调用 chain-gang 0.13.1 的 `Tx.validate(parents)`，每个模板实际执行 1,000,000 次单输入交易验证。两组各轮换八笔离线签署的固定交易，每笔计时执行 125,000 次。20 个分片在各自的同一台机器上交替运行两组，各组每个分片预热 32 次，再计时 50 批，每批 1,000 次。签名、装配及预热在计时区间外。汇总校验交易标识、提交、计数和分片完整性。累计秒数是所有分片的单线程计时之和。带 `[bench-1m]` 标记的本研究分支推送才会启动长基准。[计时程序](./benchmark_windows.py) · [工作流](../../.github/workflows/p256-script.yml)

## 压缩如何取得

v2 在 256 轮双标量乘法里单独计算点倍加，使用适用于 P-256 的射影坐标公式，并显式处理无穷远点。通用点加把模约简推迟到三个结果坐标，单次运算的中间整数控制在 2,048 位以内。群阶和曲线常数在栈上复用，标量求逆按固定指数展开。以上改动都在锁定脚本内部；一次解锁仍只推入父交易、原像、公钥和签名。本文报告本仓库两个已知布局的长度，全局最小长度尚未得到证明。[倍点公式 dbl-2007-bl-2](https://hyperelliptic.org/EFD/g1p/auto-shortw-projective-3.html#doubling-dbl-2007-bl-2) · [手写汇编](./payment.asm)

## 锁定参数与解锁栈

`locking_script(owner_hash160, allowed_types=(0x41,))` 返回 chain-gang 的 `Script`；`.raw_serialize()` 给出可写入输出的操作码字节。所有者标识为 `RIPEMD160(SHA256(Q))`，对完整的 65 字节非压缩 X9.63 公钥求哈希，含开头的 `04`。同一公钥采用另一种编码会产生不同哈希。付款时应确切约定模板和允许的类型。普通付款只需默认值。[Apple 公钥编码](https://developer.apple.com/documentation/cryptokit/p256/signing/publickey/x963representation)

`unlocking_script(parent, preimage, pubkey, signature)` 接收四段原始 bytes，返回四次压栈组成的解锁脚本。顺序从栈底到栈顶：

| 栈项 | 格式及用途 |
| --- | --- |
| `parentTx` | 当前输入直接引用的完整父交易，使用 BSV 的线序原始字节。用双 SHA-256 对照实际 outpoint 的 txid 部分。 |
| `P` | 本输入的 ForkID 原像，固定 158 字节。由钱包从当前花费交易、该输入的位置和真实前序输出金额构造。 |
| `Q` | Secure Enclave 公钥，`04 || BE32(x) || BE32(y)`。验证所有者哈希、坐标范围及 P-256 曲线方程。 |
| `sig` | 64 字节 `BE32(r) || BE32(s)`。使用 CryptoKit 的 `rawRepresentation`。接受标准 ECDSA 的两个合法 s 表示，不能依赖该签名为交易提供唯一 txid。 |

这里的“前序交易”取当前输入直接引用的那一笔。验证整笔父交易的哈希即可证明提交材料的身份，原像已绑定当前 vout 序号和节点提供的金额。脚本无需切出父交易中的变长输出，也没有从父交易中读取其他 UTXO 金额。若连续用这种模板再付款，新交易携带的父交易原文也包含上一轮的解锁数据，费用预算应计入这部分累积字节。

## 脚本怎样执行

`payment.asm` 是付款锁的源文件。`LOCK` 给出执行顺序，`ADD_POINTS` 写明有限域运算与栈槽，`SCALAR_STEP` 写明每个标量位的处理。`@` 引用命名操作码块或常量，`repeat` 在装配时复制固定次数。Python 直接连接这些指令，`tx-engine` 负责操作码编码和 Rust 执行。下图按功能概括源码。

```text
scriptSig     <parentTx> <P> <Q> <r||s>
scriptPubKey  [检查栈深、字段宽度、HASH160(Q) == ownerHash160]
              [HASH256(parentTx) == P[68..100)]
              [P 的 scriptCode 与类型编码正确；类型在锁定时写入的允许列表内]
              [验证 P-256 签名，消息摘要为 SHA256(tag || P)]
              [从 HASH256(P) 在栈内构造固定公开参数的 secp256k1 签名，附上选定类型]
              <secp256k1 的压缩生成元公钥> OP_CODESEPARATOR OP_CHECKSIG
```

最后一条 `OP_CHECKSIG` 由节点针对真实的花费交易及正在执行的输入计算摘要，只签最后一个已执行 `OP_CODESEPARATOR` 后的一字节 `ac`。所以原像中的序列化 `scriptCode` 恒为 `01 ac`，无需为此再在原像中携带整段 P-256 验证程序。完整锁定脚本已处于由 outpoint 标识的父输出中。PUSHTX 使用的公开参数只负责当前交易绑定，花费授权来自前面的 Secure Enclave 公钥签名。[节点处理 OP_CODESEPARATOR 和 CHECKSIG](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L1445-L1488) · [WP1605 原文核对与页码](../../docs/research/pels-transaction-bounds.md)

| P 中字节范围（半开区间） | 字段 |
| --- | --- |
| [0,4)、[4,36)、[36,68) | nVersion、hashPrevouts、hashSequence |
| [68,100)、[100,104) | 当前 outpoint 的父 txid（原始摘要字节）、父输出序号 LE32 |
| [104,106)、[106,114)、[114,118) | 固定 `01 ac`、当前输入金额 LE64、当前 nSequence |
| [118,150)、[150,154)、[154,158) | hashOutputs、nLockTime、签名类型 LE32 |

`Q`、`r`、`s` 和摘要均按无符号大端解码。脚本逐项验证 `1 ≤ r,s < n`，计算 `R = (z/s)G + (r/s)Q`（标量运算模群阶 n），要求 R 有限且横坐标模 n 为 r。点加采用完整射影公式，标量运算固定展开 256 轮，展开次数与交易输入、输出数量无关。[NIST FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final) · [NIST 的 P-256 参数](https://csrc.nist.gov/pubs/sp/800/186/final) · [Renes–Costello–Batina 点加公式](https://hyperelliptic.org/EFD/g1p/auto-shortw-projective-3.html#addition-add-2015-rcb)

## Secure Enclave 签名接口

钱包先核对拟支付的输出、金额、找零及所选签名类型，从同一笔交易生成 P。标签固定为 ASCII `BSV/SecureEnclave/P256/v1` 后跟一个零字节。下面的 `digest` 是 CryptoKit 的 `SHA256.Digest`，会选中直接签摘要的重载。若已有消息签名接口，也可直接把同一份 `message` 交给 SHA-256 消息重载；将摘要转成 Data 再交给消息重载会多哈希一次。[Apple 签名重载说明](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey.md)

```swift
import CryptoKit
import Foundation

func signSpend(preimage: Data, key: SecureEnclave.P256.Signing.PrivateKey) throws
    -> (publicKey: Data, signature: Data) {
    let tag = Data("BSV/SecureEnclave/P256/v1\0".utf8)
    let message = tag + preimage
    let digest = SHA256.hash(data: message)
    let signature = try key.signature(for: digest)
    return (key.publicKey.x963Representation, signature.rawRepresentation)
}
```

节点验证指定公钥对这次花费的授权。私钥生成在 Secure Enclave 内属于钱包建钥和访问控制属性；链上仅凭 ECDSA 签名无法证明设备来源、生物识别是否发生，或用户实际看过哪些交易字段。[Apple Secure Enclave 建钥和签名 API](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey)

## 可用签名类型

| 锁允许的类型 | 签名后可以变化的典型部分 |
| --- | --- |
| `0x41 ALL\|FORKID`（默认） | 所有输出及全部输入引用、sequence 已承诺。其他输入的解锁签名可随后补齐。 |
| `0xc1 ALL\|FORKID\|ANYONECANPAY` | 所有输出固定，可以另加满足自身授权的手续费输入。 |
| `0x43 SINGLE\|FORKID` | 输入引用顺序固定，仅同索引输出受输出承诺覆盖。 |
| `0xc3 SINGLE\|FORKID\|ANYONECANPAY` | 签署当前输入及其配对输出，可将二者一起调位。 |
| `0x42 NONE\|FORKID` | 持有人授权花费该输入，所有输出均可替换，包括收款人、金额及输出数量。全部输入的 outpoint 及顺序仍固定。 |
| `0xc2 NONE\|FORKID\|ANYONECANPAY` | 所有输出均可替换，其他输入也可以增加、替换或移除，只要交易整体有效。 |

可在创建输出时显式传入多项，所有者签名时从中选择。两种 NONE 模式的 `hashOutputs`、`hashSequence` 均为 32 字节零。其中 `0x42` 仍写入真实 `hashPrevouts`，`0xc2` 将其置零。NONE 不要求同索引输出，交易本身仍需至少一个合法输出。两种 SINGLE 模式均要求同索引输出存在。六种模式均直接承诺当前 outpoint、金额、sequence、版本、锁定时间、类型和本次执行的 scriptCode。[BSV ForkID 实现](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L2034-L2084)

## 两个输入分别授权

A 提供输入 0，B 提供输入 1。A 的 P-256 签名选择 `NONE`，B 的锁由另一把钥匙控制并固定允许的签名类型。节点分别执行两把锁，两者都成功才能花费两个 UTXO。下表均复用原始签名，且变更后总金额合法。

| A 签名 | B 签名 | 仅改输出 0 | 仅改输出 1 | 移除 B 并改付任意合法输出 |
| --- | --- | --- | --- | --- |
| `NONE` | `SINGLE` | 通过 | 拒绝 | 拒绝 |
| `NONE` | `ALL` | 拒绝 | 拒绝 | 拒绝 |
| `NONE+ANYONECANPAY` | `SINGLE` | 通过 | 拒绝 | 通过 |
| `NONE+ANYONECANPAY` | `ALL` | 拒绝 | 拒绝 | 通过 |

`NONE` 保留 `hashPrevouts`。如果 A 的签名必须交由 B 决定去向，A 的钱包应在签名前核对 B 的具体 outpoint、它在输入列表的位置以及该 UTXO 的真实锁定条件。B 的每条可用花费路径都须提供业务所需的输出约束。此时移除或替换 B 都会使原 A 签名失效。A 若使用 `NONE+ANYONECANPAY`，持有该签名的一方可以单独花费 A；B 的签名即使覆盖全部输出，其约束也只在实际花费 B 时生效。

B 用 `SINGLE` 时，业务应把希望保护的收款安排在与 **B 的输入位置**相同的输出位置。B 用 `ALL` 时，A 可以先授权确定的输入组合，B 再确定并签署全部输出。两笔输入的聪在整笔交易中共同结算，协议没有逐聪指定哪个输入支付哪个输出。[两把独立密钥的交易验收](./test_handwritten.py)

## 装配与云端验收

```python
from handwritten import FLAGS, locking_script

default_lock = locking_script(owner_hash160)
all_six = locking_script(owner_hash160, allowed_types=tuple(FLAGS))
all_and_none = locking_script(owner_hash160, allowed_types=(0x41, 0x42))
locking_bytes = all_six.raw_serialize()
```

测试使用 Python 3.12 和 `tx-engine==0.13.1`。软件 P-256 密钥生成与 CryptoKit 相同格式的签名；Rust 引擎对实际序列化的子交易执行 `Tx.validate(parents)`，包括手续费输入。修改交易的用例复用原来的完整解锁脚本，避免重新签名掩盖覆盖范围。测试还复核了迁移前的原像、公钥与签名向量。[chain-gang 的交易 API](https://github.com/nchain-innovation/chain-gang/blob/v0.13.1/docs/Python-API.md) · [六种模式的验收记录](https://github.com/linzhm/bsv-script-lab/actions/runs/44334209706)

```sh
python -m pip install tx-engine==0.13.1
cd research/secure-enclave-p256
python -m unittest -v test_handwritten
```

`zkscript_package` 提供交易内省工具和曲线运算积木，其专用标量乘法针对 secp256k1。本项目在独立测试中对照固定版本的 `TransactionIntrospection.pushtx`，付款锁本身由手写 ASM 装配。复现该项对照时，将固定版本的上游 checkout 根目录加入 `PYTHONPATH`，再运行 `python -m unittest -v compare_zkscript`。[nChain 的 PUSHTX 实现](https://github.com/nchain-innovation/zkscript_package/blob/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4/src/zkscript/transaction_introspection/transaction_introspection.py) · [上游曲线支持](https://github.com/nchain-innovation/zkscript_package/blob/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4/docs/secp256k1.md) · [分支验收工作流](../../.github/workflows/p256-script.yml)

默认锁与六模式锁的长度相同，允许位均占一个操作码。两者锁定字节和父交易标识不同，签名须使用对应输出的实际 outpoint。上一版 JavaScript 生成器及其交易夹具可在历史提交复查。Apple Secure Enclave 真机签署、BSV 原生节点执行、矿工接收策略及费用仍待实测。[历史版本](https://github.com/linzhm/bsv-script-lab/tree/f9c49cec9baff8246ceacb09525a612d06543448/research/secure-enclave-p256)
