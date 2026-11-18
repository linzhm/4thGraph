# 用 Apple Secure Enclave 公钥收取 BSV

这个研究模板实现普通持有人付款。付款人把收款人的 P-256 公钥哈希写入锁定脚本。收款人可签署带多个输入、多个收款输出及找零的交易；新输出可使用其他锁定脚本。默认签名类型是 `ALL|FORKID`（0x41）。[锁定与解锁脚本生成器](./script.mjs) · [可复现的交易材料](./fixture.mjs)

**实测大小是主要取舍。** 默认锁定脚本为 **339,383 字节**。BSV 节点的原生 `CHECKSIG` 使用 secp256k1，Secure Enclave 使用 NIST P-256（secp256r1）。本模板把 P-256 验签展开为 BSV 整数运算，用原生 `CHECKSIG` 绑定当前交易。标准 P2PKH 的所有者模型得以保留，但不能沿用其 25 字节脚本或标准地址编码。此大小是本参考实现的测量值，并非 P-256 验签的理论下限。[BSV 节点 CPubKey::Verify](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/pubkey.cpp#L183-L214) · [Apple SecureEnclave.P256.Signing.PrivateKey](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey)

## 锁定参数与解锁栈

`lockingScriptHex(ownerHash160, allowedTypes = [0x41])` 返回可直接序列化进交易输出的十六进制 Script。所有者标识为 `RIPEMD160(SHA256(Q))`，对完整的 65 字节非压缩 X9.63 公钥求哈希，含开头的 `04`。同一公钥采用另一种编码会产生不同哈希。付款时应确切约定模板和允许的类型。普通付款只需默认值。[Apple 公钥编码](https://developer.apple.com/documentation/cryptokit/p256/signing/publickey/x963representation)

`unlockingScriptHex(parentHex, preimageHex, x963PublicKeyHex, rawSignatureHex)` 返回四次规范压栈组成的解锁脚本。顺序从栈底到栈顶：

| 栈项 | 格式及用途 |
| --- | --- |
| `parentTx` | 当前输入直接引用的完整父交易，使用 BSV 的线序原始字节。用双 SHA-256 对照实际 outpoint 的 txid 部分。 |
| `P` | 本输入的 ForkID 原像，固定 158 字节。由钱包从当前花费交易、该输入的位置和真实前序输出金额构造。 |
| `Q` | Secure Enclave 公钥，`04 || BE32(x) || BE32(y)`。验证所有者哈希、坐标范围及 P-256 曲线方程。 |
| `sig` | 64 字节 `BE32(r) || BE32(s)`。使用 CryptoKit 的 `rawRepresentation`。接受标准 ECDSA 的两个合法 s 表示，不能依赖该签名为交易提供唯一 txid。 |

这里的“前序交易”取当前输入直接引用的那一笔。验证整笔父交易的哈希即可证明提交材料的身份，原像已绑定当前 vout 序号和节点提供的金额。脚本无需切出父交易中的变长输出，也没有从父交易中读取其他 UTXO 金额。若连续用这种模板再付款，新交易携带的父交易原文也包含上一轮的解锁数据，费用预算应计入这部分累积字节。

## 脚本怎样执行

以下是生成器的逻辑形态，方括号表示生成器实际展开的子程序。输出字节码只包含节点支持的操作码。

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

可在创建输出时显式传入多项，所有者签名时从中选择。模板对两种 SINGLE 模式都拒绝缺失配对输出；金额和收款脚本由持有人签署，不要求复制当前锁。四种模式仍直接承诺当前 outpoint、金额、sequence、版本、锁定时间、类型和本次执行的 scriptCode。[BSV ForkID 实现](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L2034-L2084)

## 离线验证与边界

默认样本使用合成父交易，目标输入金额为 1,000 聪。子交易有两个输入、两个输出；公开样本签名授权 800 聪和 300 聪两个输出。第二个输入代表另一资金来源，夹具只验证输入 0。生成的真实操作码已在独立的轻量指令解释器中核对 14 个正反场景：

| 改动 | 预期与本次结果 |
| --- | --- |
| 正确的 ALL 材料；随后把找零从 300 改为 299 聪或追加输入，复用旧材料 | 原交易通过，两个改动均拒绝 |
| 替换父交易、换公钥、令 s 为零，或挪用另一份交易授权 | 四项均拒绝 |
| 固定仅允许 ALL 的锁，提交有效的 SINGLE 授权 | 拒绝 |
| 显式允许 SINGLE，同索引输出存在；修改其他输出；修改同索引输出；缺少配对输出 | 依次通过、通过、拒绝、拒绝 |
| 显式允许 ALL+ACP 或 SINGLE+ACP 后追加输入 | 两项均通过 |

可复现样本使用 Node.js 标准库，含原像、脚本哈希和 OpenSSL P-256 验签断言。第二条命令生成原生 BSV 节点 `verifyscript` 的 JSON 请求，含相同解锁脚本下的原交易及改找零交易，预期分别为 `ok`、`error`。该命令只写标准输出，样本不需要真实 UTXO。[节点 RPC 参数及返回值](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/rpc/misc.cpp#L506-L603)

```sh
node research/secure-enclave-p256/fixture.mjs
node research/secure-enclave-p256/fixture.mjs --rpc > p256-verifyscript.json
```

本次核验覆盖合成 ECDSA 签名和已生成操作码。尚未取得 Apple 硬件签名、BSV 原生节点执行结果或节点接收策略及执行时间的实测值。轻量解释器只用于本次交叉检查，不构成共识实现。此模板的交付状态为研究参考实现。
