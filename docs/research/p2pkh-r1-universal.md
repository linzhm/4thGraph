# P2PKH-R1 通用摘要与 `SINGLE` 边界

同一 v7 输出可以在花费时按签名类型选 BIP143 或 OTDA。创建输出时将允许的类型写入模板。默认许可 `0x41`、`0x61` 两种 ALL；可以显式选取 12 种类型的任一非空子集。每笔交易有一个 `nVersion`，每个原生签名有自己的类型字节。Chronicle 激活后，`0x20` 选择 OTDA，`0x40` 是 ForkID，`0x80` 是 ANYONECANPAY。[节点分派](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L2112-L2124) · [Chronicle 规范](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release)

## 钱包与锁的接口

```python
from handwritten import UNIVERSAL_FLAGS, locking_script
from universal import authorization, universal_unlocking_script

lock = locking_script(owner_hash160, UNIVERSAL_FLAGS, version=7)
auth = authorization(unsigned_tx, input_index, previous_amount_sats, requested_type)
digest = auth.digest()
# 在 Secure Enclave 的摘要重载上签 digest，得到 64 字节大端 r || s。
unlock = universal_unlocking_script(raw_parent, auth, public_key_x963, raw_signature)
```

解锁依次推直接父交易、原像、65 字节公钥、64 字节签名、4 字节小端位置提示、32 字节小端求逆提示、分支位。普通 BIP143 使用零位置提示；OTDA 使用当前输入在签名序列化中的序号，ANYONECANPAY 时为零。锁检查允许类型、父交易哈希、公钥哈希、曲线点、`s·w mod n = 1` 和 R1 签名。两种摘要共享 4 位分表。R1 使用一次 `SHA256d(P)` 的结果作为签名摘要；调用消息签名 API 时须注意其隐含的额外 SHA-256。[通用汇编](../../research/secure-enclave-p256/universal.asm) · [钱包构造函数](../../research/secure-enclave-p256/universal.py)

OTDA 分支解码输入向量的 CompactSize 计数，检查提示小于计数，按每个前置输入 41 字节算出候选 outpoint，核对其父 txid 和紧随 36 字节 outpoint 的 `02 68 ac`。节点认证的序列化中只有当前输入具有这个脚本字段。猜测的位置早于当前输入时，长度字节为零；猜测偏晚时，由于当前记录多了两字节，候选标记的末字节会落在后续空脚本的零长度上。常规路径只需定长分割，无需在锁内遍历输入或输出。[节点 OTDA 序列化](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L1894-L1956)

## 两个输入、只有输出 0 时如何花费输入 1

| 所选类型 | 节点验签摘要 | v7 的控制权验证 |
| --- | --- | --- |
| BIP143 SINGLE（43/c3，十六进制） | `hashOutputs` 取 32 个零字节，其他适用字段照常参与双 SHA-256 | 手机签这份正常的 BIP143 摘要 |
| OTDA SINGLE（63/e3） | 节点直接返回 `uint256(1)`，没有该笔交易专属的 OTDA 原像 | 节点执行请求的 OTDA 检查，手机签一次伴随 BIP143 摘要，绑定真实 outpoint、金额、sequence、版本、锁定时间以及相同的 ANYONECANPAY 选择 |

这个例子里没有输出 1 的金额或锁定脚本。BIP143 中的 `scriptCode` 来自正在被花费的旧输出。若整笔交易的输出数量是零，则交易基本检查拒绝 `bad-txns-vout-empty`。[两种 SINGLE 路径](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L2053-L2109) · [交易基本检查](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/validation.cpp#L525-L533)

无配对 OTDA 路径保留请求的 63/e3 签名类型，同时要求一份当前输入专属的授权。这是本付款锁的所有者规则。原生常量摘要检查采用 PUSHTX 公开参数，不能单独授权花费。常规路径的 `scriptCode` 为 `68 ac`；伴随 BIP143 路径使用 `63 ad 67 ab 68 ac`，要求 `hashOutputs` 为零。两个不同后缀由实际执行的 `OP_CODESEPARATOR` 决定，防止把常规 BIP143 的手机签名移用到伴随路径。两种路径都只有一次手机 R1 签名。缺配对期间，变更仍未配对的其他输出符合 SINGLE 的覆盖范围。

## 如何解读体积

PELS 是后继输出延续规则；PUSHTX 是使用原生 CHECKSIG 的交易绑定构件。这里的普通付款锁没有强制后继输出复刻自身。为比较汇编方式，验收单独构造两份仅做绑定的脚本，同用 BIP143 ALL、完整原像、末尾代码分隔符，检查正例及修改输出后的反例。[对照测试](../../research/secure-enclave-p256/compare_zkscript.py) · [nChain 固定版本](https://github.com/nchain-innovation/zkscript_package/blob/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4/src/zkscript/transaction_introspection/transaction_introspection.py)

| 仅绑定测试 | 锁定脚本 | 解锁脚本 | 两段脚本合计 |
| --- | ---: | ---: | ---: |
| 手写，常量在锁中 | 590 B | 160 B | 750 B |
| nChain 标准 pushtx，解锁提供三项常量，锁验证 | 378 B | 263 B | 641 B |

独立候选 v5（BIP143）与 v6（OTDA）完整锁分别为 59,431 B、59,454 B，后者增加 23 B。单输入单输出 ALL 样例原像分别为 158 B、66 B；OTDA 原像随交易结构与签名范围变化。chain-gang 各执行 512 次，总时长约 2.479 秒和 2.422 秒。v5/v6 仅作为比较候选，配对要求与 v7 不同。[独立模板小样本](https://github.com/linzhm/bsv-script-lab/actions/runs/44347972870)

此前的百万次实验使用带标签的旧签名格式，2 位联合表与 4 位分表每次平均为 6.7190 ms 和 6.5925 ms，不能将这些数值作为新通用锁的性能测量。[百万次配对实验](https://github.com/linzhm/bsv-script-lab/actions/runs/44342695412/job/134946778724)

## 通用锁验收

v7 实测为 **59,811 B**。在无 P2P 连接的 BSV Node 1.2.3 regtest 上，通过只读 `verifyscript` RPC 提供序列化交易、输入索引、真实前序输出脚本和金额，并显式启用 Genesis、Chronicle 和 ForkID 规则。验收覆盖同一把锁的 12 个类型、两种输入位置、两种摘要在同笔交易混用、253 个输入的 CompactSize 前缀及错误位置提示。无配对 43/c3/63/e3 均通过；增加配对输出、移用到不同 outpoint、混用不同 `scriptCode` 的授权均按预期被拒绝。chain-gang 0.13.1 对无配对 OTDA SINGLE 的原像请求返回错误，本边界采用原生节点实测。真机 Secure Enclave 和矿工接收策略仍待实测。[原生节点验收日志](https://github.com/linzhm/bsv-script-lab/actions/runs/44350272745/job/134963678908) · [原生验收代码](../../research/secure-enclave-p256/test_universal.py)
