# P2PKH-R1 v7 初步方案：如何生成、识别和花费一把锁

[English edition](./p2pkh-r1-proposal.en.md)

付款人需要两项公开参数：收款人的 **P-256 公钥哈希**和**允许的签名类型集合**。用这两项实例化已验收的 v7 手写模板，就得到可以放进 BSV 交易输出的 59,811 字节 `scriptPubKey`。收款人在花费时才调用 Secure Enclave。v7 是本仓库的模板版本，与 BSV 交易的 `nVersion` 分开。[生成入口](../../research/secure-enclave-p256/generate_lock.py) · [手写入口块](../../research/secure-enclave-p256/universal.asm)

## 一、收款人与付款人的约定

1. 收款钱包导出 P-256（secp256r1）签名公钥的 65 字节 X9.63 表示 `04 || x_BE32 || y_BE32`。收款请求应标明 `P2PKH-R1`、模板版本 7、签名许可，以及这个公钥或其 `RIPEMD160(SHA256(Q))`。这是双方的钱包接口约定，本方案没有分配 BSV 地址前缀。仅凭公钥哈希无法确认收款人持有密钥或密钥的硬件来源。[Apple Secure Enclave 签名接口](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey)
2. 付款钱包从可信的收款请求取得字段。收到公钥时验证编码和曲线点，再哈希完整 65 字节；收到已约定的哈希时验证长度为 20 字节。普通付款默认只允许两个 ALL 类型 `41,61`。业务需要 NONE、SINGLE 或 ANYONECANPAY 时，在创建这笔输出前显式加入相应的类型。
3. 生成器装配脚本，再用完整模板识别器读回类型、版本、所有者哈希及全部许可。付款钱包核对金额，以原始字节设置新输出的 `scriptPubKey`。输出在交易中的序列化为 `amount_LE64 || CompactSize(59811) || scriptPubKey`；长度前缀是 `fd a3 e9`。整个脚本直接作为输出程序，不能再包一层 PUSHDATA。[识别器](../../research/secure-enclave-p256/lock_identity.py)

## 二、生成一份可以逐字节比较的样例

以下命令适用于有私库读取权限、Python 3.12 和对应 tx-engine wheel 的 Linux 环境。下载依赖后，生成阶段可离线运行。示例哈希仅用于重现字节，不对应本方案提供的收款钱包。

```sh
git clone --branch research/pels-transaction-bounds https://github.com/linzhm/bsv-script-lab.git
cd bsv-script-lab
git checkout --detach f2c1503d4cb2d4843a4b13f6b8be187816376eea
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --only-binary=tx-engine tx-engine==0.13.1
cd research/secure-enclave-p256
OWNER=000102030405060708090a0b0c0d0e0f10111213
python generate_lock.py --owner-hash160 "$OWNER" --allow 41,61
python generate_lock.py --owner-hash160 "$OWNER" --allow 41,61 --format raw > scriptPubKey.bin
sha256sum scriptPubKey.bin
```

清单应显示模板 `P2PKH-R1`、版本 `7`、许可 `["41","61"]` 和长度 `59811`。样例原始脚本的单次 SHA-256 为 **`6ac6c4dbbf77bb0a73cf2136338c5d81a3c2674f71929f9c2dd196064be6b952`**。这是文件指纹。花费交易的签名摘要另行计算。实际收款时可将 `--owner-hash160 "$OWNER"` 换成 `--public-key "$PUBLIC_KEY_HEX"`，对应同一公钥哈希的两个入口生成完全相同的字节。改变所有者或权限会改变文件指纹。[样例二进制与 JSON 清单](https://github.com/linzhm/bsv-script-lab/actions/runs/44356580922/artifacts/14454081010) · [生成及验收日志](https://github.com/linzhm/bsv-script-lab/actions/runs/44356580922/job/134986197432)

## 三、锁定程序如何装配

| 源码 | 工作 |
| --- | --- |
| [universal.asm](../../research/secure-enclave-p256/universal.asm) | 提供 `LOCK` 入口、所有者与十二个权限槽位、普通及无配对 SINGLE 分支，以及原生检查的代码分隔符。 |
| [payment.asm](../../research/secure-enclave-p256/payment.asm) | 检查 R1 曲线点、签名和公共运算提示，用 WP1605 的 PUSHTX 构件把所提供的摘要与当前 BSV 原生签名检查相连。 |
| [window-4.asm](../../research/secure-enclave-p256/window-4.asm) | 分别处理固定基点 G 和本次公钥 Q 的四位表。装配时把 256 位标量的 64 轮展开为固定操作码。 |
| [handwritten.py](../../research/secure-enclave-p256/handwritten.py) | 读取命名汇编块和固定重复，用 nChain chain-gang 的 tx-engine 编码操作码，填入 20 字节所有者哈希及十二个 `OP_0/OP_1`。API 调用为 `locking_script(owner_hash, allowed_types, version=7).raw_serialize()`；省略版本会选择旧模板。 |

收款时只需确定这十三个槽位。花费时，锁计算提供的原像的双 SHA-256，验证所有者的 R1 ECDSA 签名；原生 secp256k1 `OP_CHECKSIG` 提供交易绑定。PUSHTX 的辅助参数是公开的。签名材料还绑定所推父交易的哈希与当前 outpoint 中的 txid。普通支付允许收款人选新的输出脚本；如果业务要求同索引延续原锁，需要另行定义 PELS 的后继输出约束。构造 v7 无需 sCrypt、JS/TS 或上游 zkscript 编译器。[WP1605 原文章节和出处](./pels-transaction-bounds.md) · [nChain PUSHTX 对照实现](https://github.com/nchain-innovation/zkscript_package/blob/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4/src/zkscript/transaction_introspection/transaction_introspection.py) · [chain-gang 固定版本](https://github.com/nchain-innovation/chain-gang/tree/v0.13.1)

## 四、一个 UTXO 怎样支持两种签名算法

付款时固定许可集合；花费时，钱包为每个输入选择一个被允许的类型。下表各值均为十六进制，括号内为加 ANYONECANPAY 的值。Chronicle 生效时，这些类型具有 ForkID 位 `40`，额外的 `20` 位选择 OTDA。同笔交易的输入可以选择不同类型。[Chronicle 规范](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release) · [节点签名序列化与分派](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L1894-L2124)

| 授权 | BIP143 风格 ForkID | OTDA | 输出范围 |
| --- | --- | --- | --- |
| ALL | 41 (c1) | 61 (e1) | 所有输出的顺序、金额、脚本 |
| NONE | 42 (c2) | 62 (e2) | 本签名允许变更全部输出 |
| SINGLE | 43 (c3) | 63 (e3) | 有配对时约束与当前输入同索引的输出；缺配对时按下述规则 |

BIP143 路径中，未选 ANYONECANPAY 时 `hashPrevouts` 承诺有序的所有输入 outpoint，选中时为 32 个零字节。当前输入的 outpoint、前序输出金额和 sequence 仍直接进入原像。仅非 ANYONECANPAY 的 ALL 提交完整 `hashSequence`。ALL 的 `hashOutputs` 承诺全部序列化输出；有配对 SINGLE 仅承诺对应输出；NONE 和无配对 SINGLE 取零。OTDA 序列化按类型变换后的交易，没有独立的上述三个哈希字段，也没有独立的前序输出金额字段。两种算法均不会凭其他输入的 outpoint 直接证明其金额。需要总费用时，钱包应取得每个输入对应的真实前序输出。约束变长输出时须验证真实输出的序列化及边界；任意字节切片没有这样的语义。[节点源码](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L1894-L2124) · [各类约束的边界](./pels-transaction-bounds.md)

例如有输入 0、1，只有输出 0。输入 1 选 BIP143 SINGLE 仍有交易专属摘要，只将 `hashOutputs` 置零。选 OTDA SINGLE 时，节点在序列化前返回常量 `uint256(1)`。v7 保留这项原生检查，并要求手机对绑定当前输入的伴随 BIP143 SINGLE 摘要签**一次**；保留原 ANYONECANPAY 选择，使用单独的 `scriptCode`。这样缺配对时也能授权，手机绝不单独签一个可在不同交易间重复使用的常量。若业务希望 A 用 NONE 把输出的决定权交给 B，应由 A 核对并承诺 B 的 outpoint，再由 B 用 ALL 或有配对的 SINGLE。A 若打开 ANYONECANPAY，A 的签名就不要求 B 一起花费。[分支与混用实测](./p2pkh-r1-universal.md)

## 五、钱包花费时实际推什么

钱包取得直接父交易、待签子交易、当前输入序号和请求类型。先核对真实 outpoint 和前序输出、模板、许可及所有者，再把收款输出、找零、费用与本次许可的可变字段展示给用户。按选中路径构造原像 P，对 `SHA256(SHA256(P))` 用硬件摘要签名接口签一次。签名回调输入是已算好的 32 字节摘要；若交给会先哈希消息的接口，则会多哈希一轮。签名以定宽大端 `r || s` 交给钱包。仓库提供 `checked_wallet.sign_spend(tx, index, parent, requested_type, pubkey, sign_digest, history_path)`，返回解锁脚本。[已检查的钱包入口](../../research/secure-enclave-p256/checked_wallet.py) · [原像构造](../../research/secure-enclave-p256/universal.py)

| 推入顺序（从栈底到栈顶） | 内容 |
| --- | --- |
| 1 | 直接父交易的完整序列化字节 |
| 2 | 当前授权路径的原像 P |
| 3 | 收款人的 65 字节 X9.63 公钥 Q |
| 4 | 单个 64 字节 R1 签名，无 DER 外壳或附加类型字节 |
| 5 | 4 字节小端位置提示。普通非 ANYONECANPAY 的 OTDA 为真实输入序号，其他情况为零 |
| 6 | 32 字节小端 `w = s⁻¹ mod n`。锁检查范围和 `s·w mod n = 1` |
| 7 | 普通路径 `OP_0`，无配对 OTDA 伴随路径 `OP_1` |

OTDA 普通路径读取输入数量、检查位置范围和当前位置的脚本标记。R1 共用固定轮数的验证主体，锁无需按交易输入输出数量动态循环。完整父交易必须可获得，且其大小全部计入解锁。连续花费同类输出时，父交易还会包含更早一次花费所推的数据；测算费用应使用实际父交易长度。[通用汇编](../../research/secure-enclave-p256/universal.asm) · [解锁构造](../../research/secure-enclave-p256/universal.py)

## 六、识别、安全与验收

- **识别。** 对一个已解析输出的完整原始程序调用 `identify_locking_script(raw)`。v7 所有者哈希位于零起算的 `[437,457)`。识别器用字节正则捕获参数并逐字节比对固定程序，要求全部许可合法且至少开启一项。短前缀和偏移只供筛选。需要验证候选公钥时使用 `matches_owner_key`。需要为新收款人生成锁时用生成器重新装配。[识别器与正则](../../research/secure-enclave-p256/lock_identity.py) · [装配与匹配](../../research/secure-enclave-p256/handwritten.py)
- **密钥与 nonce。** 收款锁只公开所有者哈希，花费时才公开 Q。钱包不接收临时私钥作为模板参数；辅助公钥也不作为所有者返回。`w` 可从公开的 s 算出。真正需要保密的是签名私钥和 ECDSA nonce k。同钥对不同摘要重复 k 可能泄露私钥；钱包在返回解锁脚本前核验签名，用持久化历史检测同钥、不同摘要、相同 r 的冲突。它只覆盖经过该入口且历史完整的签名。真机签名器的 nonce 实现仍需按其平台保证评估。[钱包实现](../../research/secure-enclave-p256/checked_wallet.py) · [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979)
- **已验收。** 公钥与哈希两种输入生成相同字节；非曲线点、32 字节标量和未知权限被拒绝。合成交易覆盖 12 种模式、同笔混用、两种无配对 SINGLE，以及错误所有者、父交易和求逆提示。生成版 CI 通过 52 项 Python/chain-gang 测试、8 项无对等连接的 BSV Node 1.2.3 测试和 2 项 nChain 对照。无配对 OTDA 的节点行为以原生节点为准。[本次 CI](https://github.com/linzhm/bsv-script-lab/actions/runs/44356580922/job/134986197432)
- **选型与上线缺口。** 旧签名格式的两位联合表和四位分表分别为 62,051 和 61,717 字节，百万次的每次均值为 6.7190、6.5925 ms。v7 复用摘要并验证外部提供的逆元，最终为 59,811 字节。v7 的小样本是每条路径 32 次本机 RPC，均值约 22 ms，包含 RPC 开销。下一项设备验收是由真机 Secure Enclave 对固定交易摘要签名、读出 64 字节签名，再用同一离线节点验证。矿工接收策略、实际费用及部署安全审查仍待验证。[旧版百万次记录](https://github.com/linzhm/bsv-script-lab/actions/runs/44342695412/job/134946778724) · [v7 小样本](https://github.com/linzhm/bsv-script-lab/actions/runs/44350574355/job/134964757191)
