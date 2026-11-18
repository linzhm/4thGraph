# P2PKH-R1 通用摘要与 `SINGLE` 边界

生成完整付款脚本、读取权限及构造解锁栈，见 [中文初步方案](./p2pkh-r1-proposal.zh-CN.md) · [English proposal](./p2pkh-r1-proposal.en.md)。

同一 v7 输出可以在花费时按签名类型选 BIP143 或 OTDA。创建输出时将允许的类型写入模板。本报告原先使用仅许可两种 ALL 的实验设置。普通 P2PKH-R1 收款现已开放全部十二种类型，签名钱包可默认选 ALL。每笔交易有一个 `nVersion`，每个原生签名有自己的类型字节。Chronicle 激活后，`0x20` 选择 OTDA，`0x40` 是 ForkID，`0x80` 是 ANYONECANPAY。[节点分派](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L2112-L2124) · [Chronicle 规范](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release)

## 选型决定

本研究选用 **v7 通用锁、4 位分表、手写 PUSHTX 绑定**。钱包显式传入 `version=7`。固定基点的 16 项表可以逐项与独立曲线库核对，另一张表只依赖本次花费揭示的公钥。BIP143、OTDA 和伴随授权复用同一份 R1 验签主体。选择依据是这份布局已有原生节点上的分支验收、表项可独立检验；百万次测试中获得的速度差属于旧签名格式。[窗口汇编](../../research/secure-enclave-p256/window-4.asm) · [表项测试](../../research/secure-enclave-p256/test_windows.py)

| 版本 | 主要差异 | 完整锁 B | 相对上一行 |
| --- | --- | ---: | ---: |
| v3 | 旧签名格式，2 位联合表 | 62,051 | — |
| v4 | 相同格式，4 位分表 | 61,717 | −334 |
| v5 | 4 位分表，BIP143 原生摘要，花费者提供求逆值 | 59,431 | −2,286 |
| v7 | 4 位分表，通用摘要和无配对 SINGLE 路径 | 59,811 | +380 |

v4 仅 `INVERT_SCALAR` 就展开 255 次模平方和 168 次额外模乘，各 5 字节，共 2,115 字节。v5/v7 在锁内检查 32 字节的求逆提示，并把一次双 SHA-256 得到的数值摘要供 R1 验签和原生绑定共同使用。v4 至 v7 完整锁净省 1,906 字节。表中比较的是锁定脚本；提示及其推栈编码计入解锁脚本。[公共运算块](../../research/secure-enclave-p256/payment.asm) · [旧版入口](../../research/secure-enclave-p256/tagged-lock.asm) · [通用入口](../../research/secure-enclave-p256/universal.asm)

nChain 的标准 `pushtx` 可用于固定 sighash 的原像或摘要绑定。上游在生成脚本时把所选类型字节写进程序。v7 在花费时选择类型，还依赖两处执行路径的 `OP_CODESEPARATOR` 来区分普通授权和伴随授权。直接替换会改变这些签名边界。上游固定版本继续用于独立对照；普通付款也无需添加 PELS 的后继输出延续约束。下文列出两种绑定片段实测的锁定与解锁字节。[nChain PUSHTX 源码](https://github.com/nchain-innovation/zkscript_package/blob/fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4/src/zkscript/transaction_introspection/transaction_introspection.py)

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

### 通用锁的小样本

在同一台 runner 上，各路径先预热，再交替进行 32 次本机 RPC 验证。交易有两个输入，当前输入位置为 1；ALL 组有两个输出，无配对 SINGLE 组只有输出 0。计时包含客户端序列化、HTTP 往返、原生节点检查和结果读取。各路径均使用同一把 59,811 字节的锁。这组小样本主要用于确认可运行性，不能和 chain-gang 在进程内的每次验证耗时直接比较。[本机 RPC 样本及所有 CI 结果](https://github.com/linzhm/bsv-script-lab/actions/runs/44350574355/job/134964757191)

| 路径 | 手机所签原像 B | 解锁脚本 B | RPC 平均 ms |
| --- | ---: | ---: | ---: |
| BIP143 ALL | 159 | 60,207 | 22.17 |
| OTDA ALL | 118 | 60,166 | 22.21 |
| BIP143 SINGLE，无配对 | 159 | 60,207 | 22.02 |
| OTDA SINGLE，无配对 | 163 | 60,211 | 22.14 |

最后一行的 163 字节属于伴随 BIP143 授权；原生 OTDA 检查取常量摘要。测试代码提交为 [265c698297f56c5116f853b9be9092e93d8a43b7](https://github.com/linzhm/bsv-script-lab/commit/265c698297f56c5116f853b9be9092e93d8a43b7)。

## 签名私钥与 nonce 的安全边界

付款人锁定的是 R1 公钥哈希。解锁公开父交易、原像、公钥、ECDSA 签名 `(r,s)`、位置、分支位和 `w=s⁻¹ mod n`。任意观察者都可以由公开的 `s` 算出 `w`。这些字段不需要手机私钥或签名 nonce。v7 的 secp256k1 PUSHTX 检查采用公开参数，作用是交易绑定；授权依赖独立的 secp256r1 签名。

**同一把 R1 钥匙对两个不同消息摘要复用秘密 nonce，可能导致私钥被恢复。** 即使硬件不提供导出私钥的接口，已发布的错误签名仍有这个风险。相同公钥在不同摘要上出现相同 `r` 是需要阻断的信号；同一摘要的确定性重签可以产生相同签名。软件测试使用确定性签名，Apple 的公开 API 只保证了所提供的建钥、签名等接口，本研究未核实 Secure Enclave 内部生成 nonce 的具体算法或侧信道特性。[RFC 6979](https://www.rfc-editor.org/rfc/rfc6979#section-3.2) · [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final) · [Apple Secure Enclave 签名 API](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey)

钱包可以通过已检查的入口构造 v7 解锁脚本。调用方负责展示并核对收款输出、找零、金额、费用和本次 sighash 授权范围，向回调传入摘要。回调须返回 64 字节签名，且在检查完成前不记录或发送签名。对已经签署并泄露的两个冲突签名，本地阻断无法追回它们；应停止使用该钥匙新增授权，按钱包的密钥泄露流程处理。[钱包入口](../../research/secure-enclave-p256/checked_wallet.py)

```python
from checked_wallet import sign_spend

unlock = sign_spend(unsigned_tx, input_index, parent_tx, requested_type,
                    public_key_x963, hardware_sign_digest, wallet_history_path)
```

入口检查真实 outpoint 对应的脚本、金额、模板许可及所有者，重建摘要，调用签名器一次，并用独立的 P-256 实现验证结果。发布前在同一个 SQLite 写事务内检查并记录 `(Q,r,digest)`。同摘要可重试；若发现同钥同 `r` 配不同摘要，先持久化该钥匙的阻断状态，再抛出错误。数据库只记录观察所需的公钥、公开签名分量和摘要。应使用受保护的固定路径并保持历史完整；多个调用进程共用同一历史，独立数据库、历史回滚或绕过该入口的签名无法相互检测。这是事后观察，不能发现所有低熵或带偏差的 nonce。锁定脚本只能看到当前输入的验证材料。原始装配接口留给试验和已在其他位置完成验证的调用方。

| 检查层 | 通过与拒绝用例 |
| --- | --- |
| 签名器前的策略检查 | 错父交易、错误所有者、禁用的 sighash 均在调用回调前拒绝，由 outpoint 指向的实际前序输出可以位于索引 1 |
| 发布前签名与 nonce 检查 | 错误摘要的签名和越界标量不写历史；并发重试只写一行；模拟已有冲突记录时阻断且重开后仍然有效，另一把钥匙可独立使用 |
| BSV 节点输入验证 | 检查 `r,s` 为 0 或群阶、错误或越界逆元、已与所有者哈希匹配的无效公钥点；合法的另一个 ECDSA `s` 表示须配上对应逆元 |
| 跨交易与分支 | 复用既有的 outpoint、类型许可、无配对伴随授权与错误位置测试。NONE、ANYONECANPAY 放开的字段由签名类型决定 |

nonce 告警测试在临时数据库里模拟先前观察，没有生成使用重复秘密 nonce 的签名对。上述链上用例均为合成输入，在无对等连接的 regtest 上调用只读验证 RPC。新增防护不改变 v7 脚本字节。[钱包回归](../../research/secure-enclave-p256/test_checked_wallet.py) · [原生节点回归](../../research/secure-enclave-p256/test_universal.py)

## 下一项可验证提示的体积预算

v7 的四位分表中，固定 G 表的文字操作码与常量占 1,023 B，15 个非零仿射点的原始坐标本身占 960 B。把这些坐标移至解锁脚本并核对固定哈希还要增加解包代码。更值得试验的是动态 Q 表：当前窗口从 `2Q` 到 `15Q` 的建表指令共 2,172 B。可以考虑由钱包额外提供 14 个仿射斜率，按顺序从已核验的 Q 得出这 14 个点。每一步都要验证分母非零、域内的斜率等式，并由脚本计算下一点。14 个定长域元素合计 448 B，如合并为一个栈项则总推入开销为 451 B。这些量只依赖公开 Q，钱包不需要接触签名 nonce。2,172 B 是当前可替换代码的总预算，净节省量取决于新检查、解包和栈管理的实际装配大小。这里仅做静态核算，尚未改变通用锁或得出新版体积。完整花费还携带父交易，其中含上一次的锁与解锁数据，也应纳入比较。[四位窗口](../../research/secure-enclave-p256/window-4.asm)

本轮验收通过 46 项 Python/chain-gang 测试、8 项 BSV Node 1.2.3 离线测试和 2 项 nChain 对照测试。v7 锁仍为 59,811 B。[具体运行与日志](https://github.com/linzhm/bsv-script-lab/actions/runs/44353247588/job/134974347874)
