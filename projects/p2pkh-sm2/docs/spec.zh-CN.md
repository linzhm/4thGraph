# P2PKH-SM2 v2 规范

实验版本 · BRC 编号未分配 · [English](spec.en.md)

## 授权与支付模型

付款方通过收款方的 SM2 公钥哈希创建 UTXO。持有人在花费该 UTXO 时公开公钥，并对本次交易的当前输入授权。签名者只需要 SM2 私钥；用于交易绑定的 secp256k1 公钥和签名构造参数均为公开数据。

本版本使用 curveSM2 及标准 SM2 签名方程。原生 `OP_CHECKSIG` 的算法保持 secp256k1 ECDSA。SM2 验签和 SM3 哈希由已有 Bitcoin Script 指令实现，不增加操作码或修改节点。

## 公钥、标识与摘要

公钥编码固定为 65 字节：`04 || X_BE32 || Y_BE32`。必须检查坐标在 `[0,p)`，且点满足 curveSM2 曲线方程；无穷远点不接受。曲线余因子为 1。收款标识为该 65 字节编码的 HASH160。

本模板的 SM2 用户标识固定为 ASCII `1234567812345678`，共 16 字节，ENTLA 为其比特长度的两字节大端编码 `0080`。身份标识是签名算法的输入，并不证明真实身份或证书有效性。

```text
ZA = SM3(ENTLA || IDA || a || b || Gx || Gy || Qx || Qy)
H  = SHA256(SHA256(P))
e  = SM3(ZA || H)
```

曲线域元素均为 32 字节大端。脚本从实际提供的公钥计算 ZA；不接受调用方传入的 ZA、e 或 SM3 计算结果作为证明。ZA 输入前 128 字节是固定常量，可在生成脚本时预计算 SM3 中间状态。剩余两个压缩块以及 `SM3(ZA || H)` 的两个压缩块仍在脚本内执行。

标准 SM2 **消息签名接口**应传入消息 `H` 和用户标识 IDA。仅当设备明确提供 SM2 **预哈希签名接口**时，才传入 `e`；不得让设备对 e 再次计算 ZA 和 SM3。使用 SM3 是完整 SM2 签名方案的一部分；比特币交易摘要和收款公钥哈希仍保留 SHA256d 和 HASH160。

## 当前输入交易绑定

每个输入可独立选择摘要算法、输出覆盖范围和 ANYONECANPAY（ACP）。下表是签名末尾的十六进制类型字节。预映像结尾按四字节小端序编码该类型，BSV 的高 24 位 fork 值为零。Chronicle 在花费时启用 `0x20`，激活前创建的 v2 输出也可以在激活后使用 OTDA。

| 输出覆盖范围 | 常规 ForkID（BIP143） | 加 ACP | Chronicle OTDA | OTDA 加 ACP |
|---|---|---|---|---|
| ALL，全部输出 | `41` | `c1` | `61` | `e1` |
| NONE，输出可变 | `42` | `c2` | `62` | `e2` |
| SINGLE，配对输出 | `43` | `c3` | `63` | `e3` |

未设置 ACP 时，签名覆盖所有输入的 outpoint，仅 ALL 同时覆盖其他输入的 sequence。设置 ACP 时，仅覆盖当前输入。所有模式的 SM2 授权均约束当前 outpoint、sequence、交易版本和 locktime。

普通路径使用最后一个 `OP_CODESEPARATOR` 之后的 `ac` 作为 scriptCode。BIP143 预映像固定 158 字节，并纳入被花费输出的金额。

```text
versionLE32 || hashPrevouts || hashSequence || outpoint || 01ac ||
amountLE64 || sequenceLE32 || hashOutputs || locktimeLE32 || typeLE32
```

OTDA 按原始算法序列化所选输入和输出，再追加四字节签名类型。它省略前序输出金额。配对 SINGLE 在当前索引之前保留空输出占位 `ffffffffffffffff00`，开启 ACP 后仍然如此。

**SINGLE 没有同索引输出时**，常规 ForkID 使用全零 hashOutputs。原生 OTDA 返回常量 `uint256(1)`，单凭这个常量无法把所有者签名绑定到当前 UTXO。对于 `63` 和 `e3`，持有人分别对 `43` 和 `c3` 的 BIP143 补充预映像签名，保留原有 ACP 选择。该分支使用独立的 scriptCode `ad68abac`，并要求 hashOutputs 全零。脚本同时执行补充预映像的原生校验和原 OTDA 类型的常量摘要校验。替换当前 outpoint 或补上配对输出都会使原签名失效。

脚本不接收序列化的父交易。钱包可在链下使用完整父交易核对 txid、索引、金额与锁定脚本；节点从 UTXO 上下文获得实际被花费输出。收款人验证交易和需要的 SPV 证据后，可将交易发给矿工。此参考钱包不实现区块头跟踪或默克尔证明验证。

## 验签条件

将签名解释为两个 32 字节大端整数 r、s，依次验证：

1. `1 <= r,s < n`。
2. `t = (r+s) mod n`，且 `t != 0`。
3. 计算 `R = sG + tQ`；拒绝无穷远点。
4. 验证 `r = (e + x(R)) mod n`。

脚本使用四位窗口和投影坐标运算。无需解锁方提供逆元。末步检查 `X = ((r-e) mod n) * Z mod p`，或者在第二候选小于 p 时检查 `X = (((r-e) mod n)+n) * Z mod p`。因为 `p < 2n`，两个候选完整覆盖坐标模 n 的情况。

SM2 不采用 ECDSA 的 low-S 归一化。不能将 s 随意替换为 n−s。

## 模板与见证

| 字段 | 字节数 / 位置 |
|---|---|
| 锁定脚本 | 199,777 字节（v2） |
| 收款公钥哈希 | 零起点 `[168,188)`，20 字节 |
| P | 常规 BIP143 为 158 字节，普通 OTDA 随交易变化，无配对 OTDA SINGLE 为 161 字节 |
| Q | 65 字节；序列化 push 共 66 字节 |
| `r || s` | 64 字节；序列化 push 共 65 字节 |
| scriptSig | 严格三个栈项。常规 BIP143 为 291 字节，无配对 OTDA SINGLE 为 294 字节，其他 OTDA 为 `len(push(P)) + 131` 字节 |

脚本识别必须检查全部固定程序字节，不能仅凭长度或前缀判断。所有者槽位以外的指纹、零所有者基础脚本哈希见 [layout.json](../template/layout.json)。[生成器](../reference/generate_lock.py) 直接输出 raw 或 hex；无需在仓库重复存放大体积展开字节。

## API 与拒绝条件

[Python API](../reference/p2pkh_sm2.py) 提供：

- `locking_script_from_owner_hash(owner)`：付款方只持有收款哈希即可生成脚本。
- `locking_script_from_public_key(key)`：校验完整 SM2 公钥并生成脚本。
- `recognize(raw)`：检查完整固定程序，返回所有者哈希或 None。
- `identify(raw)` 检查整个模板，返回版本和所有者哈希。v1 历史输出继续使用 `0x41` 花费。
- `sign_input(tx, index, funding_raw, key, signer, sighash_type, chronicle_active=active)` 核对 outpoint，按指定模式签署当前输入，保留其他输入已有的解锁脚本。调用者应提供花费时的激活状态。参数默认 `True`，传 `False` 时钱包会在调用签名器之前拒绝 OTDA。
- `current_input_unlock(tx, index, previous_amount, key, signature)`：验证当前输入 SM2 授权并编码见证。
- `sign_payment(funding_raw, vout, outputs, fee, key, signer)`：固定使用 `0x41`，核对父输出、密钥、金额及费用，调用 `signer(H, IDA)`，验证返回签名后组装交易。

调用者须确认父交易来源及确认状态，向签名设备展示或通过可信界面确认收款、找零和费用。Python 的公开曲线运算用于验证和测试，测试签名器要求显式传入公开测试 nonce；不得用于生产私钥签名。

## 验证与实施边界

测试覆盖标准向量、OpenSSL SM2 消息签名、SM3 分块边界与固定前缀中间状态、曲线/标量错误、错误用户标识、t=0、无穷远点、极少出现的 x≥n 第二候选、伪造预映像及交易字段篡改。常规转付的三次连续测试中，每个输入的解锁脚本均为 291 字节。[16 个向量](../template/sighash-modes.json) 覆盖 12 种配对输入及 4 种无配对 SINGLE。

本地开发求值器只验证生成器所使用的操作码子集；它不代表共识实现。独立的 [节点测试](../reference/test_node.py) 在 BSV Node 1.2.3 与固定版本 chain-gang 中验证完整输入。测试使用显式 UTXO 和脚本 flags，不能代替主网激活条件、矿工策略、手续费报价或硬件集成测试。脚本较大，应基于实际矿工报价评估创建输出的成本。

## 来源与致谢

- [RFC 8998 §3.2.1](https://www.rfc-editor.org/rfc/rfc8998.html#section-3.2.1)：curveSM2 参数及 SM2 用户标识语义。
- [OpenSSL 标准测试](https://github.com/openssl/openssl/blob/openssl-3.5.0/test/sm2_internal_test.c)：GM/T 0003.5-2012 和 GB/T 32918.5-2016 附录 A 签名向量。
- [SM3 算法描述](https://datatracker.ietf.org/doc/html/draft-sca-cfrg-sm3-02)：压缩函数、消息扩展和示例；此文档为 Internet-Draft。
- [nChain WP1605](https://nchain.com/wp-content/uploads/2022/03/WP1605_PUSHTX-and-its-Building-Blocks.pdf)、[BRC-21](https://github.com/bsv-blockchain/BRCs/blob/master/scripts/0021.md)：公开 PUSHTX 交易绑定构造。
- [P2PKH-R1](../../p2pkh-r1/README.md)：本仓库已有的 a=−3 投影坐标运算、窗口结构与公开原生签名构造；SM2 使用独立常量和签名方程。
