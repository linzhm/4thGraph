# P2PKH-SM2 v1.0.0 规范

[English](spec.en.md) · [项目概览](../README.zh-CN.md)

本规范描述 v1.0.0 的发布基线，以及各锁定模板共用的授权规则。项目尚未分配 BRC 编号。[v1.12.0 候选版](../README.zh-CN.md#v1120)

## 授权与支付模型

付款方通过收款方的 SM2 公钥哈希创建 UTXO。持有人在花费该 UTXO 时公开公钥，并对本次交易的当前输入授权。签名者只需要 SM2 私钥；用于交易绑定的 secp256k1 公钥和签名构造参数均为公开数据。

本版本使用 curveSM2 和标准 SM2 签名方程。SM3 和 SM2 验签由现有 Bitcoin Script 指令实现。原生 `OP_CHECKSIG` 使用 secp256k1 ECDSA，通过公开的 PUSHTX 构造将签名预映像绑定到实际交易。

## 公钥、标识与摘要

公钥使用 65 字节的未压缩编码 `04 || X_BE32 || Y_BE32`。必须检查坐标位于 `[0,p)`，且公钥是 curveSM2 上的有限点。曲线余因子为 1。收款标识是这段 65 字节编码的 HASH160。

本模板的 SM2 用户标识固定为 ASCII `1234567812345678`，共 16 字节，ENTLA 为其比特长度的两字节大端编码 `0080`。身份标识是签名算法的输入，并不证明真实身份或证书有效性。

```text
ZA = SM3(ENTLA || IDA || a || b || Gx || Gy || Qx || Qy)
H  = SHA256(SHA256(P))
e  = SM3(ZA || H)
```

曲线域元素均为 32 字节大端。脚本从实际提供的公钥计算 ZA；不接受调用方传入的 ZA、e 或 SM3 计算结果作为证明。ZA 输入前 128 字节是固定常量，可在生成脚本时预计算 SM3 中间状态。剩余两个压缩块以及 `SM3(ZA || H)` 的两个压缩块仍在脚本内执行。

标准 SM2 **消息签名接口**应传入消息 `H` 和用户标识 IDA。仅当设备明确提供 SM2 **预哈希签名接口**时，才传入 `e`；不得让设备对 e 再次计算 ZA 和 SM3。使用 SM3 是完整 SM2 签名方案的一部分；比特币交易摘要和收款公钥哈希仍保留 SHA256d 和 HASH160。

## SM2 验签条件

将签名解释为两个 32 字节大端整数 r、s，依次验证：

1. `1 <= r,s < n`。
2. `t = (r+s) mod n`，且 `t != 0`。
3. 计算 `R = sG + tQ`；拒绝无穷远点。
4. 验证 `r = (e + x(R)) mod n`。

脚本使用四位窗口和投影坐标运算。无需解锁方提供逆元。末步检查 `X = ((r-e) mod n) * Z mod p`，或者在第二候选小于 p 时检查 `X = (((r-e) mod n)+n) * Z mod p`。因为 `p < 2n`，两个候选完整覆盖坐标模 n 的情况。

保留签名原有的 `s` 值。按 ECDSA 的低 S 归一化规则把它替换为 `n - s`，可能使 SM2 签名失效。

模板 `3` 将中间投影坐标约减到 `(-p, p)` 内的有符号余数。点运算公式是域上的多项式，有符号余数和对应的非负余数表示同一个域元素。在这个范围内，以 `Z = 0` 判定无穷远点。最终等值检查使用 X、Z 的非负余数。

## 当前输入交易绑定

每个输入可独立选择摘要算法、输出覆盖范围和 ANYONECANPAY（ACP）。下表列出原生交易签名使用的十六进制类型字节。预映像末尾以四字节小端序编码该类型，高 24 位为零。Chronicle 在花费时启用 `0x20`，激活前创建的本模板输出也可以在激活后使用 OTDA。

| 输出覆盖范围 | BIP143 | 加 ACP | Chronicle OTDA | OTDA 加 ACP |
|---|---|---|---|---|
| ALL，全部输出 | `41` | `c1` | `61` | `e1` |
| NONE，输出可变 | `42` | `c2` | `62` | `e2` |
| SINGLE，配对输出 | `43` | `c3` | `63` | `e3` |

未设置 ACP 时，签名覆盖所有输入引用的前序输出。只有未设置 ACP 的 ALL 会覆盖其他输入的序列号。设置 ACP 时，签名在输入侧只覆盖当前输入。所有模式均绑定当前输入的输出引用和序列号，以及交易版本与锁定时间。

普通路径使用最后一个 `OP_CODESEPARATOR` 之后的 `ac` 作为 scriptCode。BIP143 预映像固定 158 字节，并纳入被花费输出的金额。

```text
versionLE32 || hashPrevouts || hashSequence || outpoint || 01ac ||
amountLE64 || sequenceLE32 || hashOutputs || locktimeLE32 || typeLE32
```

OTDA 按原始算法序列化所选输入和输出，再追加四字节签名类型。它省略前序输出金额。配对 SINGLE 在当前索引之前保留空输出占位 `ffffffffffffffff00`，开启 ACP 后仍然如此。

**SINGLE 没有同索引输出时**，常规 BIP143 使用全零 hashOutputs。原生 OTDA 返回常量 `uint256(1)`，单凭这个常量无法把所有者签名绑定到当前 UTXO。对于 `63` 和 `e3`，持有人分别对 `43` 和 `c3` 的 BIP143 补充预映像签名，保留原有 ACP 选择。该分支使用独立的 scriptCode `ad68abac`，并要求 hashOutputs 全零。脚本同时执行补充预映像的原生校验和原 OTDA 类型的常量摘要校验。替换当前输入引用的前序输出 或补上配对输出都会使原签名失效。

脚本不接收序列化的父交易。钱包可在链下使用完整父交易核对 txid、索引、金额与锁定脚本；节点从 UTXO 上下文获得实际被花费输出。收款人验证交易和需要的 SPV 证据后，可将交易发给矿工。此参考钱包不实现区块头跟踪或默克尔证明验证。

## 模板与见证

| 字段 | 字节数 / 位置 |
|---|---|
| 锁定脚本 | 144,925 字节 |
| 收款公钥哈希 | 零起点 `[168,188)`，20 字节 |
| P | 常规 BIP143 为 158 字节，普通 OTDA 随交易变化，无配对 OTDA SINGLE 为 161 字节 |
| Q | 65 字节，序列化后的入栈指令共 66 字节 |
| `r || s` | 64 字节，序列化后的入栈指令共 65 字节 |
| scriptSig | 包含三个栈项。常规 BIP143 为 291 字节，无配对 OTDA SINGLE 为 294 字节，其他 OTDA 为 `len(push(P)) + 131` 字节 |

识别锁定脚本时，需要逐字节核对收款哈希以外的程序内容。布局清单记录脚本长度、收款哈希偏移、全零收款哈希对应的脚本 SHA-256，以及固定字节的指纹。生成器支持原始字节和十六进制两种输出格式。[布局清单](../versions/v1.0.0/layout.json) · [脚本生成器](../reference/generate_lock.py)

## API 与拒绝条件

钱包可用以下 Python 接口生成脚本和签署交易。[接口源码](../reference/p2pkh_sm2.py)

- `locking_script_from_owner_hash(owner)` 付款方只持有收款哈希即可生成脚本。
- `locking_script_from_public_key(key)` 校验完整 SM2 公钥并生成脚本。
- `recognize(raw)` 检查完整固定程序，返回收款哈希或 `None`。
- `identify(raw)` 检查整个模板，返回模板版本 `1` 和所有者哈希。
- `sign_input(tx, index, funding_raw, key, signer, sighash_type, chronicle_active=active)` 核对当前输入引用的前序输出，按指定模式签署当前输入，保留其他输入已有的解锁脚本。调用者应提供花费时的激活状态。参数默认 `True`，传 `False` 时钱包会在调用签名器之前拒绝 OTDA。
- `current_input_unlock(tx, index, previous_amount, key, signature)` 验证当前输入 SM2 授权并编码见证。
- `sign_payment(funding_raw, vout, outputs, fee, key, signer)` 固定使用 `0x41`，核对父输出、密钥、金额及费用，调用 `signer(H, IDA)`，验证返回签名后组装交易。

调用者须确认父交易来源及确认状态，向签名设备展示或通过可信界面确认收款、找零和费用。Python 参考实现中的显式随机数签名函数用于复现测试向量。生产私钥的签名操作由外部签名器完成。

## 验证与实施边界

测试覆盖标准向量、OpenSSL SM2 消息签名、SM3 分块边界与固定前缀中间状态、曲线/标量错误、错误用户标识、t=0、无穷远点、极少出现的 x≥n 第二候选、伪造预映像及交易字段篡改。常规转付的三次连续测试中，每个输入的解锁脚本均为 291 字节。[16 个向量](../versions/v1.0.0/sighash-modes.json) 覆盖 12 种配对输入及 4 种无配对 SINGLE。

本地求值器用于检查生成器使用的操作码。完整输入测试在 BSV Node 1.2.3 和固定版本的 chain-gang 中运行，并显式指定 UTXO 与脚本验证标志。主网激活状态、转发策略、手续费和硬件集成取决于实际部署环境。[节点验证用例](../reference/test_node.py)

## 来源与致谢

- RFC 8998 说明 curveSM2 参数和 SM2 用户标识的语义。[RFC 8998 §3.2.1](https://www.rfc-editor.org/rfc/rfc8998.html#section-3.2.1)
- OpenSSL 测试套件收录了已发布的 SM2 测试向量。[OpenSSL 标准向量](https://github.com/openssl/openssl/blob/openssl-3.5.0/test/sm2_internal_test.c)
- SM3 互联网草案描述压缩函数和消息扩展。[SM3 互联网草案](https://datatracker.ietf.org/doc/html/draft-sca-cfrg-sm3-02)
- PUSHTX 使用公开的交易绑定构造。[nChain WP1605](https://nchain.com/wp-content/uploads/2022/03/WP1605_PUSHTX-and-its-Building-Blocks.pdf) · [BRC-21](https://github.com/bsv-blockchain/BRCs/blob/master/scripts/0021.md)
- R1 项目提供窗口式投影坐标运算和公开原生签名构造的基础。P2PKH-SM2 使用自身的曲线常量和签名方程。[P2PKH-R1](../../p2pkh-r1/README.md)
