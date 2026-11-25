# P2PKH-R1 钱包 SDK

[English](./sdk.en.md) · [线格式规范](./spec.zh-CN.md)

## 公开接口

应用可将三个 SDK 以源码集成。它们在本地运行，生成同一把锁、识别同一份字节，并对相同输入构造相同的普通付款。TS 面向 Node.js 24，Rust 和 Go 为原生库。签名回调可以连接设备适配层。

| 语言 | 创建与识别 | 普通付款 | 实现 |
|---|---|---|---|
| TypeScript | `lockForKey`, `lockForOwner`, `recognize` | `signPayment(payment, key, signDigest)` | [source](../sdk/typescript/index.ts) · [payment](../sdk/typescript/payment.ts) |
| Rust | `lock_for_key`, `lock_for_owner`, `recognize` | `payment::sign_payment(&payment, key, sign_digest)` | [source](../sdk/rust/src/lib.rs) · [payment](../sdk/rust/src/payment.rs) |
| Go | `LockForKey`, `LockForOwner`, `Recognize` | `SignPayment(payment, key, signDigest)` | [source](../sdk/go/template.go) · [payment](../sdk/go/payment.go) |

**收款。** 将 [template.hex](../template/template.hex) 去掉空白并解码为二进制，作为创建函数的第一个参数。第二个参数是 65 字节 R1 公钥或 20 字节 owner HASH160。函数校验固定程序、复制字节并替换所有者字段。识别函数只接受 raw scriptPubKey，成功时返回 20 字节哈希，调用方还应与预期收款人比较。模板固定字节、长度或 framing 不符时，TS 返回 null，Rust 返回 None，Go 返回 ok=false。本模板对未压缩公钥做 HASH160，接收压缩公钥的应用应先在本地验证并还原为 65 字节编码。

**付款。** 调用方负责取得可信 UTXO，或在本地核对父交易 txid、vout、金额及 scriptPubKey。SDK 接收其显示顺序的 32 字节 txid、vout、聪金额、锁定脚本、有序的新输出列表（含找零）、已批准的手续费及本次公钥。金额使用整数聪，TypeScript 使用 bigint。SDK 验证所有者、费用平衡和非负金额，构造一笔版本 2、单输入、最终 sequence、零 locktime 的交易，固定使用 BIP143 ALL。设备回调仅接收 32 字节摘要，返回 64 字节 r∥s。SDK 验证签名、计算逆元、写入 OP_0 并返回完整的已签交易字节。回调失败或签名无效时，调用方只收到错误。设备授权、nonce 安全及跨调用签名记录由签名服务负责。三种 SDK 均不发送交易。

混合输入或显式 NONE、SINGLE、ANYONECANPAY、OTDA 的应用，按协议层的输入授权接口构造每个输入。当前三种移植的高级付款接口仅提供上述普通路径。[Python 参考实现](../reference/wallet.py) 提供 `sign_spend(tx, index, parent, requested_type, pubkey, sign_digest, history_path)`。其他语言扩展该接口时，必须基于真实交易与前序输出生成消息，并从类型、输入索引、输出数量推导分支位。普通付款无需开放类型或分支开关。

构造子交易时，调用签名回调前先从应用的可信链视图取得已确认的父交易 outpoint，
并按应用要求的确认深度核对交易和输出的索引、金额及锁定脚本。
[未确认父交易](./chronicle.md#未确认父交易)

## 正则与完整指纹

1. 检查原始脚本恰为 **59,582 字节**。
2. 将前 **228 字节**编码为小写 hex，用以下正则匹配整个头部。捕获组 1 解码后是候选的 20 字节收款哈希。

```regex
^760052a569766b7c8201[0-9a-f]{396}([0-9a-f]{40})$
```

3. 在原始二进制上计算 `SHA256(script[0:208] || script[228:])`，必须等于 `2129d374594069d08a9b2127555f48ea21c75fb06d1ad5e77c68ad251e97f784`。只有这一步成功才返回捕获值。后缀即使只有一字节不同也会导致失败。对收款人做替换时，在已验证模板的副本上覆盖 `[208,228)`。[布局](../template/layout.json)

## 对接设备与复验

先用 [spend-all.json](../template/spend-all.json) 内的签名替代真实设备。回调收到的摘要须等于 digest_hex，返回 signature_hex。三个 SDK 必须产生向量中的解锁脚本及已签 txid。然后将同一个回调换成设备接口，让设备对指定摘要签名。设备生成另一份有效签名时，签名和 txid 可以不同。对 DER 签名先解析两个正整数，再填充为两个大端 32 字节数。若设备接口会自行做一次 SHA-256，适配层须使用支持相应消息输入的接口；绝不能将 SDK 给出的双哈希摘要再交给自动哈希的消息签名接口。

```sh
(cd projects/p2pkh-r1/sdk/typescript && npm install && npm run check && npm test)
(cd projects/p2pkh-r1/sdk/rust && cargo test)
(cd projects/p2pkh-r1/sdk/go && go test ./...)
```

三个包的测试覆盖 A/B/C 模板向量、公开点验证、固定字节变动、截断、追加以及普通付款签名回放、错误签名和错误手续费。测试不需要设备、网络节点或私钥。初次安装工具或依赖需要网络。完整节点差异测试见 [reference](../reference/README.md)。
