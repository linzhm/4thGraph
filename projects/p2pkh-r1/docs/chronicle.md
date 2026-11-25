# Chronicle and P2PKH-R1 · 升级规则适用性

协议只要求签名与锁实际执行的分支一致。下表区分当前模板的要求和可选优化。The table describes this template's dependency on each rule. Engine behavior must be checked against a specific revision, activation context, spend version and verification flags.

| Rule | Effect on the current template / 对当前模板的影响 |
|---|---|
| Executed OP_CODESEPARATOR and two-phase evaluation | **Required for correct digests.** Ordinary scriptCode is `68ac`. Companion BIP143 scriptCode is `63ad67ab68ac` and retains the unexecuted separator. 两个无配对 OTDA SINGLE 是完整花费的关键回归用例。 |
| Functional opcodes in scriptSig | The wallet emits four data pushes and one constant opcode. Native two-phase support is useful for validation. The current format gains no bytes from executing calculations in scriptSig. 当前解锁栈直接传值，功能型解锁脚本不属于本模板的生成规则。 |
| MINIMALDATA | Wallets use the specified push encodings. The 32-byte inverse is carried as bytes and converted for arithmetic inside the lock. 放宽编码要求本身不会缩小当前规范编码。 |
| LOW_S | Device signatures are raw R1 scalars checked by the R1 verifier. Native CHECKSIG uses a separate, publicly constructed k1 signature, which the ordinary binder normalizes. 原生 k1 的 low-S 策略不决定设备 R1 签名的有效范围。 |
| NULLFAIL | A valid payment expects native signature checks to succeed. A failed required authorization must fail the spend. 放宽失败签名限制不会帮助合法花费通过。 |
| NULLDUMMY | The template does not execute CHECKMULTISIG. 模板没有多签 dummy 项。 |
| MINIMALIF | The wallet writes OP_0 or OP_1. 锁验证分支值；规范生成的分支位已经是最小编码。 |
| CLEANSTACK | The canonical witness and verifier have a defined stack shape. A relaxed final-stack policy does not reduce the witness. 不能仅凭 CLEANSTACK 放宽就删去内部栈清理，算术块还用栈深定位数据。 |

For acceptance, use the actual transaction checker on a complete spend. Preserve the distinction between consensus flags, policy flags and debugger behavior. The full-node test uses explicit flags in isolated regtest, so it measures input validation under those flags. Network relay and miner acceptance require separate evidence. 节点的显式 flags 输入测试不会自动证明各矿工对交易的接纳策略。[Chronicle release](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release) · [Lock](../reference/asm/lock.asm) · [Binding](../reference/asm/binding.asm) · [Arithmetic](../reference/asm/r1.asm)

## Unconfirmed parent txids

Treat an unconfirmed parent txid as provisional for both the canonical and
optimized R1 templates. The txid hashes the entire serialized transaction,
including each unlocking script.
The ForkID and OTDA signing digests bind the selected transaction fields.
Where the rules accept an alternate witness encoding, a third party can change
the txid while preserving that authorization. A child referencing the earlier
txid cannot spend the output under the txid that confirms.
[Transaction serialization](../../../shared/transaction.py)

The ordinary SDK produces version-2 ForkID transactions. With Chronicle active,
the native encoding restrictions depend on the transaction version and the
applicable flags. Native LOW_S checks apply to the secp256k1 binder. The R1
owner signature is checked separately by the template's P-256 arithmetic.
[Chronicle release](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release)
· [BSV Node 1.2.3 interpreter](https://github.com/bitcoin-sv/bitcoin-sv/blob/v1.2.3/src/script/interpreter.cpp#L31-L44)

Before signing a child that depends on this output, use a trusted chain view
to apply the application's confirmation threshold and verify the confirmed
txid, output index, amount, and lock. Derive the child's signing digest from
that outpoint.

P-256 low-S and byte-exact selector checks would narrow these fields in a
new template. Added lock checks change the template fingerprint and require
versioned recognition and separately funded outputs. Stable unconfirmed txids
also depend on the accepted encoding of every input in the complete
transaction, including inputs using other templates.

### 未确认父交易

对于已发布的 R1 模板和优化模板，未确认的父交易 txid 都应视为暂定值。
计算 txid 时会哈希完整交易的序列化结果，其中包含解锁脚本的原始字节。
ForkID 和 OTDA 摘要约束的是所选签名类型承诺的交易字段。
如果规则接受另一种解锁编码，第三方可以在保留这些字段授权的情况下改变 txid。
原先的子交易引用的 outpoint 将无法花费实际确认的输出。签署子交易前，应从可信链视图
核对父交易达到应用规定的确认深度，再用确认的 txid、vout、金额和锁构造花费。

普通 SDK 生成版本 2 的 ForkID 交易。Chronicle 生效后的原生编码约束取决于交易版本
和适用的 flags。原生 LOW_S 检查作用于 secp256k1 绑定签名，R1 持有人的签名由
模板内的 P-256 算术另行验证。若新增 P-256 low-S 和分支字段字节约束，应另发
带独立指纹的新模板，并为其创建新输出。整笔交易的 txid 稳定性还取决于每个输入
接受的解锁编码。
