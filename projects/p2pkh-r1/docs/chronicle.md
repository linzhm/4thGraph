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
the txid while preserving the input references, ordered outputs, and payment
authorization. Any replacement that confirms with a different txid has the
same effect on a child referencing the original `txid:vout`. If the replacement
also changes transaction contents, verify that it still makes the intended
payment before treating any of its outputs as the wallet's funding.
[Transaction serialization](../../../shared/transaction.py)

Versions that spend the same inputs compete for those UTXOs. First-seen handling
and double-spend notifications are useful while monitoring pending payments.
Nodes can receive the versions in a different order. The wallet's verified
chain view determines which version confirmed.
[BSV Node conflict detection](https://github.com/bitcoin-sv/bitcoin-sv/blob/v1.2.3/src/validation.cpp#L1380-L1389)
· [ARC transaction statuses](https://github.com/bitcoin-sv/arc#metamorph-transaction-statuses)

The ordinary SDK produces version-2 ForkID transactions. With Chronicle active,
the native encoding restrictions depend on the transaction version and the
applicable flags. Native LOW_S checks apply to the secp256k1 binder. The R1
owner signature is checked separately by the template's P-256 arithmetic.
[Chronicle release](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release)
· [BSV Node 1.2.3 interpreter](https://github.com/bitcoin-sv/bitcoin-sv/blob/v1.2.3/src/script/interpreter.cpp#L31-L44)

When functional unlocking is permitted, distinct unlocking scripts can leave
the same stack for the lock. Stack-field checks constrain those values, and
the txid includes the full unlocking script. When the node enforces push-only
unlocking, it rejects non-push opcodes. With Chronicle active, BSV Node 1.2.3
limits that push-only check to transaction versions up to 1 when the flag is set.
[BSV Node 1.2.3 script validation](https://github.com/bitcoin-sv/bitcoin-sv/blob/v1.2.3/src/script/interpreter.cpp#L2120-L2159)

P-256 low-S and byte-exact selector checks would narrow these fields in a new
template. Added lock checks change the template fingerprint and require
versioned recognition and separately funded outputs. Stable unconfirmed txids
also depend on the accepted encoding of every input in the complete
transaction, including inputs using other templates.

### Recovering a child payment

1. Locate the confirmed parent in a trusted chain view. Track the original
   inputs or known competing txids to find the confirmed version. Apply the
   application's confirmation threshold and check that the expected output
   index, amount, and locking script identify an unspent output.
2. Update the wallet's recorded outpoint. If it changed, mark the dependent
   child and its descendants stale. A child signed for the old outpoint
   cannot be carried over to the confirmed one.
3. If the wallet still controls the output, rebuild the child with the
   confirmed outpoint. Use the normal R1 signer to authorize the new
   transaction and generate its unlocking script. Reconcile any business
   action already taken on the stale branch before rebuilding descendants.

A wallet that accepts zero-confirmation chaining should treat those spends
as provisional and account for rebuilds. Apply the confirmation policy
before treating the payment as settled for an irreversible business action.
Recheck the outpoint in the trusted chain view after a reorganization.

### 未确认父交易

对于已发布的 R1 模板和优化模板，未确认的父交易 txid 都应视为暂定值。
计算 txid 时会哈希完整交易的序列化结果，其中包含解锁脚本的原始字节。
ForkID 和 OTDA 摘要约束的是所选签名类型承诺的交易字段。
如果规则接受另一种解锁编码，第三方可以在保留这些字段授权的情况下改变 txid。
纯解锁脚本变体保留输入引用和有序输出。任何以不同 txid 确认的替代交易，
都会使原先子交易引用的 `txid:vout` 失效。若替代交易还改动了交易内容，
应先核对它是否仍完成预期付款。

花费同一批输入的版本争用这些 UTXO。钱包可以用首见信息和双花通知监控待确认交易。
不同节点可能先收到不同版本，钱包应以可信链视图中的确认结果为准。

允许功能型解锁脚本时，不同的脚本字节可以给锁留下相同的栈。锁内的字段检查只能
约束栈里的值，计算 txid 时仍会计入完整的解锁脚本。节点执行 push-only 规则时，
带非 push 指令的解锁脚本会被拒绝。Chronicle 生效后，BSV Node 1.2.3 在设置该
标志的情况下仅对版本不高于 1 的交易执行这项检查。

普通 SDK 生成版本 2 的 ForkID 交易。Chronicle 生效后的原生编码约束取决于交易版本
和适用的 flags。原生 LOW_S 检查作用于 secp256k1 绑定签名，R1 持有人的签名由
模板内的 P-256 算术另行验证。若新增 P-256 low-S 和分支字段字节约束，应另发
带独立指纹的新模板，并为其创建新输出。整笔交易的 txid 稳定性还取决于每个输入
接受的解锁编码。

#### 恢复子交易

1. 通过原父交易的输入或已知的冲突 txid，在可信链视图中找到实际确认的版本。
   按应用的确认策略检查确认深度，核对输出索引、金额和锁定脚本，并确认该输出仍未花费。
2. 更新钱包记录的 outpoint。如果 outpoint 变了，将依赖旧 outpoint 的子交易及其后续
   交易标为失效。旧子交易的授权无法迁移到实际确认的 outpoint。
3. 如果钱包仍控制该输出，用实际确认的 outpoint 重建子交易，通过正常的 R1 签名流程
   授权新交易并生成解锁脚本。继续重建后续交易前，先核对曾依据旧交易链触发的业务动作。

支持零确认续花的钱包应将这些花费作为暂定状态，并考虑重建成本。对于不可逆的业务动作，
应先按应用的确认策略核对付款是否已达到结算条件。链重组后，应在可信链视图中重新核对 outpoint。
