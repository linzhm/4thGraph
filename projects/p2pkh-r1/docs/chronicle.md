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
