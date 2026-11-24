# Chronicle and P2PKH-R1-Deferred · 升级规则适用性

| Rule | Effect / 影响 |
|---|---|
| ForkID and OTDA | Genesis validates the six ForkID activation modes. Chronicle adds the six OTDA modes. 两者共用同一短锁。 |
| Transaction version | The Genesis vectors use version 1 and the Chronicle OTDA vectors use version 2. The activation bit is in the sighash byte and the node context decides availability. |
| `OP_CODESEPARATOR` | The required ForkID SINGLE preimage uses serialized scriptCode `01 ac` on the direct path or `04 ad 68 ab ac` on the two-check path. The selected auxiliary digest uses `01 ac`. |
| Relaxed unlocking rules | The reference always emits data pushes. The short lock verifies stack depth, the output-check preimage, and all required native signature results. |
| Missing paired output | ForkID SINGLE yields zero `hashOutputs`. The lock rejects zero, including in malformed funding commitments. 缺少同索引输出时拒绝启用。 |

The [conformance entry point](../reference/README.md) uses actual serialized inputs and explicit prevouts and flags. Its BSV Node tests check Genesis funding before and after Chronicle, and native rejection of OTDA before activation. The local chain-gang build verifies the twelve digest paths, but its height-aware interface also accepted OTDA in a pre-activation context. The BSV Node activation boundary remains an independent release check. Miner admission, policies and fees require separate measurements.
