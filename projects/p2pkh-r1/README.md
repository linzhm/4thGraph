# P2PKH-R1

[BSV Script Lab](../../README.md) · First public script project / 首个公开脚本项目

A BSV payment script for a secp256r1 (P-256) public-key hash. The recipient signs the current input once. The unlocking script carries the signing preimage, public key, signature, verified inverse and a derived branch opcode. An ordinary ForkID ALL spend uses a 59,582-byte output script and a 326-byte unlocking script.

P2PKH-R1 允许付款人只凭 R1 公钥哈希创建输出。普通付款固定使用 ALL，签名器只签一次当前输入的摘要。解锁数据的大小与历史转付次数无关。

| Developer resource | 中文 | English |
|---|---|---|
| Script template, wire format and signing rules | [协议规范](docs/spec.zh-CN.md) | [Specification](docs/spec.en.md) |
| TypeScript, Rust and Go wallet integration | [SDK 接入](docs/sdk.zh-CN.md) | [SDK guide](docs/sdk.en.md) |
| Compiled script sizes and test settings | [sCrypt 体积对照](docs/scrypt-comparison.md) | [sCrypt comparison](docs/scrypt-comparison.md) |
| Consensus and policy considerations | [Chronicle 规则](docs/chronicle.md) | [Chronicle rules](docs/chronicle.md) |

The [binary layout and generation vectors](template/layout.json) define recognition. The [payment vector](template/spend-all.json) supplies a digest, fixed test signature, unlocking bytes and signed txid for offline replay. The canonical template, layout vector C and the payment vector share a public test key. Outputs using that key are for local tests only. Source SDKs support output generation, owner recognition and ordinary single-input payments. The [reference wallet and assembly](reference/README.md) also cover mixed inputs and Chronicle OTDA.

The Python reference wallet offers an opt-in 47,510-byte template with the full ForkID and OTDA signing modes, prebuilt lock bytes and optional OTDA witness compression. [Optimized template and measurements](reference/README.md#optimized-full-mode-template)

**Status** · v0.1 development baseline. Developer RFC, with no assigned BRC number. The [reference tests](reference/README.md) use the fork's pinned OTDA fix. Physical-device validation and independent security review remain open.
