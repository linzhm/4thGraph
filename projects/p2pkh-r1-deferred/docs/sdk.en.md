# P2PKH-R1-Deferred SDK integration

[简体中文](sdk.zh-CN.md)

All three source SDKs use the [deferred template](../template/template.hex) and the [canonical R1 template](../../p2pkh-r1/template/template.hex). Strip whitespace from the `.hex` files and decode the raw bytes starting at the first opcode. Amounts are integer satoshis. TypeScript uses `bigint`, Rust uses `u64`, and Go uses `int64`.

| Operation | TypeScript | Rust | Go |
|---|---|---|---|
| Construct from the key hash | `lockForOwner` | `lock_for_owner` | `LockForOwner` |
| Construct from the full key | `lockForKey` | `lock_for_key` | `LockForKey` |
| Recognize the complete script | `recognize` | `recognize` | `Recognize` |
| Encode the activation unlocking script | `activationWitness` | `activation_witness`, `activation_witness_with_digest` | `ActivationWitness` |

Construction takes both templates, the recipient key hash or full key, and the amount. Both constructors encode the 20-byte key hash. Recognition takes the R1 template, actual short lock, and actual amount. It reconstructs the full script before returning the validated key hash, target script SHA-256, and target output HASH256. The legacy format also yields its embedded public key. The receiving wallet checks the expected key hash and amount against its invoice.

Finalize the paired inputs and outputs, fee inputs, and change. The builder constructs a ForkID SINGLE preimage from the actual transaction and authenticated previous output. Pass only this preimage for a direct `0x43` or `0xc3` activation. For other modes, also pass the 33-byte `typeByte || HASH256(selectedPreimage)` and use the two-check scriptCode in the specification for the paired preimage. The helper validates the preimage fields and sighash combination before encoding the pushes. See the [Python reference](../reference/README.md) for complete transaction construction. Use the [ordinary R1 SDK](../../p2pkh-r1/docs/sdk.en.md) and its external signer callback for the activated output.

Run `npm test`, `cargo test`, or `go test ./...` in the corresponding SDK directory. Each suite replays the [generation and recognition vectors](../template/layout.json) and the [twelve activation modes](../template/sighash-modes.json).
