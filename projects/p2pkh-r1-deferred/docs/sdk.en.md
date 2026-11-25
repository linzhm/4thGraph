# P2PKH-R1-Deferred SDK integration

[简体中文](sdk.zh-CN.md)

## Unified wallet API

Use `createLock` with the amount to build a short lock. Pass the output amount and raw script to recognition. Existing locks activate to their committed R1 version. Install the reference environment from the repository root.

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r projects/p2pkh-r1-deferred/reference/requirements.txt
```

Use `config` from the [wallet quickstart](../../../shared/sdk/README.md) and authenticated wallet data.

```ts
import { WalletClient } from "./shared/sdk/typescript/index.ts";

const deferred = new WalletClient("p2pkh-r1-deferred", { ...config, template: "v0.2.0" });
const shortLock = deferred.createLock({ publicKey: receiveKeyHex, valueSats });
const prevout = deferred.prevoutFromFunding(fundingTxHex, fundingVout);
const commitment = deferred.recognize({
  script: prevout.script, valueSats: prevout.valueSats, publicKey: spendKeyHex,
});
if (!commitment) throw new Error("Unrecognized Deferred output");

const r1 = new WalletClient("p2pkh-r1", { ...config, template: commitment.targetTemplate });
const targetScript = r1.createLock({ publicKey: spendKeyHex });
// Put { script: targetScript, valueSats: prevout.valueSats } at inputIndex in the
// approved transaction's output list and include any needed fee-paying input.
const activatedHex = deferred.activate({ transaction: preparedHex, inputIndex, prevout });
```

`activate` uses ForkID SINGLE (`0x43`) by default and fills the selected input without a signing callback. Assemble the transaction first, placing the full R1 output at the same index and retaining the Deferred amount. Sign any fee-paying input separately. Use the ordinary R1 SDK to spend the resulting output.

Replay the vector in all four languages from the repository root.

```sh
SCRIPT_LAB_SDK_PYTHON="$PWD/.venv/bin/python" \
  bash shared/verify_node.sh -- bash shared/sdk/verify_wallet.sh p2pkh-r1-deferred
```

## Existing source SDKs

All three source SDKs use the [deferred template](../template/v0.2.0/template.hex) and the [R1 v0.2.0 template](../../p2pkh-r1/template/v0.2.0/template.hex). Strip whitespace from the `.hex` files and decode the raw bytes starting at the first opcode. Amounts are integer satoshis. TypeScript uses `bigint`, Rust uses `u64`, and Go uses `int64`.

Recognize and activate an existing short lock with the R1 version it originally committed to. v0.1.0 funding activates to its v0.1.0 target. [v0.1.0 R1 template](../../p2pkh-r1/template/template.hex)

| Operation | TypeScript | Rust | Go |
|---|---|---|---|
| Construct from the key hash | `lockForOwner` | `lock_for_owner` | `LockForOwner` |
| Construct from the full key | `lockForKey` | `lock_for_key` | `LockForKey` |
| Recognize the complete script | `recognize` | `recognize` | `Recognize` |
| Encode the activation unlocking script | `activationWitness` | `activation_witness`, `activation_witness_with_digest` | `ActivationWitness` |

Construction takes both templates, the recipient key hash or full key, and the amount. Both constructors encode the 20-byte key hash. Recognition takes the R1 template, actual short lock, and actual amount. It reconstructs the full script before returning the validated key hash, target script SHA-256, and target output HASH256. The legacy format also yields its embedded public key. The receiving wallet checks the expected key hash and amount against its invoice.

Finalize the paired inputs and outputs, fee inputs, and change. The builder constructs a ForkID SINGLE preimage from the actual transaction and authenticated previous output. Pass only this preimage for a direct `0x43` or `0xc3` activation. For other modes, also pass the 33-byte `typeByte || HASH256(selectedPreimage)` and use the two-check scriptCode in the specification for the paired preimage. The helper validates the preimage fields and sighash combination before encoding the pushes. See the [Python reference](../reference/README.md) for complete transaction construction. Use the [ordinary R1 SDK](../../p2pkh-r1/docs/sdk.en.md) and its external signer callback for the activated output.

Run `npm test`, `cargo test`, or `go test ./...` in the corresponding SDK directory. Each suite replays the [generation and recognition vectors](../template/v0.2.0/layout.json) and the [twelve activation modes](../template/v0.2.0/sighash-modes.json).
