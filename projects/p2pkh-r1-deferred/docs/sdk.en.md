# P2PKH-R1-Deferred SDK integration

[简体中文](sdk.zh-CN.md)

<a name="quickstart"></a>

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

## Build the activation transaction

1. Authenticate the deposit UTXO and recognize it with its actual amount. Match the owner against the invoice and use the returned `targetTemplate`.
2. Build the complete R1 output for that owner at the full deposit amount. Place it at the same index as the activation input. Arrange fees with a separate sponsor input and finalize its change.
3. Call `activate` with the prepared transaction, input index and authenticated prevout. The default is ForkID SINGLE (`0x43`). Other modes use the same-index target plus the parameters in the protocol specification. Sign the sponsor input separately.
4. Track the activated R1 outpoint and use the [R1 wallet integration](../../p2pkh-r1/docs/sdk.en.md) for later payments.

[Activation specification](spec.en.md) · [Twelve-mode vectors](../template/v0.2.0/sighash-modes.json) · [Reference transaction construction](../reference/README.md)
