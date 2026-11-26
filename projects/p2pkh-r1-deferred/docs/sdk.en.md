# P2PKH-R1-Deferred SDK integration

[简体中文](sdk.zh-CN.md)

<a name="quickstart"></a>

## Unified wallet API

Use `createLock` with the amount to build a short lock. Pass the output amount and raw script to recognition. Existing locks activate to their committed R1 version. Install the reference environment from the repository root.

```sh
python3.12 -m venv projects/p2pkh-r1-deferred/workspace/venv
projects/p2pkh-r1-deferred/workspace/venv/bin/python -m pip install -r projects/p2pkh-r1-deferred/reference/requirements.txt
```

Use authenticated transaction data. Set `config.python` to the absolute path of `projects/p2pkh-r1-deferred/workspace/venv/bin/python` and `config.bridge` to this checkout’s `sdk/python/bridge.py`. [Shared integration example](../../../sdk/docs/integration.md#first-payment)

```ts
import { WalletClient } from "./sdk/typescript/index.ts";

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

`activate` uses BIP143 SINGLE (`0x43`) by default and fills the selected input without a signing callback. Assemble the transaction first, placing the full R1 output at the same index and retaining the Deferred amount. Sign any fee-paying input separately. Use the ordinary R1 SDK to spend the resulting output.

Replay the vector in all four languages from the repository root.

```sh
SCRIPT_LAB_SDK_PYTHON="$PWD/projects/p2pkh-r1-deferred/workspace/venv/bin/python" \
  bash tools/verify_node.sh -- bash sdk/verify_wallet.sh p2pkh-r1-deferred
```

## Build the activation transaction

1. Authenticate the deposit UTXO and recognize it with its actual amount. Match the owner against the invoice and use the returned `targetTemplate`.
2. Build the complete R1 output for that owner at the full deposit amount. Place it at the same index as the activation input. Arrange fees with a separate sponsor input and finalize its change.
3. Call `activate` with the prepared transaction, input index and authenticated prevout. The default is BIP143 SINGLE (`0x43`). Other modes use the same-index target plus the parameters in the protocol specification. Sign the sponsor input separately.
4. Track the activated R1 outpoint and use the [R1 wallet integration](../../p2pkh-r1/docs/sdk.en.md) for later payments.

## Track the deposit and the activated outpoint

Store the short-lock outpoint, value, owner and `targetTemplate` with the invoice. When building a batch, freeze the mapping from each activation input to its same-index R1 output before assembling any unlock. The output preserves the complete deposit amount, so a separate input supplies the fee. The sponsor approves the transaction and signs its own input.

After confirmation, record the final activation txid and output index as the new R1 outpoint. If broadcast is delayed or a reorganization changes the parent, reconcile the short-lock and activated outpoints in the wallet's chain view before creating a child payment. [R1 spending workflow](../../p2pkh-r1/docs/sdk.en.md#quickstart)

[Activation specification](spec.en.md) · [Twelve-mode vectors](../template/v0.2.0/sighash-modes.json) · [Reference transaction construction](../reference/README.md)
