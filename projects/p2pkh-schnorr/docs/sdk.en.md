# P2PKH-Schnorr wallet SDK

[简体中文](sdk.zh-CN.md) · [Project overview](../README.md) · [Unified wallet SDK](../../../shared/sdk/README.md)

<a name="quickstart"></a>

## Receive and spend

Select project `p2pkh-schnorr` and template `v0.1.0` in the unified SDK. Supply a 32-byte x-only public key or its 20-byte HASH160 to create a receive script. The client loads the frozen template and fills the owner slot. For recognition, supply the actual output script and optionally the expected public key.

The signing request identifies the algorithm as `schnorr-secp256k1`, the payload kind as `message`, and the signature format as `bip340`. Give the 32-byte payload to the BIP340 signer as the message. Return the signer's original 64 bytes. The SDK verifies the signature and derives the public witness coordinates.

The TypeScript call below uses approved wallet data and the bridge configuration from the shared quickstart. Point the bridge at the Python interpreter in `.venv/p2pkh-schnorr` when using the project environment. The wallet authenticates the funding outpoint and approves payment outputs and fee before this call. [Bridge setup](../../../shared/sdk/README.md#quickstart)

```ts
import { WalletClient } from "./shared/sdk/typescript/index.ts";

const wallet = new WalletClient("p2pkh-schnorr", { ...config, template: "v0.1.0" });
const receiveScript = wallet.createLock({ publicKey: receiveKeyHex });
const prevout = wallet.prevoutFromFunding(fundingTxHex, fundingVout);
if (!wallet.recognize({ script: prevout.script, publicKey: spendKeyHex })) {
  throw new Error("Funding output does not match the Schnorr key");
}
const signedHex = wallet.signPayment({
  prevout,
  publicKey: spendKeyHex,
  outputs: approvedOutputs,
  feeSats: approvedFeeSats.toString(),
}, ({ payload }) => signer.signBip340(payload));
```

For a prepared transaction, use `signInput` and supply the current input index and its authenticated prevout. For Chronicle OTDA, supply `chronicleActive` from the actual chain context. SINGLE requires a same-index output. The same methods are available in Python, Rust, and Go. [Shared API table](../../../shared/sdk/README.md#calls-and-data)

## Replay with public keys and fixtures

Install the project requirements shown on the project overview, then run the offline example. Its public keys and auxiliary randomness are test data.

```sh
.venv/p2pkh-schnorr/bin/python -m shared.sdk.examples.receive_and_pay p2pkh-schnorr
SCRIPT_LAB_SDK_PYTHON="$PWD/.venv/p2pkh-schnorr/bin/python" \
  bash shared/verify_node.sh -- bash shared/sdk/verify_wallet.sh p2pkh-schnorr
```

[Setup and acceptance scope](../README.md#validate-the-baseline)
