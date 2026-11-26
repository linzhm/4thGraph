# Pure ML-DSA-44 wallet SDK

[简体中文](sdk.zh-CN.md) · [Developer guide](developer.en.md#sdk) · [Wallet quickstart](../../../sdk/README.md)

Use the expected 1,312-byte public key to create and recognize the lock. Pass the exact 32-byte payload as the message to Pure ML-DSA-44 with an empty context. The signature is 2,420 bytes. The SDK verifies it before assembling the unlocking script. Public fixture generation needs OpenSSL 3.5 or later. Set `ML_DSA_OPENSSL` if your executable is outside PATH.

<a name="quickstart"></a>

## Sign a payment

The runtime uses the Python 3.12 standard library. The replay needs the test dependencies below.

Use the quickstart's bridge configuration and approved wallet data. Create a receiving script and prepare a payment with the same client.

```ts
import { WalletClient } from "./sdk/typescript/index.ts";

const wallet = new WalletClient("ml-dsa", { ...config, template: "pure-ml-dsa-44" });
const receiveScript = wallet.createLock({ publicKey: receiveKeyHex });
const prevout = wallet.prevoutFromFunding(fundingTxHex, fundingVout);
const recognized = wallet.recognize({ script: prevout.script, publicKey: spendKeyHex });
if (!recognized) throw new Error("Funding output does not match the spending key");

const signedHex = wallet.signPayment({
  prevout,
  publicKey: spendKeyHex,
  outputs: approvedOutputs,
  feeSats: approvedFeeSats.toString(),
}, ({ payload }) => signer.signPureMlDsa44(payload, new Uint8Array()));
```

Use `signInput` for a prepared transaction. Supply the transaction, its input index and the corresponding prevout. See the [call table](../../../sdk/README.md#calls-and-data) for the matching Rust, Go, and Python interfaces.

## Verify a signer before funding

Use the raw 1,312-byte ML-DSA-44 public key from your signer when creating and recognizing the lock. Pass the 32-byte SDK payload as the message to Pure ML-DSA-44 with an empty context. Confirm that the provider returns the raw 2,420-byte signature. A deliberately changed payload should fail the integration test.

Start with the offline example to check message handling. Then replay the payment through both engines and verify a funded spend separately under the target script-size and validation policy. Lock size depends on the public-key fixture, so measure with the actual receive key. [Funded regtest guide](../../../docs/benchmark.md#funded-regtest-measurements)

## Replay vectors

```sh
.venv/bin/python -m pip install -r tools/requirements-chronicle.txt
SCRIPT_LAB_SDK_PYTHON="$PWD/.venv/bin/python" \
  bash tools/verify_node.sh -- bash sdk/verify_wallet.sh ml-dsa
```
