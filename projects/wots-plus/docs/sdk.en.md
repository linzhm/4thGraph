# WOTS+ wallet SDK

[简体中文](sdk.zh-CN.md) · [Developer guide](developer.en.md#sdk) · [Wallet quickstart](../../../sdk/README.md)

Select `canonical` (default), `cached-constants`, `cached-steps`, `compact`, `compact-v2`, or `compact-v3`. Supply the expected 64-byte public key to recognize a receive script. The signer receives a 32-byte digest and returns a 2,144-byte signature. Persist one-time key consumption before releasing the signature, use a fresh key for change, and keep the signed transaction for retries. With Chronicle active, `compressOtda: true` enables eligible reconstructed unlocks in version-2 transactions.

<a name="quickstart"></a>

## Sign a payment

The runtime uses the Python 3.12 standard library. The replay needs the test dependencies below.

Create the Python environment for the bridge from the repository root.

```sh
python3.12 -m venv projects/wots-plus/workspace/venv
```

Use authenticated transaction data. Set `config.python` to the absolute path of `projects/wots-plus/workspace/venv/bin/python` and `config.bridge` to this checkout’s `sdk/python/bridge.py`. [Shared integration example](../../../sdk/docs/integration.md#first-payment)

```ts
import { WalletClient } from "./sdk/typescript/index.ts";

const wallet = new WalletClient("wots-plus", { ...config, template: "compact-v3" });
const receiveScript = wallet.createLock({ publicKey: receiveKeyHex });
const prevout = wallet.prevoutFromFunding(fundingTxHex, fundingVout);
const recognized = wallet.recognize({ script: prevout.script, publicKey: spendKeyHex });
if (!recognized) throw new Error("Funding output does not match the spending key");

const signedHex = wallet.signPayment({
  prevout,
  publicKey: spendKeyHex,
  outputs: approvedOutputs,
  feeSats: approvedFeeSats.toString(),
}, ({ payload }) => signer.signWotsOnce(keyId, payload));
```

Use `signInput` for a prepared transaction. Supply the transaction, its input index and the corresponding prevout. See the [call table](../../../sdk/docs/reference.md#calls-and-data) for the matching Rust, Go, and Python interfaces.

## Choose a receive template and rehearse a retry

For a version-2 Chronicle transaction that creates eligible compact or `cached-steps` outputs, set `compressOtda: true` to test reconstruction. Retain the canonical 64-byte public key for each output. [Template measurements](../README.md#compact-profile)

Use a durable signer and a fresh key for each output. For a broadcaster retry, replay the stored transaction bytes. A different transaction needs a fresh authorization, so check key consumption before requesting it. Test that a second signing request for the same key is blocked across process restarts. [Durable signer reference](../../../src/fourthgraph/bsv/one_time_signer.py)

## Replay vectors

```sh
projects/wots-plus/workspace/venv/bin/python -m pip install -r projects/wots-plus/reference/requirements.txt
SCRIPT_LAB_SDK_PYTHON="$PWD/projects/wots-plus/workspace/venv/bin/python" \
  bash tools/verify_node.sh -- bash sdk/verify_wallet.sh wots-plus
```
