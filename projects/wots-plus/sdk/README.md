# WOTS+ wallet SDK

[简体中文](README.zh-CN.md) · [Developer guide](../docs/developer.en.md#sdk) · [Wallet quickstart](../../../shared/sdk/README.md)

Select `canonical` (default), `cached-constants`, or `cached-steps`. Supply the expected 64-byte public key to recognize a receive script. The signer receives a 32-byte digest and returns a 2,144-byte signature. Persist one-time key consumption before releasing the signature, use a fresh key for change, and keep the signed transaction for retries. With Chronicle active, `compressOtda: true` enables eligible compact unlocks in version-2 transactions.

## Sign a payment

The runtime uses the Python 3.12 standard library. The replay needs the test dependencies below.

Use the quickstart's bridge configuration and approved wallet data. Create a receiving script and prepare a payment with the same client.

```ts
import { WalletClient } from "./shared/sdk/typescript/index.ts";

const wallet = new WalletClient("wots-plus", { ...config, template: "cached-steps" });
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

Use `signInput` for a prepared transaction. Supply the transaction, its input index and the corresponding prevout. See the [call table](../../../shared/sdk/README.md#calls-and-data) for the matching Rust, Go, and Python interfaces.

## Replay vectors

```sh
.venv/bin/python -m pip install -r projects/wots-plus/reference/requirements.txt
SCRIPT_LAB_SDK_PYTHON="$PWD/.venv/bin/python" \
  bash shared/verify_node.sh -- bash shared/sdk/verify_wallet.sh wots-plus
```

## Existing project-specific entry points

| Language | Source and entry point |
|---|---|
| TypeScript | [index.ts](typescript/index.ts) · `createClient` |
| Rust | [Cargo.toml](rust/Cargo.toml) · `bsv_script_lab_wots_sdk::client` |
| Go | [go.mod](go/go.mod) · `New` |
| Python | [Client entry](python/__init__.py) · `create_client` |
