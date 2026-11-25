# Pure ML-DSA-44 wallet SDK

[简体中文](README.zh-CN.md) · [Developer guide](../docs/developer.en.md#sdk) · [Wallet quickstart](../../../shared/sdk/README.md)

Use the expected 1,312-byte public key to create and recognize the lock. Pass the exact 32-byte payload as the message to Pure ML-DSA-44 with an empty context. The signature is 2,420 bytes. The SDK verifies it before assembling the unlocking script. Public fixture generation needs OpenSSL 3.5 or later. Set `ML_DSA_OPENSSL` if your executable is outside PATH.

## Sign a payment

The runtime uses the Python 3.12 standard library. The replay needs the test dependencies below.

Use the quickstart's bridge configuration and approved wallet data. Create a receiving script and prepare a payment with the same client.

```ts
import { WalletClient } from "./shared/sdk/typescript/index.ts";

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

Use `signInput` for a prepared transaction. Supply the transaction, its input index and the corresponding prevout. See the [call table](../../../shared/sdk/README.md#calls-and-data) for the matching Rust, Go, and Python interfaces.

## Replay vectors

```sh
.venv/bin/python -m pip install -r shared/requirements-chronicle.txt
SCRIPT_LAB_SDK_PYTHON="$PWD/.venv/bin/python" \
  bash shared/verify_node.sh -- bash shared/sdk/verify_wallet.sh ml-dsa
```

## Existing project-specific entry points

| Language | Source and entry point |
|---|---|
| TypeScript | [index.ts](typescript/index.ts) · `createClient` |
| Rust | [Cargo.toml](rust/Cargo.toml) · `bsv_script_lab_mldsa_sdk::client` |
| Go | [go.mod](go/go.mod) · `New` |
| Python | [Client entry](python/__init__.py) · `create_client` |
