# Lamport OTS wallet SDK

[简体中文](README.zh-CN.md) · [Developer guide](../docs/developer.en.md#sdk) · [Wallet quickstart](../../../shared/sdk/README.md)

Choose `full-key` (default) or `committed-key` for receiving and pass the complete ordered public key to recognition. The SDK can also recognize legacy outputs, whose spending mode is ForkID ALL. The signer receives a 32-byte digest and returns an 8,192-byte signature. Have the signer durably consume the key before releasing a signature. Use a fresh key for change and keep the signed transaction for retries.

## Sign a payment

The runtime uses the Python 3.12 standard library. The replay needs the test dependencies below.

Use the quickstart's bridge configuration and approved wallet data. Create a receiving script and prepare a payment with the same client.

```ts
import { WalletClient } from "./shared/sdk/typescript/index.ts";

const wallet = new WalletClient("lamport-ots", { ...config, template: "full-key" });
const receiveScript = wallet.createLock({ publicKey: receiveKeyHex });
const prevout = wallet.prevoutFromFunding(fundingTxHex, fundingVout);
const recognized = wallet.recognize({ script: prevout.script, publicKey: spendKeyHex });
if (!recognized) throw new Error("Funding output does not match the spending key");

const signedHex = wallet.signPayment({
  prevout,
  publicKey: spendKeyHex,
  outputs: approvedOutputs,
  feeSats: approvedFeeSats.toString(),
}, ({ payload }) => signer.signLamportOnce(keyId, payload));
```

Use `signInput` for a prepared transaction. Supply the transaction, its input index and the corresponding prevout. See the [call table](../../../shared/sdk/README.md#calls-and-data) for the matching Rust, Go, and Python interfaces.

## Replay vectors

```sh
.venv/bin/python -m pip install -r projects/lamport-ots/reference/requirements.txt
SCRIPT_LAB_SDK_PYTHON="$PWD/.venv/bin/python" \
  bash shared/verify_node.sh -- bash shared/sdk/verify_wallet.sh lamport-ots
```

## Existing project-specific entry points

| Language | Source and entry point |
|---|---|
| TypeScript | [index.ts](typescript/index.ts) · `createClient` |
| Rust | [Cargo.toml](rust/Cargo.toml) · `bsv_script_lab_lamport_sdk::client` |
| Go | [go.mod](go/go.mod) · `New` |
| Python | [Client entry](python/__init__.py) · `create_client` |
