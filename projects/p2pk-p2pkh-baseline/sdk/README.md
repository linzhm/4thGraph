# Native P2PK and P2PKH wallet SDK

[简体中文](README.zh-CN.md) · [Developer guide](../docs/developer.en.md#sdk) · [Wallet quickstart](../../../shared/sdk/README.md)

Pass a compressed 33-byte secp256k1 key. A P2PKH receive script can also use `createLock({ ownerHash160 })`. To create a P2PK output, choose `template: "p2pk"` and pass the full key. Recognition checks both templates. The signer receives a 32-byte digest and returns a low-S DER signature. The SDK writes the sighash byte.

## Sign a payment

Create a Python 3.12 environment and install the dependencies from the repository root.

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r projects/p2pk-p2pkh-baseline/sdk/requirements.txt
```

Use the quickstart's bridge configuration and approved wallet data. Create a receiving script and prepare a payment with the same client.

```ts
import { WalletClient } from "./shared/sdk/typescript/index.ts";

const wallet = new WalletClient("p2pk-p2pkh-baseline", { ...config, template: "p2pkh" });
const receiveScript = wallet.createLock({ publicKey: receiveKeyHex });
const prevout = wallet.prevoutFromFunding(fundingTxHex, fundingVout);
const recognized = wallet.recognize({ script: prevout.script, publicKey: spendKeyHex });
if (!recognized) throw new Error("Funding output does not match the spending key");

const signedHex = wallet.signPayment({
  prevout,
  publicKey: spendKeyHex,
  outputs: approvedOutputs,
  feeSats: approvedFeeSats.toString(),
}, ({ payload }) => signer.signSecp256k1DigestDer(payload));
```

Use `signInput` for a prepared transaction. Supply the transaction, its input index and the corresponding prevout. See the [call table](../../../shared/sdk/README.md#calls-and-data) for the matching Rust, Go, and Python interfaces.

## Replay vectors

```sh
.venv/bin/python -m pip install -r projects/p2pk-p2pkh-baseline/reference/requirements.txt ecdsa==0.19.1
SCRIPT_LAB_SDK_PYTHON="$PWD/.venv/bin/python" \
  bash shared/verify_node.sh -- bash shared/sdk/verify_wallet.sh p2pk-p2pkh-baseline
```

## Existing project-specific entry points

| Language | Source and entry point |
|---|---|
| TypeScript | [index.ts](typescript/index.ts) · `createClient` |
| Rust | [Cargo.toml](rust/Cargo.toml) · `bsv_script_lab_native_sdk::client` |
| Go | [go.mod](go/go.mod) · `New` |
| Python | [Client entry](python/__init__.py) · `create_client` |
