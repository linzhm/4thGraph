# Lamport OTS wallet SDK

[简体中文](sdk.zh-CN.md) · [Developer guide](developer.en.md#sdk) · [Wallet quickstart](../../../sdk/README.md)

Choose `full-key` (default), `committed-key`, or either experimental profile `committed-key-forth` and `committed-key-forth-compact` for receiving. Pass the complete ordered public key to recognition. The SDK also recognizes legacy outputs, whose spending mode is BIP143 ALL. [Profile and transaction costs](../README.md#choose-a-payment-profile)

<a name="quickstart"></a>

## Sign a payment

The runtime uses the Python 3.12 standard library. The replay needs the test dependencies below.

Create the Python environment for the bridge from the repository root.

```sh
python3.12 -m venv projects/lamport-ots/workspace/venv
```

Use authenticated transaction data. Set `config.python` to the absolute path of `projects/lamport-ots/workspace/venv/bin/python` and `config.bridge` to this checkout’s `sdk/python/bridge.py`. [Shared integration example](../../../sdk/docs/integration.md#first-payment)

```ts
import { WalletClient } from "./sdk/typescript/index.ts";

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

Use `signInput` for a prepared transaction. Supply the transaction, its input index and the corresponding prevout. See the [call table](../../../sdk/docs/reference.md#calls-and-data) for the matching Rust, Go, and Python interfaces.

## Reconstruct OTDA preimages

For a trusted Chronicle spend context, set `chronicleActive: true`, `compressOtda: true` and an OTDA sighash such as `0x61` in the signing request. Use `compress_otda=True` in Python or `CompressOTDA` in Go. With a version-2 transaction, reconstruction applies to compact Forth outputs covered by OTDA ALL or a paired OTDA SINGLE, including ANYONECANPAY. The wallet chooses the shorter encoding and calls the signer with the same digest as the literal encoding. Fund the output using the existing `committed-key-forth-compact` profile. [Encoding and measurements](optimization.md#otda-unlocking-reconstruction)

## Keep key state with the invoice

Record the exact payment profile on the invoice and retain the full 16,384-byte public key in order. The committed profiles use those bytes to assemble the spending proof. Recover the public key and the key-consumption record together.

Reserve the key before the signer releases the 8,192-byte signature. A timeout after requesting a signature can leave the key consumed. Recover and rebroadcast the same signed transaction when available, and use fresh keys on new outputs. [One-time signing in the shared SDK](../../../sdk/docs/reference.md#one-time-signing)

## Replay vectors

```sh
projects/lamport-ots/workspace/venv/bin/python -m pip install -r projects/lamport-ots/reference/requirements.txt
SCRIPT_LAB_SDK_PYTHON="$PWD/projects/lamport-ots/workspace/venv/bin/python" \
  bash tools/verify_node.sh -- bash sdk/verify_wallet.sh lamport-ots
```
