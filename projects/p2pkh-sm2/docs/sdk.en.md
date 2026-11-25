# P2PKH-SM2 wallet SDK

[简体中文](sdk.zh-CN.md) · [Developer guide](developer.en.md#sdk) · [Wallet quickstart](../../../shared/sdk/README.md)

Use a 65-byte uncompressed SM2 key or a 20-byte owner hash for the receive script. The SDK option `template: "v1.0.0"` selects locking template `1`, which the v1.1.0 candidate also uses. Pass the 32-byte transaction message and the supplied user ID to the SM2 signer. The raw response is a 64-byte `r ∥ s` signature. For a GB/T 35275-2026 provider, set `signerIdentifier` to the trusted DER issuer-and-serial hex and return the requested DER SignedData.

Set `chronicleActive` from the actual spend context when using OTDA. The SDK automatically selects the shorter encoding for eligible version-2 OTDA ALL and paired SINGLE spends, including ANYONECANPAY. The signer receives the same message and user ID for both encodings. Use the final signed transaction ID when constructing a child.

<a name="quickstart"></a>

## Sign a payment

Create a Python 3.12 environment and install the dependencies from the repository root.

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r projects/p2pkh-sm2/reference/requirements-sdk.txt
```

Use the quickstart's bridge configuration and approved wallet data. Create a receiving script and prepare a payment with the same client.

```ts
import { WalletClient } from "./shared/sdk/typescript/index.ts";

const wallet = new WalletClient("p2pkh-sm2", { ...config, template: "v1.0.0" });
const receiveScript = wallet.createLock({ publicKey: receiveKeyHex });
const prevout = wallet.prevoutFromFunding(fundingTxHex, fundingVout);
const recognized = wallet.recognize({ script: prevout.script, publicKey: spendKeyHex });
if (!recognized) throw new Error("Funding output does not match the spending key");

const signedHex = wallet.signPayment({
  prevout,
  publicKey: spendKeyHex,
  outputs: approvedOutputs,
  feeSats: approvedFeeSats.toString(),
}, ({ payload, userId }) => signer.signSm2(payload, userId!));
```

Use `signInput` for a prepared transaction. Supply the transaction, its input index and the corresponding prevout. See the [call table](../../../shared/sdk/README.md#calls-and-data) for the matching Rust, Go, and Python interfaces.

The SDK requires a same-index output when you request SINGLE. The Python reference also supports the unpaired OTDA companion encoding. [Reference wallet](../reference/README.md)

## Replay vectors

```sh
.venv/bin/python -m pip install -r projects/p2pkh-sm2/reference/requirements.txt
SCRIPT_LAB_SDK_PYTHON="$PWD/.venv/bin/python" \
  bash shared/verify_node.sh -- bash shared/sdk/verify_wallet.sh p2pkh-sm2
```
