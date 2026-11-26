# Integrate the Wallet SDK

[简体中文](integration.zh-CN.md) · [SDK overview](../README.md) · [API reference](reference.md)

[Bridge setup](#bridge-setup) · [Wallet workflow](#wallet-workflow) · [External signer](#first-payment) · [Prepared transactions](#prepared-payments)

<a name="bridge-setup"></a>

## Configure the local bridge

The TypeScript binding requires Node.js 24 or later. The Go module requires Go 1.23 or later. The Rust crate uses edition 2021.

Keep a specific 4thGraph checkout available to the application and its local bridge. Resolve absolute paths to the checkout's `sdk/python/bridge.py` and the scheme's Python interpreter in application configuration. The language bindings and templates should come from the same revision.

| Language | Load the binding |
| --- | --- |
| TypeScript | Import the checkout's `sdk/typescript/index.ts` from the Node.js process. Use `signPaymentAsync` or `signInputAsync` with an asynchronous device SDK. The local bridge still runs synchronously. |
| Rust | Run `cargo add --path /path/to/4thGraph/sdk/rust` from your crate. |
| Go | From your wallet module, use `go work init .` if you need a workspace, then `go work use /path/to/4thGraph/sdk/go`. |
| Python | Add the checkout to `PYTHONPATH` and import `WalletClient` from `sdk.python.client`. By default the bridge uses the current interpreter. |

Use the project guide's Python requirements for native P2PK/P2PKH, R1, Deferred R1, Schnorr, and SM2. The Lamport, WOTS+, and ML-DSA payment SDK paths use the standard library. The fixture signer for ML-DSA also needs OpenSSL with Pure ML-DSA-44 support. Node and chain-gang replays have additional dependencies. Use separate Python environments for replays that require different chain-gang revisions. [Scheme integrations](../README.md#scheme-integrations)

Set `python` to the interpreter with your project’s dependencies and `bridge` to the checkout’s `sdk/python/bridge.py`. The following examples use the native payment environment from the offline quickstart.

<a name="wallet-workflow"></a>

## From payment request to broadcast

| Step | Wallet responsibility | SDK operation |
| --- | --- | --- |
| Receive | Record the project, expected key or owner hash, and invoice amount. Keep the full public-key bytes required by the selected template. | `createLock` returns the raw script to put into an output. |
| Identify a UTXO | From a trusted chain view, check the funding txid, output index, amount, and spendability. Match the actual output against the invoice. | `prevoutFromFunding` parses the parent. `recognize` checks the actual script against the selected project and supplied key. |
| Approve | Choose inputs, ordered recipient and change outputs, and the fee. For a prepared transaction, check the fee from all authenticated prevouts. | `signPayment` assembles a single-input payment. `signInput` fills an input in your prepared transaction. |
| Authorize | Route the request to the signer for that key. Check the algorithm, payload kind, signature format, and sighash before releasing a signature. | The selected client prepares the payload, verifies the returned signature, and assembles the unlock. Deferred activation uses `activate` for the committed input. |
| Submit | Persist the final bytes and txid, apply relay policy, submit, and track confirmations. Rebuild any dependent child if its parent outpoint changes. | The client returns the complete transaction for your broadcaster. |

<a name="first-payment"></a>

## Connect an external signer

This example connects the TypeScript client to a wallet. `receiveKeyHex` is the invoice key. `fundingTxHex`, `fundingVout`, and `spendKeyHex` identify a prevout the wallet has already checked. `approvedOutputs` includes change, and `approvedFeeSats` is the total fee for this one-input payment. The callback calls the wallet's external signer.

```ts
import { resolve } from "node:path";
import { WalletClient } from "./sdk/typescript/index.ts";

const config = {
  python: resolve("workspace/sdk-venv/bin/python"),
  bridge: resolve("sdk/python/bridge.py"),
};
const wallet = new WalletClient("p2pk-p2pkh-baseline", config);

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

The signer returns a low-S DER signature. The SDK appends the sighash byte and verifies the signature before returning serialized transaction hex. Your wallet submits the transaction after applying its own approval and broadcasting policies. Set `template: "p2pk"` when constructing the client to create P2PK outputs through the same API. Recognition checks the actual script and can recognize both formats.

## Call from Rust, Go, and Python

Set the same absolute interpreter and bridge paths in the Rust and Go `config`. Pass approved outputs as `Vec<Output>` in Rust, `[]sdk.Output` in Go, or a sequence of `(integer satoshis, raw script bytes)` in Python.

```rust
use bsv_script_lab_local_sdk::{WalletClient, WalletPayment, WalletSigningOptions};

let wallet = WalletClient::new("p2pk-p2pkh-baseline", config, None);
let prevout = wallet.prevout_from_funding(&funding_hex, vout)?;
let signed_hex = wallet.sign_payment(
    WalletPayment {
        prevout,
        outputs: approved_outputs,
        fee_sats: approved_fee_sats.to_string(),
        options: WalletSigningOptions { public_key: spend_key_hex, ..Default::default() },
    },
    |request| signer.sign_secp256k1_digest_der(&request.payload),
)?;
```

```go
import sdk "github.com/linzhm/4thGraph/sdk/go"

wallet := sdk.NewWallet("p2pk-p2pkh-baseline", config, "")
prevout, err := wallet.PrevoutFromFunding(ctx, fundingHex, vout)
if err != nil {
    return err
}
signedHex, err := wallet.SignPayment(ctx, sdk.WalletPayment{
    Prevout: prevout, Outputs: approvedOutputs, FeeSats: approvedFeeSats,
    WalletSigningOptions: sdk.WalletSigningOptions{PublicKey: spendKeyHex},
}, func(request sdk.SigningRequest) ([]byte, error) {
    return signer.SignSecp256k1DigestDER(request.Payload)
})
```

```python
from pathlib import Path
from sdk.python.client import WalletClient

wallet = WalletClient("p2pk-p2pkh-baseline", python=str(Path("workspace/sdk-venv/bin/python").resolve()))
prevout = wallet.prevout_from_funding(funding_bytes, vout)
signed = wallet.sign_payment(
    prevout, approved_outputs, approved_fee_sats, spend_key,
    lambda request: signer.sign_secp256k1_digest_der(request.payload),
)
```

<a name="prepared-payments"></a>

## Sign a prepared transaction

Use `signInput` for several inputs, mixed signature schemes, custom sequence values, or custom locktime. Start with a transaction whose selected inputs have empty unlocking scripts. Create an approval for each input using the client for its actual prevout. For example, an R1 UTXO and a native P2PKH fee input use separate clients and signers. Set R1's persistent `historyPath` in its request.

```ts
import { WalletClient, type WalletInput, type WalletSigner } from "./sdk/typescript/index.ts";

type ApprovedInput = {
  wallet: WalletClient;
  request: Omit<WalletInput, "transaction">;
  signer: WalletSigner;
};

export function fillApprovedInputs(transaction: string, approvedInputs: readonly ApprovedInput[]): string {
  for (const { wallet, request, signer } of approvedInputs) {
    transaction = wallet.signInput({ ...request, transaction }, signer);
  }
  return transaction;
}
```

Calculate the total fee as the sum of the authenticated input amounts minus the sum of the outputs before calling this helper. Keep the approved input and output order, sequences and locktime fixed while adding unlocks. Use the result of each call as the input to the next, then verify that each required input has its unlock before broadcasting. For Deferred, assemble the committed same-index output and call `activate`, then sign the sponsor input with its own client. [Deferred integration](../../projects/p2pkh-r1-deferred/docs/sdk.en.md#quickstart)

## Design references

4thGraph uses one source library per language and selects the payment template by project, following the separation of transaction objects and locking templates in the BSV SDK. The signing callback keeps key custody with the application, as in the BDK transaction-signing flow. TypeScript's separate async methods follow bitcoinjs-lib's signer API and preserve the wallet's approved transaction while a device is pending. [BSV template API](https://hub.bsvblockchain.org/bsv-code-academy/code-features/code-features/custom-templates) · [BDK signing workflow](https://bookofbdk.com/design/signing/) · [bitcoinjs-lib async signer](https://bitcoinjs.github.io/bitcoinjs-lib/interfaces/SignerAsync.html)
