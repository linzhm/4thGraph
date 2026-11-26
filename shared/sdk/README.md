# Wallet SDK integration guide

[简体中文](README.zh-CN.md)

Use the same wallet API to create and recognize a lock, prepare a signing request, and assemble a signed spend. Start with native P2PKH to check serialization and your secp256k1 signer, then select a project to try another signing policy. Each call runs the local Python 3.12 bridge against the templates in this checkout.

[Offline quickstart](#quickstart) · [Wallet workflow](#wallet-workflow) · [Prepared payments](#prepared-payments) · [Scheme integrations](#scheme-integrations) · [Troubleshooting](#troubleshooting)

<a name="quickstart"></a>

## Set up native P2PKH

Run these commands from the repository root to try the Python example.

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r projects/p2pk-p2pkh-baseline/reference/requirements-sdk.txt ecdsa==0.19.1
.venv/bin/python -m shared.sdk.examples.receive_and_pay
```

The offline example creates and recognizes a native P2PKH lock, then signs a synthetic payment with a 100-satoshi fee. It prints the template, byte sizes and transaction ID. It uses a public test key and never connects to a node or broadcasts. The `ecdsa` package is for the test signer. [Example source](examples/receive_and_pay.py)

Pass `p2pkh-sm2`, `lamport-ots`, `wots-plus`, or `ml-dsa` as the final argument to try another scheme. Install SM2's dependencies from its integration guide. Lamport and WOTS+ use the Python standard library for this example. ML-DSA-44 uses OpenSSL 3.5 or later, selected with `ML_DSA_OPENSSL` when needed. The R1 and Deferred guides below include their transaction and activation replays.

The TypeScript example requires Node.js 24 or later. Go examples use Go 1.23 or later, and the Rust crate uses edition 2021.

Use `WalletClient` from [TypeScript](typescript/index.ts), `WalletClient::new` from [Rust](rust/Cargo.toml), `NewWallet` from [Go](go/go.mod), or `WalletClient` from [Python](python/client.py). These are source packages. With Python, run from the repository root or put the checkout on `PYTHONPATH`.

The following TypeScript snippet plugs into a wallet. `receiveKeyHex` is the invoice key. `fundingTxHex`, `fundingVout`, and `spendKeyHex` identify a prevout the wallet has already checked. `approvedOutputs` includes change, and `approvedFeeSats` is the total fee for this one-input payment. The callback calls the wallet's external signer.

```ts
import { resolve } from "node:path";
import { WalletClient } from "./shared/sdk/typescript/index.ts";

const config = {
  python: resolve(".venv/bin/python"),
  bridge: resolve("shared/sdk/python/bridge.py"),
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

### Use the SDK from a wallet repository

Keep a specific Script Lab checkout available to the application and its local bridge. Resolve absolute paths to the checkout's `shared/sdk/python/bridge.py` and the scheme's Python interpreter in application configuration. The language bindings and templates should come from the same revision.

| Language | Load the binding |
| --- | --- |
| TypeScript | Import the checkout's `shared/sdk/typescript/index.ts` from the Node.js process. Use `signPaymentAsync` or `signInputAsync` with an asynchronous device SDK. The local bridge still runs synchronously. |
| Rust | Run `cargo add --path /path/to/bsv-script-lab/shared/sdk/rust` from your crate. |
| Go | From your wallet module, use `go work init .` if you need a workspace, then `go work use /path/to/bsv-script-lab/shared/sdk/go`. |
| Python | Add the checkout to `PYTHONPATH` and import `WalletClient` from `shared.sdk.python.client`. By default the bridge uses the current interpreter. |

Use the project guide's Python requirements for native P2PK/P2PKH, R1, Deferred R1, and SM2. The Lamport, WOTS+, and ML-DSA payment SDK paths use the standard library. The fixture signer for ML-DSA also needs OpenSSL with Pure ML-DSA-44 support. Node and chain-gang replays have additional dependencies. Use separate Python environments for replays that require different chain-gang revisions. [Scheme integrations](#scheme-integrations)

<a name="wallet-workflow"></a>

## From payment request to broadcast

| Step | Wallet responsibility | SDK operation |
| --- | --- | --- |
| Receive | Record the project, expected key or owner hash, and invoice amount. Keep the full public-key bytes required by the selected template. | `createLock` returns the raw script to put into an output. |
| Identify a UTXO | From a trusted chain view, check the funding txid, output index, amount, and spendability. Match the actual output against the invoice. | `prevoutFromFunding` parses the parent. `recognize` checks the actual script against the selected project and supplied key. |
| Approve | Choose inputs, ordered recipient and change outputs, and the fee. For a prepared transaction, check the fee from all authenticated prevouts. | `signPayment` assembles a single-input payment. `signInput` fills an input in your prepared transaction. |
| Authorize | Route the request to the signer for that key. Check the algorithm, payload kind, signature format, and sighash before releasing a signature. | The selected client prepares the payload, verifies the returned signature, and assembles the unlock. Deferred activation uses `activate` for the committed input. |
| Submit | Persist the final bytes and txid, apply relay policy, submit, and track confirmations. Rebuild any dependent child if its parent outpoint changes. | The client returns the complete transaction for your broadcaster. |

## Design references

Script Lab uses one source library per language and selects the payment template by project, following the separation of transaction objects and locking templates in the BSV SDK. The signing callback keeps key custody with the application, as in the BDK transaction-signing flow. TypeScript's separate async methods follow bitcoinjs-lib's signer API and preserve the wallet's approved transaction while a device is pending. [BSV template API](https://hub.bsvblockchain.org/bsv-code-academy/code-features/code-features/custom-templates) · [BDK signing workflow](https://bookofbdk.com/design/signing/) · [bitcoinjs-lib async signer](https://bitcoinjs.github.io/bitcoinjs-lib/interfaces/SignerAsync.html)

## Calls and data

| TypeScript | Rust / Python | Go | Result |
| --- | --- | --- | --- |
| `createLock` | `create_lock` | `CreateLock` | Raw locking script for a public key or a supported 20-byte owner hash |
| `recognize` | `recognize` | `Recognize` | Matching project, template and any available owner or commitment data |
| `prevoutFromFunding` | `prevout_from_funding` | `PrevoutFromFunding` | Display-order `txid`, parent output index `vout`, `valueSats` and raw `script` |
| `signPayment` | `sign_payment` | `SignPayment` | A version-2, single-input transaction with final sequence, zero locktime and approved outputs |
| `signInput` | `sign_input` | `SignInput` | The supplied transaction with an unlocking script added at `inputIndex` |
| `activate` | `activate` | `Activate` | The supplied transaction with a Deferred activation script added at `inputIndex` |

TypeScript, Rust and Go use even-length, unprefixed hex for serialized transactions, public keys and Script, and canonical decimal strings for integer satoshis. Python uses bytes and integer satoshis, with a display-order txid string. The signer receives and returns binary bytes in all four languages. A recognition miss is `null`, `None`, or `nil`. A malformed request raises or returns an error.

You can pass an authenticated prevout directly. `prevoutFromFunding` reads serialized funding bytes and calculates the txid. The wallet uses its chain view to check outpoint existence, confirmation, spendability and amount. `signPayment` checks that output amounts plus the fee equal the prevout amount. For a transaction with multiple inputs, approve the total fee using all prevouts before calling `signInput` for each unsigned input. `prevout.vout` always refers to the parent transaction. `inputIndex` always refers to the spending transaction.

Wallet signing defaults to ForkID ALL (`0x41`), and `SINGLE` requires an output at the same index. Set `chronicleActive` from the trusted chain context before choosing OTDA. The callback receives `algorithm`, `payloadKind` (`digest` or `message`), `signatureFormat`, `sighash`, `payload`, and the SM2 `userId` when present. Use the scheme-specific signing operation and encoding below.

Leave the reconstruction option unset to use the scheme's default. SM2 automatically uses reconstruction when it shortens the OTDA unlock. In Go, `CompressOTDA` is a `*bool`, with `nil` for the default. In Rust, `compress_otda` is an `Option<bool>`, with `None` for the default. Use a pointer to `false`, `Some(false)`, or `false` in TypeScript and Python to reproduce the literal SM2 encoding.

<a name="prepared-payments"></a>

## Sign a prepared transaction

Use `signInput` for several inputs, mixed signature schemes, custom sequence values, or custom locktime. Start with a transaction whose selected inputs have empty unlocking scripts. Create an approval for each input using the client for its actual prevout. For example, an R1 UTXO and a native P2PKH fee input use separate clients and signers. Set R1's persistent `historyPath` in its request.

```ts
import { WalletClient, type WalletInput, type WalletSigner } from "./shared/sdk/typescript/index.ts";

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
import sdk "github.com/linzhm/bsv-script-lab/shared/sdk/go"

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
from shared.sdk.python.client import WalletClient

wallet = WalletClient("p2pk-p2pkh-baseline", python=str(Path(".venv/bin/python").resolve()))
prevout = wallet.prevout_from_funding(funding_bytes, vout)
signed = wallet.sign_payment(
    prevout, approved_outputs, approved_fee_sats, spend_key,
    lambda request: signer.sign_secp256k1_digest_der(request.payload),
)
```

<a name="one-time-signing"></a>

For Lamport and WOTS+ in Python, wrap your digest signer with `durable_signer(database, project, spend_key, sign_digest)` and pass the resulting function as `lambda request: sign_once(request.payload)`, where `sign_once` is the returned wrapper. Use the same database and canonical public key across wallet processes and template formats. [One-time signer](../one_time_signer.py)

## Scheme integrations

| Project | Signing request | Select this guide |
| --- | --- | --- |
| Native P2PK and P2PKH | secp256k1 digest, low-S DER | [Native SDK](../../projects/p2pk-p2pkh-baseline/docs/sdk.en.md#quickstart) |
| P2PKH-R1 | P-256 digest or device-hashed message, 64-byte `r ∥ s` | [R1 SDK](../../projects/p2pkh-r1/docs/sdk.en.md#quickstart) |
| P2PKH-R1-Deferred | Activation builds the unlocking script from the committed R1 output | [Deferred SDK](../../projects/p2pkh-r1-deferred/docs/sdk.en.md#quickstart) |
| P2PKH-SM2 | SM2 message and user ID, 64-byte `r ∥ s` or DER SignedData | [SM2 SDK](../../projects/p2pkh-sm2/docs/sdk.en.md#quickstart) |
| P2PKH-Schnorr | 32-byte BSV transaction message, 64-byte BIP340 signature | [Schnorr SDK](../../projects/p2pkh-schnorr/docs/sdk.en.md#quickstart) |
| Lamport OTS | 32-byte digest, 8,192-byte signature | [Lamport SDK](../../projects/lamport-ots/docs/sdk.en.md#quickstart) |
| WOTS+ | 32-byte digest, 2,144-byte signature | [WOTS+ SDK](../../projects/wots-plus/docs/sdk.en.md#quickstart) |
| Pure ML-DSA-44 | 32-byte message with empty context, 2,420-byte signature | [ML-DSA SDK](../../projects/ml-dsa/docs/sdk.en.md#quickstart) |

<a name="troubleshooting"></a>

## Troubleshooting and retries

| What you see | What to check |
| --- | --- |
| The bridge fails to launch | Check the absolute interpreter and bridge paths, the checked-out templates, and which interpreter received the scheme's dependencies. Run the offline example with that interpreter. |
| Recognition misses or preparation rejects the request | Check the project and actual prevout bytes. For a prepared spend, verify `inputIndex`, `prevout.vout`, the empty unlocking script and the selected sighash. For `signPayment`, verify that outputs plus fee equal the input amount. |
| The signer returns, then assembly fails | Check whether the callback returned the requested raw or DER bytes and signed the correct digest or message. Preserve the signing state, especially for one-time keys that might already have released a signature. |
| No broadcaster accepts the signed bytes | Verify that the funding outpoints remain spendable and check the broadcaster's policy response. Rebroadcast the exact saved bytes if appropriate. For one-time keys, resolve existing signing state before generating any replacement. |

## Replay the baseline

On Linux, install the native project's pinned test dependencies and run the four-language replay from the repository root. The Rust toolchain is required for the pinned chain-gang binding and Rust client tests.

```sh
.venv/bin/python -m pip install -r projects/p2pk-p2pkh-baseline/reference/requirements.txt ecdsa==0.19.1
SCRIPT_LAB_SDK_PYTHON="$PWD/.venv/bin/python" \
  bash shared/verify_node.sh -- bash shared/sdk/verify_wallet.sh p2pk-p2pkh-baseline
```

The replay compares locking scripts, signer requests and signed transaction bytes in all four clients. It also verifies the public vectors through chain-gang and BSV Node with supplied prevouts. A funded regtest adds UTXO admission and mining under a stated policy. Run that check when your integration depends on relay or block acceptance. [Benchmark and funded regtest guide](../benchmark.md)
