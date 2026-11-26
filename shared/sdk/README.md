# Wallet SDK quickstart

[简体中文](README.zh-CN.md)

Use the same wallet workflow for every Script Lab project. Start with native P2PKH to check transaction serialization and your secp256k1 signer, then select another project and connect its signer. A client uses a local Python 3.12 process and the templates in this checkout.

Use the shared source package for your language and select a scheme by project identifier. Each integration guide covers its template, signer format and project-specific workflow.

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

The example takes its inputs from your wallet. The wallet resolves the funding transaction and verifies that the output is spendable through its trusted chain view. It approves recipient outputs, change, and the fee before signing.

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

For a separate wallet checkout, add the same Rust crate with `cargo add --path /path/to/bsv-script-lab/shared/sdk/rust`, or add the same Go module with `go work use /path/to/bsv-script-lab/shared/sdk/go`. Select the Python environment for your scheme in the client configuration. For TypeScript hardware adapters with an asynchronous signing API, use `signPaymentAsync` or `signInputAsync`.

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

If the bridge fails to start, check the interpreter path, scheme dependencies, and source checkout. A fee mismatch fails before the signer runs. A signature error can occur after the callback returns, so retain the signer state and check the project's retry guidance, especially for one-time keys.

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

## Replay the baseline

On Linux, install the native project's pinned test dependencies and run the four-language replay from the repository root. The Rust toolchain is required for the pinned chain-gang binding and Rust client tests.

```sh
.venv/bin/python -m pip install -r projects/p2pk-p2pkh-baseline/reference/requirements.txt ecdsa==0.19.1
SCRIPT_LAB_SDK_PYTHON="$PWD/.venv/bin/python" \
  bash shared/verify_node.sh -- bash shared/sdk/verify_wallet.sh p2pk-p2pkh-baseline
```

The replay checks locking scripts, signer requests and signed transaction bytes in all four clients, and verifies the public vectors through chain-gang and BSV Node with supplied prevouts. Use the signed samples as serialization fixtures. See the [benchmark guide](../benchmark.md) for cost comparisons and funded regtest.
