# P2PKH-Schnorr wallet SDK

[简体中文](sdk.zh-CN.md) · [Project overview](../README.md) · [Unified wallet SDK](../../../sdk/README.md)

<a name="quickstart"></a>

## Receive and spend

Select project `p2pkh-schnorr` in the unified SDK. The client uses template `v0.17.0` by default. Supply a 32-byte x-only public key or its 20-byte HASH160. The client fills the owner slot in the frozen Forth build and checks all fixed script bytes when recognizing an output. You can also supply the expected public key. The SDK identifies and spends UTXOs of all twelve versions from their prevout scripts. Set the wallet's `template` to an earlier supported version to create that output format. [Version catalog](../versions/index.json)

The signing request identifies the algorithm as `schnorr-secp256k1`, the payload kind as `message`, and the signature format as `bip340`. Give the 32-byte payload to the BIP340 signer as the message. Return the signer's original 64 bytes. The SDK verifies the signature, derives the public witness coordinates, and runs the Forth `schnorr-unlock` word to generate the input script. [Forth source](../reference/schnorr.fth)

Use authenticated transaction data. Set `config.python` to the absolute path of `projects/p2pkh-schnorr/workspace/p2pkh-schnorr/bin/python` and `config.bridge` to this checkout’s `sdk/python/bridge.py`. [Shared integration example](../../../sdk/docs/integration.md#first-payment) · [Project Python environment](../README.md#validate-the-baseline)

```ts
import { WalletClient } from "./sdk/typescript/index.ts";

const wallet = new WalletClient("p2pkh-schnorr", config);
const receiveScript = wallet.createLock({ publicKey: receiveKeyHex });
const prevout = wallet.prevoutFromFunding(fundingTxHex, fundingVout);
if (!wallet.recognize({ script: prevout.script, publicKey: spendKeyHex })) {
  throw new Error("Funding output does not match the Schnorr key");
}
const signedHex = wallet.signPayment({
  prevout,
  publicKey: spendKeyHex,
  outputs: approvedOutputs,
  feeSats: approvedFeeSats.toString(),
}, ({ payload }) => signer.signBip340(payload));
```

For a prepared transaction, use `signInput` and supply the current input index and its authenticated prevout. For Chronicle OTDA, supply `chronicleActive` from the actual chain context. SINGLE requires a same-index output. For version-2 OTDA ALL or paired SINGLE, the wallet uses a shorter preimage constructor where available. Set `compressOtda: false` (`compress_otda=False` in Python) to request a literal push. The same methods are available in Python, Rust, and Go. [Shared API table](../../../sdk/docs/reference.md#calls-and-data)

## Integrate MuSig2

Keep the ordered compressed participant keys in the wallet's policy. Derive their BIP327 aggregate x-only key before funding. Pass that aggregate key as `publicKey` for receiving, recognizing a previous output, and spending. For signing, the external coordinator gives both participants the approved input and `payload`, exchanges public nonces, verifies both partial signatures, and returns the final 64-byte BIP340 signature through the existing callback. A replacement session uses fresh nonces and partial signatures for that input. Participant approval, transport, and nonce persistence belong to the external signer. [2-of-2 acceptance and costs](threshold-comparison.en.md) · [BIP327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki)

## Replay with public keys and fixtures

Install the project requirements shown on the project overview, then run the offline example. Its public keys and auxiliary randomness are test data.

```sh
PYTHONPATH=src:. projects/p2pkh-schnorr/workspace/p2pkh-schnorr/bin/python -m sdk.examples.receive_and_pay p2pkh-schnorr
SCRIPT_LAB_SDK_PYTHON="$PWD/projects/p2pkh-schnorr/workspace/p2pkh-schnorr/bin/python" \
  bash tools/verify_node.sh -- bash sdk/verify_wallet.sh p2pkh-schnorr
```

[Setup and acceptance scope](../README.md#validate-the-baseline)
