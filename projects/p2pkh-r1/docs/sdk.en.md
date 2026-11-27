# Wallet SDK integration

[中文](./sdk.zh-CN.md) · [Wire specification](./spec.en.md)

<a name="quickstart"></a>

## Unified wallet API

Select `v0.8.0` to receive with the current 41,114-byte compiler template. Use an uncompressed 65-byte P-256 key or pass `ownerHash160`. From the repository root, set up the project's reference environment. [v0.8.0 layout](../versions/v0.8.0/layout.json)

```sh
python3.12 -m venv projects/p2pkh-r1/workspace/venv
projects/p2pkh-r1/workspace/venv/bin/python -m pip install -r projects/p2pkh-r1/reference/requirements.txt
```

Use authenticated transaction data. Set `config.python` to the absolute path of `projects/p2pkh-r1/workspace/venv/bin/python` and `config.bridge` to this checkout’s `sdk/python/bridge.py`. [Shared integration example](../../../sdk/docs/integration.md#first-payment)

```ts
import { resolve } from "node:path";
import { WalletClient } from "./sdk/typescript/index.ts";

const wallet = new WalletClient("p2pkh-r1", { ...config, template: "v0.8.0" });
const receiveScript = wallet.createLock({ publicKey: receiveKeyHex });
const prevout = wallet.prevoutFromFunding(fundingTxHex, fundingVout);
if (!wallet.recognize({ script: prevout.script, publicKey: spendKeyHex })) {
  throw new Error("Funding output does not match the spending key");
}
const signedHex = wallet.signPayment({
  prevout,
  publicKey: spendKeyHex,
  outputs: approvedOutputs,
  feeSats: approvedFeeSats.toString(),
  historyPath: resolve(walletStateDir, "r1-signing.sqlite"),
}, ({ payload }) => signer.signP256DigestRaw(payload));
```

The signer returns a 64-byte `r ∥ s` signature. The default payload is `SHA256d(P)`. For a device that applies SHA-256 internally, set `signMessage: true` and pass its `message` payload `SHA256(P)` to the device. Share a persistent `historyPath` across wallet processes to track P-256 nonce reuse. Use `signInput` for a prepared transaction. With Chronicle active, `compressOtda: true` can encode eligible version-2 OTDA unlocks.

Replay the vector in all four languages from the repository root.

```sh
SCRIPT_LAB_SDK_PYTHON="$PWD/projects/p2pkh-r1/workspace/venv/bin/python" \
  bash tools/verify_node.sh -- bash sdk/verify_wallet.sh p2pkh-r1
```

## Bring up a device signer

1. Replay ordinary BIP143 ALL with the test fixture. Confirm that recognition returns the expected owner hash and template before trying a physical device.
2. Use the default with a prehashed signer. Set `signMessage: true` when the device applies SHA-256 exactly once. Return fixed-width, 64-byte `r ∥ s`. Convert DER to that format if your device returns DER.
3. Configure an absolute persistent `historyPath` on storage shared by signing processes. Exercise a restart using the same history. If the wallet blocks a key after detecting nonce reuse, investigate the signer and affected key before resuming payment.

[Nonce history and wallet behavior](../reference/README.md)

## v0.2.0 regex and complete fingerprint

1. Require exactly **46,302 bytes** of binary script.
2. Encode the first **228 bytes** as lowercase hex. Match the entire resulting string against the following pattern. Capture 1 decodes to the candidate 20-byte owner hash.

```regex
^760052a569766b7c8201[0-9a-f]{396}([0-9a-f]{40})$
```

3. Hash the raw bytes `SHA256(script[0:208] || script[228:])`. Require `52a1d9eb9e236403c66e845e18cf31d9c3a5f4c2e0ed7ca0270a60ba4e867ca6` before returning the capture. Changing a single fixed suffix byte fails recognition. To replace an owner, overwrite `[208,228)` in a verified copy. [Layout](../versions/v0.2.0/layout.json)

## Device signers and prepared inputs

A digest signer receives `SHA256d(P)`. Set `signMessage: true` for a device that takes `SHA256(P)` and applies SHA-256 itself. Both paths return 64 raw bytes, with `r` and `s` each padded to 32 bytes in big-endian order. TypeScript clients can use `signPaymentAsync` and `signInputAsync` for asynchronous devices.

Use `signInput` for mixed inputs and explicit sighash modes. The wallet assembles the intended transaction and verifies the previous output and fee before collecting signatures. If a different parent txid confirms, reconcile the outpoint and rebuild the child. [R1 signature and digest vector](../versions/v0.2.0/spend-all.json) · [Recover a child payment](chronicle.md#recovering-a-child-payment)

## Template selection and OTDA

The default wallet template is v0.2.0. Recognition and spending use the template of the actual previous output, including v0.1.0, the earlier compiled template, v0.2.0 and v0.8.0. Set `compressOtda: true` to use the v0.8.0 reconstruction program for eligible OTDA ALL and paired SINGLE spends. [v0.1.0 layout](../versions/v0.1.0/layout.json) · [v0.8.0 layout](../versions/v0.8.0/layout.json)

In the Python reference, `sign_spend(..., compress_otda="paired")` enables
output reconstruction in version 2 Chronicle OTDA transactions using ALL
or paired SINGLE. SINGLE reconstructs its same-index output and retains
the null placeholders that precede it in the preimage. Version 1, unpaired
SINGLE, and unknown output formats use their existing encodings. The
signer receives the original digest, and its signature goes into the witness.

Version 2 OTDA ALL can reconstruct both the 47,510-byte compiled template
and the 46,302-byte v0.2.0 template. The wallet compares the literal,
single-template and two-template encodings. A two-input, two-output
payment with one output of each template measures 110,302 bytes, down
from 195,028 bytes with single-template reconstruction.
