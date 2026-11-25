# Local wallet SDKs

[简体中文](README.zh-CN.md)

The TypeScript, Rust, Go and Python source clients use a short-lived local Python bridge to reuse each project's reference wallet. Configure an absolute path to `shared/sdk/python/bridge.py` and the Python 3.12 interpreter for the project. Keep the repository checkout and its template files available to that interpreter. The TypeScript client runs on Node.js 24 or later. The Go modules use Go 1.23 or later. The Rust crates use edition 2021.

## Wallet workflow

1. Create a lock with `lock`. P2PKH and SM2 can also create a lock from the 20-byte owner hash. Confirm incoming raw script bytes with `recognize`. Hash-based and ML-DSA wallet formats reproduce the lock from the expected public key.
2. Choose the recipients, change, fee and sighash before requesting approval. For a one-input payment provide raw funding, its output index, ordered outputs and fee. For an already prepared transaction provide the raw transaction and the input index. Authenticate the funding outpoint against the application's chain view.
3. Supply a caller-owned signer callback. The SDK prepares the exact signer arguments, calls the signer once and uses the original request to verify the returned signature before writing the witness. Signers return bytes. SM2 also receives its user ID. Only signatures and public transaction data go to the bridge.
4. Inspect the returned signed transaction and hand it to the wallet's own broadcasting path.

TypeScript uses `createClient` from the project's `sdk/typescript/index.ts`, Go uses the project's `sdk/go` module and its `New` constructor, and Rust uses the project's `sdk/rust` crate and its `client` constructor. For Python, import `Client` from `shared.sdk.python.client` with the repository on `PYTHONPATH`.

The TypeScript, Rust and Go clients take and return raw transaction and script hex. Their monetary fields are canonical decimal satoshi strings. For `signPayment`, `index` is the funding output index. For `signSpend`, it is the prepared transaction's input index. `0x41` is the default. Set `chronicleActive` from the trusted spend context before selecting OTDA; signers always authorize the requested mode. The Python client uses bytes and integer amounts directly. See each project's SDK README for its formats and callback contract.

## Replay

Use the project reference environment with the pinned chain-gang dependency for tests. The native fixture also uses `ecdsa==0.19.1`; the ML-DSA fixture uses OpenSSL 3.5 or later. On Linux run from the repository root:

```sh
bash shared/verify_node.sh -- bash shared/sdk/verify.sh PROJECT
```

Substitute the project directory name for `PROJECT`. The replay compares all four client outputs with the same public vector, checks the transactions through BSV Node and chain-gang, and exercises recognition and signing preflight. The shipped SDK code and document examples delegate private-key operations to the application.

## TypeScript example

The inputs below are provided by the wallet and remain under its approval policy. Use the project import for the selected signature algorithm.

```ts
import { resolve } from "node:path";
import { createClient } from "./projects/p2pkh-sm2/sdk/typescript/index.ts";

const sdk = createClient({ bridge: resolve("shared/sdk/python/bridge.py") });
const signedHex = sdk.signPayment({
  funding: authenticatedFundingHex,
  index: fundingVout,
  publicKey: publicKeyHex,
  outputs: approvedOutputs,
  feeSats: approvedFeeSats.toString(),
}, (message, userId) => walletSigner.signSm2(message, userId));
```
