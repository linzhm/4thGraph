# Wallet SDK integration

[中文](./sdk.zh-CN.md) · [Wire specification](./spec.en.md)

## Public API

The three source SDKs construct the same locking scripts, recognize raw outputs, and build an ordinary signed payment locally. TypeScript targets Node.js 24. Rust and Go are native libraries. Supply a signing callback to connect a hardware adapter.

| Language | Create and recognize | Ordinary payment | Implementation |
|---|---|---|---|
| TypeScript | `lockForKey`, `lockForOwner`, `recognize` | `signPayment(payment, key, signDigest)` | [source](../sdk/typescript/index.ts) · [payment](../sdk/typescript/payment.ts) |
| Rust | `lock_for_key`, `lock_for_owner`, `recognize` | `payment::sign_payment(&payment, key, sign_digest)` | [source](../sdk/rust/src/lib.rs) · [payment](../sdk/rust/src/payment.rs) |
| Go | `LockForKey`, `LockForOwner`, `Recognize` | `SignPayment(payment, key, signDigest)` | [source](../sdk/go/template.go) · [payment](../sdk/go/payment.go) |

**Receive.** Remove whitespace and decode [template.hex](../template/template.hex) once. Pass its bytes as the first constructor argument and a 65-byte R1 public key or 20-byte owner hash as the second. The constructor verifies the fixed program and changes the owner bytes in a copy. Recognition accepts a raw scriptPubKey and returns the 20-byte owner on success. Compare it with the intended recipient. A length, framing or program mismatch returns null in TS, None in Rust or ok=false in Go. An application accepting compressed public keys must validate and expand them before hashing the 65-byte encoding.

**Pay.** The caller obtains an authenticated UTXO or verifies its funding txid, index, amount and script locally. Supply its 32-byte txid in display order, vout, satoshi value and scriptPubKey, the ordered outputs including change, approved fee and public key. Amounts are integer satoshis; TypeScript uses bigint. The SDK checks the owner, nonnegative amounts and exact fee balance. It constructs one version-2 input with final sequence, zero locktime and BIP143 ALL. The digest signer receives the 32-byte digest. Both signing entry points return a 64-byte r∥s signature from the callback. The SDK verifies the signature, computes the inverse, writes OP_0 and returns the serialized signed transaction. Callback failures and invalid signatures return an error. The signer service owns device consent, nonce safety and any durable signing history. The SDK does not submit transactions.

For mixed inputs or explicit NONE, SINGLE, ANYONECANPAY and OTDA, build each input through the protocol-layer authorization interface. The three ported high-level payment APIs implement the ordinary profile above. The [Python reference](../reference/wallet.py) exposes `sign_spend(tx, index, parent, requested_type, pubkey, sign_digest, history_path)`. A port of that interface must construct the message from the real transaction and authenticated prevout, deriving the selector from type, input position and output count. The ordinary payment API has no sighash or selector argument.

For a child payment, obtain the confirmed funding outpoint from the
application's trusted chain view before invoking the signing callback.
Apply the application's confirmation threshold and recheck the output index,
amount, locking script, and unspent status. If a different txid confirmed,
reconcile the wallet's outpoint and rebuild the child before requesting a
new signature.
[Recovering a child payment](./chronicle.md#recovering-a-child-payment)

## Regex and complete fingerprint

1. Require exactly **59,582 bytes** of binary script.
2. Encode the first **228 bytes** as lowercase hex. Match the entire resulting string against the following pattern. Capture 1 decodes to the candidate 20-byte owner hash.

```regex
^760052a569766b7c8201[0-9a-f]{396}([0-9a-f]{40})$
```

3. Hash the raw bytes `SHA256(script[0:208] || script[228:])`. Require `2129d374594069d08a9b2127555f48ea21c75fb06d1ad5e77c68ad251e97f784` before returning the capture. Changing a single fixed suffix byte fails recognition. To replace an owner, overwrite `[208,228)` in a verified copy. [Layout](../template/layout.json)

## Hardware adapter and replay

The vector's digest callback receives `digest_hex` and returns `signature_hex`. All three SDKs reproduce the vector's scriptSig and signed txid. A different valid device signature may produce a different txid. Convert a DER signature by decoding its two positive integers and left-padding each to 32 big-endian bytes. [Payment vector](../template/spend-all.json)

Use `signPayment` (TypeScript), `sign_payment` (Rust), or `SignPayment` (Go) with a prehashed signer. These callbacks receive `SHA256d(P)`. If the device applies SHA-256 internally, use `signPaymentWithMessage`, `sign_payment_with_message`, or `SignPaymentWithMessage`. Those callbacks receive the 32-byte message `SHA256(P)`. Both entry points validate the same transaction and verify the returned 64-byte signature against `SHA256d(P)`.

```sh
(cd projects/p2pkh-r1/sdk/typescript && npm install && npm run check && npm test)
(cd projects/p2pkh-r1/sdk/rust && cargo test)
(cd projects/p2pkh-r1/sdk/go && go test ./...)
```

The three test suites check the A/B/C constructor vectors, curve-point validation, fixed-byte changes, truncation, appended bytes, ordinary signed payments, incorrect signatures and fee mismatches. These tests require no device, node or signing secret. Installing dependencies initially requires network access. See the [reference guide](../reference/README.md) for node-level verification.

## Scheduled candidate

The Python constructor accepts `compiled_curve="scheduled"` for the
46,302-byte full-mode lock. The CLI option is `--scheduled-curve`.
The wallet fills the 20-byte owner HASH160 in a fixed template.
TypeScript, Rust and Go recognize the template and use their existing
signer callbacks for ordinary ForkID ALL payments.
[Template layout](../template/candidates/scheduled-layout.json)
· [Payment vector](../template/candidates/scheduled-spend-all.json)

In the Python reference, `sign_spend(..., compress_otda="paired")` enables
output reconstruction in version 2 Chronicle OTDA transactions using ALL
or paired SINGLE. SINGLE reconstructs its same-index output and retains
the null placeholders that precede it in the preimage. Version 1, unpaired
SINGLE, and unknown output formats use their existing encodings. The
signer receives the original digest, and its signature goes into the witness.

Version 2 OTDA ALL can reconstruct both the 47,510-byte compiled template
and the 46,302-byte scheduled template. The wallet compares the literal,
single-template and two-template encodings. A two-input, two-output
payment with one output of each template measures 110,302 bytes, down
from 195,028 bytes with single-template reconstruction.
