# Wallet SDK reference

[简体中文](reference.zh-CN.md) · [SDK overview](../README.md) · [Integration guide](integration.md)

[Calls and data](#calls-and-data) · [One-time signing](#one-time-signing) · [Troubleshooting](#troubleshooting) · [Replay](#replay)

<a name="calls-and-data"></a>

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

Wallet signing defaults to BIP143 ALL (`0x41`), and `SINGLE` requires an output at the same index. Set `chronicleActive` from the trusted chain context before choosing OTDA. The callback receives `algorithm`, `payloadKind` (`digest` or `message`), `signatureFormat`, `sighash`, `payload`, and the SM2 `userId` when present. Use the operation and encoding for your scheme. [Signing schemes](../README.md#scheme-integrations)

Leave the reconstruction option unset to use the scheme's default. SM2 and Schnorr automatically use reconstruction when it shortens the OTDA unlock. In Go, `CompressOTDA` is a `*bool`, with `nil` for the default. In Rust, `compress_otda` is an `Option<bool>`, with `None` for the default. Use a pointer to `false`, `Some(false)`, or `false` in TypeScript and Python to reproduce the literal encoding.

<a name="one-time-signing"></a>

## One-time signing

For Lamport and WOTS+ in Python, call `sign_once = durable_signer(database, project, spend_key, sign_digest)` to wrap the digest signer. Pass the wrapper as `lambda request: sign_once(request.payload)`. Use the same database and canonical public key across wallet processes and template formats. [One-time signer](../../src/fourthgraph/bsv/one_time_signer.py)

<a name="troubleshooting"></a>

## Troubleshooting and retries

| What you see | What to check |
| --- | --- |
| The bridge fails to launch | Check the absolute interpreter and bridge paths, the checked-out templates, and which interpreter received the scheme's dependencies. Run the offline example with that interpreter. |
| Recognition misses or preparation rejects the request | Check the project and actual prevout bytes. For a prepared spend, verify `inputIndex`, `prevout.vout`, the empty unlocking script and the selected sighash. For `signPayment`, verify that outputs plus fee equal the input amount. |
| The signer returns, then assembly fails | Check whether the callback returned the requested raw or DER bytes and signed the correct digest or message. Preserve the signing state, especially for one-time keys that might already have released a signature. |
| No broadcaster accepts the signed bytes | Verify that the funding outpoints remain spendable and check the broadcaster's policy response. Rebroadcast the exact saved bytes if appropriate. For one-time keys, resolve existing signing state before generating any replacement. |

<a name="replay"></a>

## Replay the baseline

After running the [offline quickstart](../README.md#quickstart), use Node.js 24+, Go 1.23+, and Cargo to replay all four language bindings. The pinned chain-gang package also needs Rust and a C toolchain. Run the commands below from the repository root on Linux x86-64.

```sh
workspace/sdk-venv/bin/python -m pip install -r projects/p2pk-p2pkh-baseline/reference/requirements.txt ecdsa==0.19.1
SCRIPT_LAB_SDK_PYTHON="$PWD/workspace/sdk-venv/bin/python" \
  bash tools/verify_node.sh -- bash sdk/verify_wallet.sh p2pk-p2pkh-baseline
```

The replay compares locking scripts, signer requests and signed transaction bytes in all four clients. It also verifies the public vectors through chain-gang and BSV Node with supplied prevouts. A funded regtest adds UTXO admission and mining under a stated policy. Run that check when your integration depends on relay or block acceptance. [Benchmark and funded regtest guide](../../docs/benchmark.md)
