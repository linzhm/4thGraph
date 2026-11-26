# Pure ML-DSA-44

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md) · [Versions](versions/index.json)

## Developer resources

**[Wallet SDK quickstart](docs/sdk.en.md#quickstart)** · [Unified wallet SDK](../../sdk/README.md#quickstart)

Make a lock from the raw ML-DSA-44 public key and sign the payment message in Pure mode with an empty context.

[Protocol](docs/developer.en.md#protocol) · [Security](docs/developer.en.md#security) · [Verify](#reproduce-the-checks) · [Transaction costs](#complete-transactions-and-stack-measurements)

**Status** · v0.1.0 development baseline.

The verifier uses the FIPS 204 Pure ML-DSA-44 public-key and signature
encodings. A public key is 1,312 bytes and a signature is 2,420 bytes.
The OpenSSL fixture uses a public test seed and deterministic signing.
[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)

| Entry point | Purpose |
|---|---|
| `fips204.verify(public_key, message, signature, context=...)` | Verify a byte message and optional context in Python. |
| `script.verify_message_script(public_key, message_bytes, context=...)` | Compile the Script verifier. The public key, byte length and context are fixed at generation. The message and signature go on the stack. |
| `script.locking_script(public_key)` | Bind the same verifier to the current input. It verifies the signature over a 32-byte transaction digest with the empty context. |

The Script compiler precomputes the matrix and transformed public-key
polynomials. At execution the script checks the signature encoding, response
norm and canonical hints, derives the challenge polynomial, and reconstructs
and hashes the commitment. The payment wrapper supports all twelve BIP143 and
Chronicle OTDA sighash combinations. Unpaired OTDA `SINGLE` uses the companion
BIP143 binding. The wallet checks the funding output before requesting an
external signature. The caller authenticates the funding transaction and
approves the transaction intent.
[Transaction-binding construction](../../src/fourthgraph/bsv/pushtx.py)

## Use cases and trade-offs

Evaluate Pure ML-DSA-44 when measuring FIPS 204 signer interoperability or large-script resource limits. A lab can start with the detached conformance vectors and then run the payment wrapper with the same kind of public key and a dedicated payment signer. The wrapper passes a 32-byte payment message to Pure ML-DSA-44 with an empty context. Key and signature validation, transaction binding, and node admission each have their own evidence. [Reproduction steps](#reproduce-the-checks)

The fixed-key payment lock is about 663 kB in the measured fixtures. Evaluate script size, transaction size and validation policy on the target node or miner before choosing this format for a funded workflow. [Funded regtest method](../../docs/benchmark.md#funded-regtest-measurements)

## Sampling boundary

Python and Script use the same 221-byte SHAKE256 output budget specified by
FIPS 204 Appendix C, Table 3. It includes eight sign bytes and up to 213
candidate indices for 39 selections. At exhaustion the verifier fails. The
Script sampler discards its intermediate stack values before failing.
[Sampler](reference/challenge_script.py)

## Reproduce the checks

```sh
python -m unittest discover -s projects/ml-dsa/reference -p test_mldsa.py -v
python -m pip install -r tools/requirements-chronicle.txt
python projects/ml-dsa/reference/check_chain_gang.py -v
python projects/ml-dsa/reference/test_shake_script.py -v
python projects/ml-dsa/reference/test_signature_script.py -v
python projects/ml-dsa/reference/test_challenge_script.py -v
python projects/ml-dsa/reference/test_payment.py -v
```

The Python verifier matched OpenSSL-generated test fixtures and all 80
standard ML-DSA-44 Wycheproof cases. The bounded Python verifier and the
detached Script verifier matched all 15 NIST ACVP external Pure ML-DSA-44
sigVer cases, including messages up to 8,192 bytes and contexts up to 255 bytes.
The payment format uses the empty context and a 32-byte transaction digest.
Set the variables below to the local corpus files before running the checks.
Use `ML_DSA_OPENSSL` to select a compatible OpenSSL executable.

```sh
python projects/ml-dsa/reference/check_wycheproof.py "$WYCHEPROOF_VECTORS"
PYTHONPATH=src:. python projects/ml-dsa/reference/check_acvp.py "$ACVP_PROMPT" "$ACVP_EXPECTED"
```

[Pinned Wycheproof corpus](https://github.com/C2SP/wycheproof/blob/8e7fa6f87e6993d7b613cf48b46512a32df8084a/testvectors_v1/mldsa_44_standard_verify_test.json)
· [NIST ACVP sigVer corpus](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-sigVer-FIPS204)

The ACVP inputs used Git blob IDs `22b0803253f7aa24644229acd04c387d260e874a`
for `prompt.json` and `dba8bcfe5f090503c9390701c11677389752cecd` for
`expectedResults.json`.

The payment fixture enumerates 640 unique cases across transaction versions 1
and 2, Genesis BIP143 and Chronicle OTDA, paired and unpaired `SINGLE`, ordered
prevout eras, and three single changes. Its coverage record gives the exact
domain and expected decisions. [Payment acceptance](reference/payment-acceptance.md)

Set `ML_DSA_BSVS` to the executable `bsvs` path to repeat the Lean comparison.
The native replay uses an explicit script policy limit. The shared launchers
set `-maxscriptsizepolicy=100000000` alongside the existing
transaction-size and stack-memory limits. An isolated regtest can repeat the
matrix through `REGTEST_COOKIE` and `REGTEST_URL`.
[Shared regression evidence](../../docs/chronicle-regression.md)

## Script sizes

These are Script bytes for identical fixtures, before transaction serialization.

| Component | PR #68 baseline | Compact |
|---|---:|---:|
| NTT | 46,134 | 28,721 |
| Inverse NTT | 43,500 | 29,929 |
| Fixed-key verification equation | 500,794 | 310,198 |
| Signature decoding | 62,723 | 46,392 |
| SampleInBall with the 221-byte budget | 70,229 | 63,701 |
| Apply hints and encode high bits | 89,687 | 66,135 |
| SHAKE256, 832-byte input to 32-byte output | 176,542 | 153,694 |
| Complete payment lock | 926,403 | **663,284** |
| One-input BIP143 `ALL` unlock | 2,588 | 2,588 |

The first pass, at 735,807 bytes, defers NTT reduction until coefficients
are packed and reads each transformed coefficient once for all four rows.
Reusing Keccak lanes at their last use brings the lock to 703,167 bytes.
Decoding the 80 hint slots in one pass and simplifying FIPS 204 `UseHint`
brings it to 663,284 bytes, 28.4% below the baseline. The arithmetic kernel
measurements also retain the signed-residue experiment, whose verification
equation uses 452,154 bytes. [Benchmark adapter](reference/benchmark_adapter.py)

The arithmetic and SHAKE scripts are also independently replayable. [Deterministic fixture](versions/v0.1.0/deterministic.json)

## Developer and wallet integration

Use `locking_script(public_key)` to create a compact payment output and retain
the authenticated 1,312-byte public key. The wallet recognizes and spends
either generation for that key. Use `locking_script(public_key, legacy=True)`
to reproduce the earlier lock bytes. Before authorizing a payment, verify the
funding amount, outpoint and confirmations. Call `sign_payment`
for a single-input payment or `sign_spend` for an already prepared input.
The callback signs the supplied 32 bytes as the message with Pure ML-DSA-44
and an empty context. It returns the 2,420-byte standard signature for
verification and witness assembly. The message verifier can separately test
variable-length messages and permitted contexts. [Wallet source](reference/payment.py)

Fixed-key script generation can serialize different keys to slightly different
lengths. In OTDA ALL, each witness carries the full serialized outputs, which
amplifies the savings from smaller output locks.

## Complete transactions and stack measurements

BSV Node 1.2.3 and the pinned chain-gang validate these compact-lock transactions with supplied prevouts. Sizes are in bytes and follow input and output order. `× n` indicates n equal sizes. The development evaluator lacks the comparison opcodes needed for stack measurements. The two-input, two-output transactions measured 1,858,122 bytes for BIP143 ALL and 5,563,725 bytes for OTDA ALL in the legacy baseline.

| Template and mode | Inputs×outputs | Previous locks | Unlocks | New locks | Total | Main / alt items | Stack payload |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `pure-ml-dsa-44` · `0x41` | 2×2 | 663,293 × 2 | 2,588 × 2 | 663,291 / 663,295 | 1,331,884 | — / — | — |
| `pure-ml-dsa-44` · `0x61` | 2×2 | 663,302 / 663,294 | 1,329,147 × 2 | 663,297 / 663,294 | 3,985,011 | — / — | — |

## Marginal and lifecycle costs

Each marginal cell shows the **change in total bytes (output locks / input unlocks / other bytes)**. Other bytes include values, outpoints, sequence numbers, and CompactSize fields. Previous locks identify the coins being spent and belong to their funding transactions. Both lifecycle totals include native P2PKH funding and exit. The second adds one payment between project outputs.

| Template and mode | Added-input shape | Added-input bytes | Added-output shape | Added-output bytes | Fund and exit | One turnover |
| --- | --- | --- | --- | --- | --- | --- |
| `pure-ml-dsa-44` · `0x41` | 3×2 | 2,627 (-4 / 2,588 / 43) | 2×3 | 663,299 (663,286 / 0 / 13) | 1,332,108 | 2,663,987 |
| `pure-ml-dsa-44` · `0x61` | 3×2 | 1,329,307 (-2 / 1,329,264 / 45) | 2×3 | 1,989,909 (663,290 / 1,326,606 / 13) | 1,332,124 | 5,317,124 |

[Unified benchmark and reproduction](../../docs/benchmark.md)
