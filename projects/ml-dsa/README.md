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

The fixed-key payment lock is about 926 kB in the measured fixtures. Evaluate script size, transaction size and validation policy on the target node or miner before choosing this format for a funded workflow. [Funded regtest method](../../docs/benchmark.md#funded-regtest-measurements)

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
Because the canonical lock is 926,403 bytes, the native node requires an
explicit script policy limit for the replay.
The shared launchers set `-maxscriptsizepolicy=100000000` alongside the existing
transaction-size and stack-memory limits. An isolated regtest can repeat the
matrix through `REGTEST_COOKIE` and `REGTEST_URL`.
[Shared regression evidence](../../docs/chronicle-regression.md)

## Script sizes

These are fixture-specific Script bytes, excluding transaction serialization.
The SHAKE measurements fix the input and output lengths at compile time.

| Component | Bytes |
|---|---:|
| NTT | 46,134 |
| Inverse NTT | 43,500 |
| Negacyclic ring product | 141,915 |
| Fixed-key verification equation | 500,794 |
| Signature decoding | 62,723 |
| SampleInBall with the 221-byte budget | 70,229 |
| Apply hints and encode high bits | 89,687 |
| SHAKE256, 832-byte input to 32-byte output | 176,542 |
| Complete payment lock | 926,403 |
| One-input BIP143 `ALL` unlock | 2,588 |

The fixed-key equation accepts packed challenge and response coefficients and
produces four canonical residual polynomials. The arithmetic and SHAKE scripts
are also independently replayable. [Deterministic fixture](versions/v0.1.0/deterministic.json)

### Signed-residue NTT experiment

`transform_script(signed_residues=True)` keeps intermediates as signed
representatives of the field and restores canonical coefficients before
serialization. The forward transform measures 38,454 bytes and the inverse
40,940 bytes. The fixed-key equation measures 452,154 bytes for the same
fixture, down from 500,794. Independent polynomial evaluation and complete
input replay check the canonical result, including zero and alternating
field-boundary coefficients. This experiment lives at the arithmetic
kernel boundary. Full payment and external signature conformance use the
canonical verifier.

## Developer and wallet integration

Use `locking_script(public_key)` to create a payment output and retain the
authenticated 1,312-byte public key. Before authorizing a payment, compare the
funding output with the script generated for that key, verify its amount and
outpoint, and apply the wallet's confirmation requirement. Call `sign_payment`
for a single-input payment or `sign_spend` for an already prepared input.
The callback signs the supplied 32 bytes as the message with Pure ML-DSA-44
and an empty context. It returns the 2,420-byte standard signature for
verification and witness assembly. The message verifier can separately test
variable-length messages and permitted contexts. [Wallet source](reference/payment.py)

Fixed-key script generation can serialize different keys to slightly different
lengths, so the single-lock arithmetic fixture above and the payment rows
below have different values. In OTDA ALL, each witness also carries the full
serialized outputs. That cost dominates the 5,563,725-byte two-in, two-out
fixture. The signed-residue NTT numbers describe a component experiment.

## Complete transactions and stack measurements

These deterministic fixtures use commit `beeb4dd`. BSV Node 1.2.3 and the project's pinned chain-gang validate the complete inputs. The node replays scripts with supplied prevouts. Funded mempool and mining tests have separate records. Scripts and transactions are measured in bytes. Script sizes follow input and output order. `× n` indicates n equal sizes. Stack peaks refer to input zero, with independent peaks for main-stack items, altstack items, and combined payload. The development evaluator measures stack payload bytes on the successful path. The evaluator stops at `OP_GREATERTHANOREQUAL`, so stack results are unavailable for both ML-DSA-44 rows.

| Template and mode | Inputs×outputs | Previous locks | Unlocks | New locks | Total | Main / alt items | Stack payload |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `pure-ml-dsa-44` · `0x41` | 2×2 | 926,412 × 2 | 2,588 × 2 | 926,410 / 926,414 | 1,858,122 | — / — | — |
| `pure-ml-dsa-44` · `0x61` | 2×2 | 926,421 / 926,413 | 1,855,385 × 2 | 926,416 / 926,413 | 5,563,725 | — / — | — |

## Marginal and lifecycle costs

Each marginal cell shows the **change in total bytes (output locks / input unlocks / other bytes)**. Other bytes include values, outpoints, sequence numbers, and CompactSize fields. Previous locks identify the coins being spent and belong to their funding transactions. Both lifecycle totals include native P2PKH funding and exit. The second adds one payment between project outputs.

| Template and mode | Added-input shape | Added-input bytes | Added-output shape | Added-output bytes | Fund and exit | One turnover |
| --- | --- | --- | --- | --- | --- | --- |
| `pure-ml-dsa-44` · `0x41` | 3×2 | 2,627 (-4 / 2,588 / 43) | 2×3 | 926,418 (926,405 / 0 / 13) | 1,858,346 | 3,716,464 |
| `pure-ml-dsa-44` · `0x61` | 3×2 | 1,855,545 (-2 / 1,855,502 / 45) | 2×3 | 2,779,266 (926,409 / 1,852,844 / 13) | 1,858,363 | 7,422,076 |

[Unified benchmark and reproduction](../../docs/benchmark.md)
