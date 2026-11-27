# Pure ML-DSA-44

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md) · [Versions](versions/index.json)

## Developer resources

**[Wallet SDK quickstart](docs/sdk.en.md#quickstart)** · [Unified wallet SDK](../../sdk/README.md#quickstart)

Make a lock from the raw ML-DSA-44 public key and sign the payment message in Pure mode with an empty context.

[Protocol](docs/developer.en.md#protocol) · [Security](docs/developer.en.md#security) · [Verify](#reproduce-the-checks) · [Transaction costs](#complete-transactions-and-stack-measurements)

**Status** · v0.11.0.

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

The fixed-key payment lock is about 252 kB in the measured fixtures. Evaluate script size, transaction size and validation policy on the target node or miner before choosing this format for a funded workflow. [Funded regtest method](../../docs/benchmark.md#funded-regtest-measurements)

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
python projects/ml-dsa/reference/test_boundaries.py -v
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

| Component | PR #68 baseline | Compact `879b52c` | v0.2.0 | v0.3.0 | v0.4.0 | v0.5.0 | v0.6.0 | v0.7.0 | v0.8.0 | v0.9.0 | v0.10.0 | v0.11.0 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Fixed-key verification equation | 500,794 | 310,198 | 257,122 | 137,874 | 137,874 | 137,874 | 124,849 | 124,849 | 127,876 | 122,627 | 122,627 | 122,627 |
| Signature decoding | 62,723 | 46,392 | 36,152 | 36,152 | 28,224 | 28,224 | 28,224 | 28,224 | 6,007 | 6,007 | 6,007 | 6,007 |
| SampleInBall with the 221-byte budget | 70,229 | 63,701 | 61,101 | 61,101 | 61,101 | 45,211 | 43,512 | 40,827 | 40,827 | 40,827 | 30,638 | 25,717 |
| Apply hints and encode high bits | 89,687 | 66,135 | 66,135 | 66,135 | 31,087 | 31,087 | 31,087 | 23,389 | 23,389 | 11,829 | 11,829 | 11,829 |
| Standalone Keccak-f[1600] with little-endian lanes | 25,097 | 21,833 | 20,533 | 20,533 | 20,533 | 12,588 | 12,588 | 12,588 | 12,588 | 12,588 | 12,588 | 12,588 |
| SHAKE256, 832-byte input to 32-byte output | 176,542 | 153,694 | 144,594 | 144,594 | 144,594 | 88,979 | 81,821 | 79,133 | 79,133 | 79,133 | 74,766 | 74,023 |
| Current-input binding | 718 | 718 | 718 | 718 | 718 | 506 | 506 | 506 | 506 | 506 | 506 | 506 |
| Complete payment lock | 926,403 | 663,284 | 586,981 | 467,733 | 424,757 | 345,095 | 322,447 | 308,992 | 289,802 | 272,993 | 257,662 | **251,704** |
| One-input BIP143 `ALL` unlock | 2,588 | 2,588 | 2,588 | 2,588 | 2,588 | 2,588 | 2,588 | 2,588 | 2,588 | 2,588 | 2,588 | 2,588 |

The Forth payment entry uses `stack` optimization on upstream revision `889ff6e`. v0.5.0 emits Keccak's theta and chi over five-lane rows. Theta masks the one-bit shifts at lane boundaries, and rho and pi operate on individual lanes. Ten permutations in the payment lock save 79,450 bytes. The shared compact input binding saves another 212 bytes. [Forth entry](reference/payment-lock.fth) · [v0.4.0 measurements](versions/v0.4.0/measurements.json) · [v0.5.0 measurements](versions/v0.5.0/measurements.json)

v0.6.0 applies two adjacent NTT butterfly stages to each four-coefficient group at the top of the stack. Bounds on the centered transforms allow a modulus-aligned offset that keeps each packed lane below its sign bit, saving 13,025 bytes together with the paired butterflies. SHAKE keeps its internal lanes big-endian across permutations and converts only absorbed and squeezed bytes, saving another 9,623 bytes in the lock. [v0.6.0 measurements](versions/v0.6.0/measurements.json)

v0.7.0 applies each sparse hint by shifting its residue by one rounding interval modulo q−1, then encodes the high bits in one scan with shared constants. This saves 7,698 bytes. Keeping the challenge coefficients in one signed byte each saves 1,917 bytes. Keccak applies chi as soon as each rho/pi row is ready and moves it off the main stack, saving 384 bytes per permutation and 3,840 bytes per lock. [v0.7.0 measurements](versions/v0.7.0/measurements.json)

v0.8.0 checks the strict response norm in 64-coefficient blocks in the original 18-bit encoding. A guard bit in each lane prevents borrows between lanes. The NTT reads the checked wire response directly, reuses the modulus across pointwise products, and concatenates fixed-width inverse input lanes. The signature decoder is 22,217 bytes smaller and the equation grows by 3,027 bytes, for a net reduction of 19,190 bytes. [v0.8.0 measurements](versions/v0.8.0/measurements.json)

v0.9.0 complements the wire response and subtracts one bias from all four packed response lanes at once. The NTT reuses the forward bias and modulus at fixed stack depths. Together with the fixed-depth inverse bias, this saves 5,249 bytes in the equation. A reciprocal multiplication rounds 64 hint-adjusted residues in parallel. A second multiplication gathers four six-bit digits at a time into the FIPS 204 encoding, saving 11,560 bytes in hint application and encoding. [v0.9.0 measurements](versions/v0.9.0/measurements.json)

v0.10.0 makes a mask of acceptable draws with a parallel byte comparison, then bisects it to find the first acceptable byte for each SampleInBall selection. The original 221-byte budget still applies, including the sign bytes. This saves 8,683 bytes in the sampler. SHAKE swaps byte groups in parallel when converting the rate block and uses the shorter shift for some Keccak rotations, saving 6,648 bytes in the lock. [v0.10.0 measurements](versions/v0.10.0/measurements.json)

v0.11.0 locates the first accepted draw by subtracting one from the nonzero acceptance mask and XORing the result with the mask. The minimal byte length of the result identifies the draw and saves 4,560 bytes in the sampler. SHAKE constructs zero padding and capacity in Script and absorbs the first block directly into the empty state, saving another 1,398 bytes. [v0.11.0 measurements](versions/v0.11.0/measurements.json)

The arithmetic and SHAKE scripts are also independently replayable. [Deterministic fixture](versions/v0.1.0/deterministic.json)

## Developer and wallet integration

Use `locking_script(public_key)` to create a compact payment output and retain
the authenticated 1,312-byte public key. The wallet recognizes and spends
the eleven earlier generations for that key. Use `locking_script(public_key, legacy=True)`
to reproduce the original v0.1.0 lock bytes. Before authorizing a payment, verify the
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

BSV Node 1.2.3 and the pinned chain-gang validate these transactions with supplied prevouts. Sizes are in bytes and follow input and output order. `× n` indicates n equal sizes. The development evaluator lacks the comparison opcodes needed for stack measurements. The two-input, two-output transactions measured 520,616 bytes for BIP143 ALL and 1,551,168 bytes for OTDA ALL in v0.10.0.

| Template and mode | Inputs×outputs | Previous locks | Unlocks | New locks | Total | Main / alt items | Stack payload |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `pure-ml-dsa-44` · `0x41` | 2×2 | 251,702 / 251,704 | 2,588 × 2 | 251,701 × 2 | 508,700 | — / — | — |
| `pure-ml-dsa-44` · `0x61` | 2×2 | 251,708 / 251,700 | 505,950 × 2 | 251,694 / 251,700 | 1,515,420 | — / — | — |

## Marginal and lifecycle costs

Each marginal cell shows the **change in total bytes (output locks / input unlocks / other bytes)**. Other bytes include values, outpoints, sequence numbers, and CompactSize fields. Previous locks identify the coins being spent and belong to their funding transactions. Both lifecycle totals include native P2PKH funding and exit. The second adds one payment between project outputs.

| Template and mode | Added-input shape | Added-input bytes | Added-output shape | Added-output bytes | Fund and exit | One turnover |
| --- | --- | --- | --- | --- | --- | --- |
| `pure-ml-dsa-44` · `0x41` | 3×2 | 2,635 (4 / 2,588 / 43) | 2×3 | 251,708 (251,695 / 0 / 13) | 508,934 | 1,017,626 |
| `pure-ml-dsa-44` · `0x61` | 3×2 | 506,102 (-4 / 506,061 / 45) | 2×3 | 755,130 (251,697 / 503,420 / 13) | 508,946 | 2,024,357 |

[Unified benchmark and reproduction](../../docs/benchmark.md)
