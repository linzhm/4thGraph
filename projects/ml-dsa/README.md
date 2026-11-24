# Pure ML-DSA-44

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
and hashes the commitment. The payment wrapper supports all twelve ForkID and
Chronicle OTDA sighash combinations. Unpaired OTDA `SINGLE` uses the companion
ForkID binding. The wallet checks the funding output before requesting an
external signature. The caller authenticates the funding transaction and
approves the transaction intent.
[Transaction-binding construction](../../shared/pushtx.py)

## Sampling boundary

Python and Script use the same 221-byte SHAKE256 output budget specified by
FIPS 204 Appendix C, Table 3. It includes eight sign bytes and up to 213
candidate indices for 39 selections. At exhaustion the verifier fails. The
Script sampler discards its intermediate stack values before failing.
[Sampler](reference/challenge_script.py)

## Reproduce the checks

```sh
python -m unittest discover -s projects/ml-dsa/reference -p test_mldsa.py -v
python -m pip install -r shared/requirements-chronicle.txt
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

```sh
python projects/ml-dsa/reference/check_wycheproof.py <vectors.json>
PYTHONPATH=. python projects/ml-dsa/reference/check_acvp.py <prompt.json> <expectedResults.json>
```

[Pinned Wycheproof corpus](https://github.com/C2SP/wycheproof/blob/8e7fa6f87e6993d7b613cf48b46512a32df8084a/testvectors_v1/mldsa_44_standard_verify_test.json)
· [NIST ACVP sigVer corpus](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-sigVer-FIPS204)

The ACVP inputs used Git blob IDs `22b0803253f7aa24644229acd04c387d260e874a`
for `prompt.json` and `dba8bcfe5f090503c9390701c11677389752cecd` for
`expectedResults.json`.

The updated chain-gang build and the executable bsv-script-lean evaluator
each matched all 192 payment checks. The matrix covers transaction versions
1 and 2, Genesis ForkID and Chronicle OTDA, unpaired `SINGLE`, and mutations.
The chain-gang primitive suites also passed.
Set `ML_DSA_BSVS` to the executable `bsvs` path to repeat the Lean comparison.
Native BSV Node 1.2.3 RPC validation remains pending. An isolated regtest
can run the same matrix through `REGTEST_COOKIE` and `REGTEST_URL`.
[Shared regression evidence](../../shared/chronicle-regression.md)

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
| One-input ForkID `ALL` unlock | 2,588 |

The fixed-key equation accepts packed challenge and response coefficients and
produces four canonical residual polynomials. The arithmetic and SHAKE scripts
are also independently replayable. [Deterministic fixture](template/deterministic.json)
