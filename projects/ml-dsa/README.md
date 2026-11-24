# ML-DSA-44 payment experiment

The Python reference verifies Pure ML-DSA-44 with the FIPS 204 public-key and
signature encodings. The raw public key is 1,312 bytes and the raw signature is
2,420 bytes. The OpenSSL fixture uses a public test seed and deterministic
signing. Payment signing calls an external signer with a 32-byte transaction
digest as the Pure ML-DSA message and the empty context. The caller authenticates
the funding transaction and approves the transaction intent. [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)

The generated BSV Script decodes the signature, checks the response norm and
canonical hints, derives the challenge polynomial, and reconstructs and hashes
the commitment. It precomputes the matrix and transformed public-key
polynomials from the fixed public key when generating the lock. The payment
template binds the digest to the current input with the shared fixed-r PUSHTX
implementation. It supports the twelve ForkID and Chronicle OTDA sighash
combinations and uses the companion ForkID binding for unpaired OTDA `SINGLE`.
[Transaction-binding construction](../../shared/pushtx.py)

## Sampling boundary

The Script verifier checks the first 136 bytes of the SHAKE256 output for
SampleInBall. After the eight sign bytes it has 128 candidate indices. It
rejects if it cannot make all 39 selections in that budget. In the
independent-uniform byte model, exhaustion requires at least 90 rejections,
with rejection probability at most 38/256 per candidate. A binomial tail
therefore bounds modeled exhaustion by about 2^-147.77. Valid FIPS signatures
outside the bounded sampler's acceptance set require a fresh signature.
The wallet checks the same budget before emitting the witness. The off-chain
FIPS reference keeps squeezing as needed. [Sampler](reference/challenge_script.py)

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

The first suite compares the independent Python verifier and deterministic
test fixtures with OpenSSL. Both OpenSSL 3.5.9 and 4.1.0 passed. A separate
run of the pure verifier matched all 80 standard ML-DSA-44 Wycheproof vectors.
To repeat it, pass the pinned corpus below to
`python projects/ml-dsa/reference/check_wycheproof.py <vectors.json>`.
[Wycheproof corpus](https://github.com/C2SP/wycheproof/blob/8e7fa6f87e6993d7b613cf48b46512a32df8084a/testvectors_v1/mldsa_44_standard_verify_test.json)

The arithmetic suite uses 60 complete synthetic inputs covering transaction
versions 1 and 2, spend heights before, at and after Chronicle activation, and
both expected outcomes. The contextual chain-gang build is pinned at
`74676b9c002c452e7f21a9ed9265f4972bef03f6`. Native BSV Node and executable
Lean validation are pending. [Shared regression evidence](../../shared/chronicle-regression.md)

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
| Bounded SampleInBall | 37,296 |
| Apply hints and encode high bits | 89,687 |
| SHAKE256, 832-byte input to 32-byte output | 176,542 |
| Complete payment lock | 893,470 |
| One-input ForkID `ALL` unlock | 2,588 |

The fixed-key equation accepts packed challenge and response coefficients and
produces four canonical residual polynomials. The arithmetic and SHAKE scripts
are also independently replayable. The detached verifier accepts a supplied
message and is intended for development checks. [Deterministic fixture](template/deterministic.json)
