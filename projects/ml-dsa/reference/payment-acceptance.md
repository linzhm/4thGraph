# ML-DSA-44 payment acceptance

The payment fixture uses a fixed ML-DSA-44 public key and a two-input transaction.
The first input spends an `OP_TRUE` output. The second input spends the
ML-DSA-44 lock. The independent OpenSSL signer signs a 32-byte digest using
Pure ML-DSA-44 and an empty context. Its seed is public test material.

## Complete enumeration of the declared domain

| Axis | Values |
| --- | --- |
| Transaction version | 1 and 2 |
| Sighash and output shape | All 12 supported flags with a matching output. Each of the four `SINGLE` flags is also exercised without a matching output. |
| Synthetic spend and ordered prevout heights | Spend 2 with `(1, 1)`, or spend 4 with `(1, 1)`, `(1, 3)`, `(3, 1)` or `(3, 3)`. Chronicle activates at height 3. |
| Transaction variant | Original, last output value reduced by one satoshi, locktime set to 1, or one challenge bit flipped in the ML-DSA signature. |

The fixture checks all **2 × 16 × 5 × 4 = 640** tuples. It checks the
independent twelve-flag inventory against the supported flags, asserts that
every row belongs to the product, rejects repeat rows, and compares the final
visited set with the entire product. Both the original and each single change
run in every height context. [Executable fixture](test_payment.py)

## Expected decisions

| Output commitment | Original | Last output value change | Locktime change | Signature challenge bit change |
| --- | --- | --- | --- | --- |
| `ALL` | Accept | Reject | Reject | Reject |
| `NONE` | Accept | Accept | Reject | Reject |
| `SINGLE` with matching output | Accept | Reject | Reject | Reject |
| `SINGLE` without matching output | Accept | Accept | Reject | Reject |

The table applies where the sighash family is active. Before Chronicle,
all OTDA rows reject, including unpaired `SINGLE` with the companion BIP143
binding. After applying the activation rule, 144 original transactions and 72
output changes must pass. The other 424 rows must fail. The acceptance table
uses declared commitment rules. Chain-gang and optional Lean and native Node
replays compare each actual decision to those rules. Rejection in chain-gang
must come from script evaluation, so a different transaction or fixture error
still fails the test. The node replay also checks the returned flag word.

An in-memory mutation omitted a single tuple and triggered the exact-set
assertion. A second mutation marked the original `ALL` payments as invalid.
Chain-gang exposed all 36 wrong expected decisions, and the verdict-count
assertion failed.

The exhaustive claim covers this finite product. Other message sizes, contexts,
keys, input shapes, transaction fields and arbitrary malformed encodings are
outside that product. The ACVP and Wycheproof fixtures provide separate
primitive conformance evidence for their published cases. The ACVP driver
checks unique group and case IDs and matching test ID sets against the answer
file. The Wycheproof driver checks unique case IDs and the published case count.
[NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)

## Boundary rejection

The boundary suite runs 92 vectors through each of three activation contexts.
The vectors contain 15 valid controls and 77 expected rejections. They cover
signed integers that fit or overflow the 3-, 26-, and 104-byte serialization
widths, noncanonical NTT residues, packed response norms, hint lengths and
ordering, negative and out-of-range hint indices, and exhausted or malformed
sampler input. SHAKE cases check the exact message length at a rate boundary.
Each rejection fixture ends in `OP_1` and requires script execution to fail
before that point. The chain-gang assertions check the exact `OP_NUM2BIN`
failure for numeric overflow and the `OP_SPLIT` failures for invalid indices.
[Boundary suite](test_boundaries.py)

The payment suite also checks one valid BIP143 ALL payment and one valid OTDA
ALL payment, then tests eight malformed signature encodings against each.
All 16 mutations must fail with their transaction and preimage held fixed.
[Payment suite](test_payment.py)

## Replay

```sh
python -m pip install -r tools/requirements-chronicle.txt
PYTHONPATH=src:.:projects/ml-dsa/reference python -m unittest -v test_payment
PYTHONPATH=src:.:projects/ml-dsa/reference bash tools/verify_node.sh test_payment
REGTEST_CHRONICLE_HEIGHT=3 PYTHONPATH=src:.:projects/ml-dsa/reference bash tools/verify_node.sh test_boundaries
```

Set `ML_DSA_BSVS` to the absolute path to the Lean `bsvs` executable to add
its independent verdict to every row. Set `ML_DSA_OPENSSL` when the installed
ML-DSA-capable OpenSSL is outside the default path. The native replay uses
explicit synthetic prevouts through `verifyscript` on a peerless regtest.

## Recorded replay

The 640 rows matched for the baseline lock on Linux x86-64 with the
[pinned chain-gang build](../../../tools/requirements-chronicle.txt),
BSV Node 1.2.3 (`101020300`), and Lean `bsvs` from revision
`1c051eaef1077cc95e5d1618686d5efacc4aa097`. OpenSSL 3.5.7 generated the test signatures.
The pinned corpora also matched 15/15 ACVP cases in Python and Script and
80/80 Wycheproof cases in Python.

The compact lock and the Forth locks from v0.2.0 through v0.11.0 each matched
all 640 rows with the same chain-gang pin and BSV Node 1.2.3. The isolated node used
`-maxstdtxvalidationduration=5000` and `-maxnonstdtxvalidationduration=7000`.
The v0.11.0 suite reproduced all eleven earlier locks' SHA-256 fingerprints and
spent each in BIP143 ALL, OTDA ALL and unpaired OTDA SINGLE on both engines.
BSV Node and chain-gang matched all 276 boundary checks and the 18 additional
payment checks. [v0.11.0 measurements](../versions/v0.11.0/measurements.json)
