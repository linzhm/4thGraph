# P2PKH-R1 input acceptance

The fixture evaluates the v0.2.0, v0.1.0 and compiled research P-256 locks
separately at input index 1 of a two-input transaction. It uses public test keys and compares input validation
with the commitments in the [project specification](../docs/spec.en.md#signature-coverage).
The serialized test cases use the reference wallet's signing preimages and an
independent P-256 implementation from `cryptography`. The verdict table uses
the field commitments of each mode.

| Axis | Values |
| --- | --- |
| Transaction version | 1, 2 |
| Output layout | Output at input index, no output at input index |
| Sighash | ALL, NONE or SINGLE × ForkID or OTDA × with or without ANYONECANPAY |
| Rule context | Genesis UTXO and Genesis spend, Genesis UTXO and Chronicle spend, Chronicle UTXO and Chronicle spend |
| Change after preparing the authorization | Unchanged, another input's outpoint, another input's sequence, current sequence, output zero, same-index output, valid signature from a different key, changed signing amount, locktime |

For the unpaired layout, the same-index change adds an output at that index.
The wrong-amount witness uses a fresh signature for the changed amount.

| Requirement | Expected result |
| --- | --- |
| Unchanged authorization | Valid in the applicable rule context. Genesis rejects OTDA, including the unpaired companion path. |
| Another input's outpoint | Only ANYONECANPAY permits the change. |
| Another input's sequence | ANYONECANPAY, NONE and SINGLE permit the change. |
| Current input's sequence or locktime | The change invalidates the authorization. |
| Output zero | ALL commits to this output. NONE and SINGLE at input 1 leave it free. |
| Same-index output | Only NONE permits changing or adding this output. |
| Wrong P-256 signing key | Rejected with the claimed owner's key. |
| Changed amount passed to the signer | Only a direct OTDA digest omits the amount. ForkID and the unpaired OTDA SINGLE companion both commit to it. |
| Witness structure | Each ordinary ForkID/OTDA and both unpaired companion paths reject an extra item, a bad inverse, a flipped or non-boolean selector, higher type bytes, and a correctly signed witness from a different owner. |

The fixture checks the axes for duplicates and requires every observed tuple to
belong to the product and occur once. It then requires the number observed to
equal the product cardinality `2 × 2 × 12 × 3 × 9 = 1,296`. A subset of a finite
set with the same cardinality equals the entire set.
Deliberately omitting one tuple caused the cardinality check to fail at 1,295.

For each template, BSV Node 1.2.3 matched all 1,296 results, with 80 accepted in Genesis and 180
accepted in each Chronicle context. The pinned chain-gang build matched the
432-row Chronicle UTXO subset, with 180 accepts and 252 rejects. The extra
witness checks replay four valid controls through BSV Node and 24 invalid
witnesses through both engines.

From the repository root, run the [standard verification entry point](verify.sh).

```sh
python -m pip install -r projects/p2pkh-r1/reference/requirements.txt
bash projects/p2pkh-r1/reference/verify.sh
```

The proof covers the enumerated product and the stated witness controls.
Arbitrary transactions, encodings, P-256 keys, UTXO histories and network
admission policy require separate evidence.
