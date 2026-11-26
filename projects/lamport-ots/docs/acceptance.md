# Lamport OTS acceptance

The fixture checks the repository's wire encoding and payment commitment rules
against independently specified outcomes. The tests use public deterministic
test keys. [Wire and payment rules](spec.md)

## Universal payment lock

The domain fixes the input being signed at index one of a two-input transaction
with one or two outputs. The fixture crosses all twelve advertised sighash
bytes, versions 1 and 2, and both output shapes. It keeps the initial witness
fixed across the following edits.

| Edit | Modes that accept |
| --- | --- |
| None | All twelve |
| Change the first output amount | NONE or SINGLE |
| Change the other input sequence | NONE, SINGLE, or ANYONECANPAY |
| Change the other outpoint and provide the corresponding prevout | ANYONECANPAY |
| Change the signing input sequence | None |
| Change locktime | None |
| Swap version 1 and 2 | None |
| Add or remove the output at index one | NONE |
| Change the output amount at index one, when present | NONE |

The paired shape has nine edit choices and the unpaired shape has eight. This
gives `12 × 2 × (9 + 8) = 408` rows. For each version, the table yields
`24 + 16 + 20 + 12 + 8 + 4 = 84` acceptances. The full expected result is
168 acceptances and 240 rejections. The test constructs the expected row set
and acceptance set from these axes and verdict rules. It rejects unknown or
repeated rows, requires the observed row set to equal the entire expected
set, and compares each chain-gang and BSV Node result with the expected
verdict. [Fixture](../reference/test_acceptance.py)

## Digest-only and legacy locks

For each index and starting commitment choice, the digest-only fixture flips
the digest bit alone, substitutes the opposite signature slot alone, and
changes both together. It constructs the expected signature from the raw key
blocks and checks the Python signer, Python verifier and generated Script.
The declared domain is `2 × 256 × 3 = 1,536` rows. The complete row-set
comparison covers 512 acceptances and 1,024 rejections, in addition to the
two unchanged baseline signatures.

For the legacy BIP143 ALL lock, the fixture checks the exact inventory of 32
existing scenarios, including the two expected valid rows, against chain-gang
and BSV Node. Its scope is the named inventory in the test.

## Reproduce

From the repository root, install the pinned dependencies in a Python
environment and run the local and native checks.

```sh
python -m pip install -r projects/lamport-ots/reference/requirements.txt
python -m unittest discover -s projects/lamport-ots/reference -p test_acceptance.py -v
bash projects/lamport-ots/reference/verify.sh
```

The local command exercises the standalone fixture and chain-gang. The native
launcher supplies BSV Node 1.2.3 regtest, explicit post-Chronicle verification
flags and synthetic prevouts. The Apple Container launcher runs the same tests
with `bash projects/lamport-ots/reference/verify_apple.sh`.

Coverage is exact for these defined domains. Other transaction shapes,
simultaneous field edits, different activation or relay policy configurations,
and arbitrary Script byte strings remain outside this proof.

## Executed coverage audit

On Linux, BSV Node 1.2.3 and chain-gang at the pinned revision
`5cb8c6e410dbfad1c619cec3ca54d1bcaacd4eb7` agreed on all 408 universal and 32
legacy rows. The native suite ran seven test methods. The twelve existing
local methods, three acceptance methods, and two repository layout checks
also passed.

Omitting just the paired-output edit at version 1 and mode `0x41` failed
the row-set equality check with 407 of 408 rows visited. Leaving the original
output in every first-output mutation row produced 16 verdict failures.
To reproduce the omitted-row check, run this from the reference directory
without a configured regtest.

```sh
python - <<'PY'
import io
import unittest
from unittest.mock import patch
import test_acceptance as fixture

original = fixture.edited_payments
skipped = False

def omit_once(*args):
    global skipped
    for row in original(*args):
        if row[0] == 'paired_output' and not skipped:
            skipped = True
            continue
        yield row

with patch.object(fixture, 'edited_payments', omit_once):
    test = fixture.LamportAcceptance('test_universal_payment_decisions_cover_the_declared_domain')
    result = unittest.TextTestRunner(stream=io.StringIO()).run(unittest.TestSuite([test]))
assert skipped and len(result.failures) == 1 and not result.errors
assert "(1, True, 65, 'paired_output')" in result.failures[0][1]
print("Exactly one omitted row detected (407/408)")
PY
```
