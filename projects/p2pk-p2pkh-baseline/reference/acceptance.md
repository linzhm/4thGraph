# Native P2PK and P2PKH acceptance evidence

The [acceptance test](test_acceptance.py) uses the canonical compressed-key
locks from the baseline and synthetic previous outputs. Every row constructs
a complete spending input. The other input uses an `OP_TRUE` previous output.
The pinned chain-gang binding checks each transaction with its parents
and explicit Chronicle heights.
BSV Node 1.2.3 can replay the target input with the same previous output via
`verifyscript` using explicit script flags.

## Reproduce

From the repository root:

```sh
uv run --no-project --with-requirements projects/p2pk-p2pkh-baseline/reference/requirements-acceptance.txt \
  python -m unittest discover -s projects/p2pk-p2pkh-baseline/reference -p test_acceptance.py -v
```

For a peerless Linux x86-64 regtest using the shared launcher:

```sh
PYTHONPATH=.:projects/p2pk-p2pkh-baseline/reference \
  uv run --no-project --with-requirements projects/p2pk-p2pkh-baseline/reference/requirements-acceptance.txt \
  bash shared/verify_node.sh test_acceptance
```

The same test accepts `REGTEST_COOKIE` and an optional `REGTEST_URL` for an
already-running isolated node. It checks the RPC verdict and reported flags
for every row. All keys are public test fixtures.

The generator and acceptance tests use the same shared Chronicle pin,
including the explicit context API and unpaired OTDA SINGLE support.
The original PyPI control remains available separately for reproducing
the offline vector. In this acceptance fixture, that build rejected valid
unpaired OTDA inputs with `input out of tx_out range`.
[Acceptance dependency](https://github.com/linzhm/chain-gang/tree/74676b9c002c452e7f21a9ed9265f4972bef03f6)

## Complete enumeration of the declared domain

| Axis | Values exercised |
| --- | --- |
| Lock and witness public key | P2PK signature only, P2PKH with matching key, P2PKH with different key |
| Original spending transaction version | 1, 2 |
| Controlled input index | 0, 1 |
| Sighash byte | ForkID and Chronicle OTDA crossed with ALL, NONE, SINGLE and with or without ANYONECANPAY |
| Signing key | Lock owner's key, a different key |
| Transaction or signing data | Unchanged, changed version, locktime, current or other sequence, current or other outpoint, signed amount, current or other output |

Each fixture starts with two inputs and two outputs and has an output at the
controlled input's index. Each mutation changes one designated transaction
field, or supplies an incorrect amount to the signer while the verifier uses
the real previous amount. The outpoint cases use a different synthetic parent
with the same locking conditions and amount.

The product contains `3 × 2 × 2 × 12 × 2 × 10 = 2,880` rows. The test checks
the axis sizes and distinct values, verifies every visited row belongs to
the product, and asserts every row is visited once. A set of 2,880 distinct
members of a domain of size 2,880 exhausts that domain. A rejecting row
must fail script validation. RPC replay must return one result for each row
and agree with the same expected verdict for every input.

## Expected verdict

A row can pass only with the owner's signature, the matching public key
where required, and a change outside the signature's commitment. The
commitment table predicts digest equality independently of the serializer.
The test checks that prediction separately before asking either engine
to validate the spend. It generates canonical low-S ECDSA signatures using
the cryptography library with the public test key scalars and verifies each
signature with that library before packaging the witness.

| Mutation | When the committed digest is preserved |
| --- | --- |
| Unchanged | Every mode |
| Version, locktime, current sequence or current outpoint | No mode |
| Other sequence | ANYONECANPAY or a base mode other than ALL |
| Other outpoint | ANYONECANPAY |
| Incorrect amount supplied to signer | Chronicle OTDA |
| Current output | NONE |
| Other output | NONE or paired SINGLE |

The preserved rows per lock, version and index for the correct signing key
and witness are `12 + 10 + 6 + 6 + 4 + 8 = 46`. The two locks, two versions and
two input positions yield 368 accepted rows and 2,512 rejected rows.

## Boundary slices

| Domain | Rows | Expected result |
| --- | ---: | --- |
| Unpaired SINGLE with the owned input at index 1 | 80 | Two locks, two transaction versions, four SINGLE flags and five mutations. Both families accept the original and an earlier output change. Only OTDA accepts a change to the current sequence. Adding the indexed output and signing a different digest both fail. 40 accept and 40 reject. |
| Chronicle activation | 192 | Two locks and two versions, with 12 paired modes and four unpaired SINGLE modes, in three contexts. The cases cover pre-activation spend, post-activation spend of an older UTXO and post-activation spend of a new UTXO. Before activation ForkID passes and OTDA fails. Both pass after activation. 160 accept and 32 reject. |

Each slice uses the owner's key and the correct witness. Unpaired native
OTDA SINGLE uses the constant-one digest. ForkID uses a transaction
preimage with zero hashOutputs. The fixture exercises both cases with the
native locks. [BSV Node 1.2.3 sighash implementation](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L2034)

The coverage checks detected an omitted paired row with `2879 != 2880`.
Making the oracle claim that every current-output change preserves the
digest produced 192 assertion failures. In Linux x86-64 regtest, BSV Node
1.2.3 version `101020300` and the pinned chain-gang build agreed with all
3,152 expected verdicts across the three matrices.

The completeness claim applies to these three finite domains. It excludes
arbitrary key and signature encodings, combined mutations, pre-Genesis
conditions, mempool admission and funded UTXO validation.
