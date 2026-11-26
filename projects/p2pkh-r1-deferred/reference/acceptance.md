# P2PKH-R1-Deferred activation acceptance

The fixture activates input 1 of a two-input transaction into its corresponding
R1 output, with a sponsor input at index 0. It evaluates both hash-only and full-key
funding layouts against both R1 target versions for the earlier assembly,
Forth `baseline` and `safe`, and the fixed v0.3.0 `stack` template. The expected decisions follow the
[activation specification](../docs/spec.en.md#spending-the-short-lock).

| Axis | Values |
| --- | --- |
| Funding layout | Hash-only and full-key header |
| Target R1 version | v0.1.0, v0.2.0 |
| Transaction version | 1, 2 |
| Sighash | ALL, NONE or SINGLE × BIP143 or OTDA × with or without ANYONECANPAY |
| Rule context | Genesis UTXO and Genesis spend, Genesis UTXO and Chronicle spend, Chronicle UTXO and Chronicle spend |
| Activation case | Unchanged, fresh witness for wrong target amount, fresh witness for wrong recipient script, missing target, changed sponsor output, changed activation sequence, fresh witness with wrong binding amount, extra stack item, fresh witness for the same owner at the wrong R1 version |

An unchanged witness passes in the applicable context. The Genesis context
rejects all OTDA modes. The mandatory BIP143 SINGLE binding must always commit
to the equal-value target at the activation input's index. The fixture supplies
fresh preimages for wrong target amounts, scripts and template versions below the wallet's preflight
to exercise the lock's own check. Changing the sponsor output with a stale
authorization is allowed by NONE and SINGLE. ALL catches the change through
its selected digest. The remaining mutations must all fail.

The test rejects duplicated axis values, asserts that each visited tuple
belongs to the product and occurs once, then checks the exact product size
`2 × 2 × 2 × 12 × 3 × 9 = 2,592` per build. The [ordinary R1 acceptance matrix](../../p2pkh-r1/reference/acceptance.md)
covers the subsequent recipient signature on the activated output.

BSV Node 1.2.3 matched all 10,368 results. Each build had 80 accepts in Genesis
and 160 accepts in each Chronicle context. The pinned chain-gang build
`8b60b71a` matched the 3,456-row Chronicle UTXO subset, with 160 accepts and
704 rejects per build. Additional cases cover malformed preimage and auxiliary
encodings, mismatched ANYONECANPAY bits, stale selected digests, and a zero
target commitment.

From the repository root, run the [standard verification entry point](verify.sh).

```sh
python -m pip install -r projects/p2pkh-r1-deferred/reference/requirements.txt
bash projects/p2pkh-r1-deferred/reference/verify.sh
```

The replay uses explicit previous outputs and the declared two-input fixtures.
