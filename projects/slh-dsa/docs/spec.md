# SLH-DSA payment format

## Owner authorization

The public key is the 32-byte `PK.seed || PK.root`. The signature uses the
7,856-byte encoding of FIPS 205 `SLH-DSA-SHA2-128s`. Script applies the pure,
empty-context prefix `00 00` to the 32-byte message before it derives the FORS
indices and verifies the hypertree. The message is `SHA256d(preimage)`. An
external signer receives these 32 bytes and signs them as a pure SLH-DSA
message. A single public key can authorize multiple transactions.

## Transaction binding

An unlocking script pushes `preimage`, `signature`, and `selector` in that
order. The ordinary selector is `0`, and the fallback selector is `1`.
Ordinary payments use `0x41` unless the caller selects a different mode.
The signature mode is part of the preimage covered by the owner signature.

| Output coverage | ForkID | ForkID plus ANYONECANPAY | Chronicle OTDA | OTDA plus ANYONECANPAY |
|---|---|---|---|---|
| `ALL` | `41` | `c1` | `61` | `e1` |
| `NONE` | `42` | `c2` | `62` | `e2` |
| `SINGLE` | `43` | `c3` | `63` | `e3` |

The ordinary `scriptCode` is `616168ac`, or `616163ad67ab616168ac` for the
fallback. The two `OP_NOP` instructions separate these digests from Lamport
and WOTS+. With an absent same-index OTDA `SINGLE` output, the fixed public
signature checks the native constant. The owner signs the companion ForkID
`SINGLE` preimage, which commits to the current outpoint and amount and has
zero `hashOutputs`. The transaction binding has the same fixed-r digest
equivalence assumptions as the [Lamport design](../../lamport-ots/docs/security.md).

The detached verifier accepts an arbitrary caller-provided message for
algorithm tests. Payment construction uses the transaction-bound template.
These fixtures use synthetic inputs and public test seeds.

[NIST FIPS 205](https://doi.org/10.6028/NIST.FIPS.205)
