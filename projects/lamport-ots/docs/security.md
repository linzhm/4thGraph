# Security boundaries and review notes

## What this experiment establishes

The primitive checks 256 SHA-256 preimages. The payment script additionally checks
a native current-input transaction relation. This is a research implementation;
passing tests is not a security audit or proof of end-to-end post-quantum security.
Python key handling does not offer secure memory erasure or hardware isolation.

## Fixed-r binding: analyze the relation, not the presence of CHECKSIG alone

Let G be the secp256k1 generator, n its order, r=x(G), Q=G and h=int(SHA256d(P)).
Script constructs, rather than accepts from the witness,

```
s0 = (h + r) mod n
s = min(s0, n - s0)
signature = strict-DER(r, s) || authenticated_type
```

It rejects s0=0. Both private key d=1 and nonce k=1 are public by design. This
native ECDSA signature is a transaction-binding gadget, not an owner signature;
Lamport alone supplies the owner's authorization.

For actual native transaction digest z, ECDSA tests the x-coordinate of
R' = ((z+r)/s)G modulo n. Here r+n exceeds the field prime p, so the only curve
points with x mod n=r are G and -G. Consequently acceptance requires

```
z = h (mod n), or z = -h - 2r (mod n).
```

This is a **small digest equivalence class, not literal 256-bit equality**.
Low-s normalization preserves this two-sign ambiguity. Reduction modulo n can
also admit an additional 256-bit representative. To redirect an observed valid
Lamport authorization to different transaction contents, an attacker still needs
a transaction preimage whose native hash hits one of those targets, or must break
Lamport authorization / the hash assumptions. Arbitrary valid ECDSA signatures
for Q do not help: the locking program computes its own fixed-r signature.

This algebra also explains why merely saying “CHECKSIG uses elliptic curves, so
Shor automatically breaks this gadget” is not a sufficient analysis: no unknown
discrete logarithm protects this fixed-key construction. Conversely, this note
is not a formal quantum security reduction. SHA-256 preimage/collision bounds,
chosen-message security, multiple targets, hash composition, one-time state and
consensus semantics all need review before deployment. A 256-bit digest is not a
claim of 256-bit quantum security.

The script validates the sighash type before hashing the preimage. BIP143
branches also enforce the exact preimage length and scriptCode. The native
signature checks apply the selected digest algorithm and its coverage rules.
The binding protects fields committed by the chosen mode. In particular,
NONE lets outputs change, and SINGLE leaves outputs other than the paired one
mutable. ANYONECANPAY lets other inputs change. The default is BIP143 ALL.

For unpaired Chronicle SINGLE, the first native check uses a fixed public
signature to detect the OTDA constant, subject to the same small digest
equivalence class. It supplies no owner authorization on its own. Lamport
signs the BIP143 SINGLE digest with a branch-specific scriptCode and zero
hashOutputs. The final native check enforces that binding, including the
current outpoint and amount. Distinct scriptCode separates the ordinary
and companion modes even where their BIP143 type bytes coincide.

The prepared-input wallet API rejects unpaired SINGLE before calling the
external signer unless the caller passes `allow_unpaired_single=True`.
An unpaired BIP143 or Chronicle SINGLE input commits to no outputs.
Review that scope before approving the one-time signature.

## Unconfirmed parent txids

The txid of a BSV funding transaction includes the serialized unlocking scripts
in all its inputs. Where the applicable rules accept alternate witness encodings,
the same input outpoints and ordered outputs can confirm under a different txid.
Any valid replacement that confirms under a different txid affects an existing child
that spends a Lamport output. The child references the original `txid:vout`, and
moving the spend to the confirmed outpoint changes the required signing digest.
This applies to the legacy, full-key and both committed payment profiles. If a
replacement also changes transaction contents, verify that it still makes the
intended payment.
[Transaction serialization](../../../src/fourthgraph/bsv/transaction.py)

Transactions spending the same inputs compete for those UTXOs. First-seen
information and conflict notifications help monitor a pending parent. Confirm
which version won in the wallet's trusted chain view.
[BSV Node conflict detection](https://github.com/bitcoin-sv/bitcoin-sv/blob/v1.2.3/src/validation.cpp#L1380-L1389)
· [ARC transaction statuses](https://github.com/bitcoin-sv/arc#metamorph-transaction-statuses)

### Recovering a child payment

Before passing a digest to the Lamport signer, obtain the funding transaction
from a trusted chain view and verify that it meets the application's required
confirmation depth. If the original version did not confirm, track its inputs
or known competing txids to locate the confirmed transaction. Check the output
index, amount, and locking script against the intended payment, and verify that
the output remains unspent. If the outpoint changed, update the wallet's record
and mark any child and descendants tied to the old outpoint stale. The same
reconciliation applies after a chain reorganization.

- If the signer still records the key as unused and no signature has been
  disclosed, build and authorize the child using the confirmed outpoint, then
  generate its unlocking script.
- If a signature was already disclosed for the old outpoint, retain the
  consumed-key record and stop that key's signing workflow. Signing the new
  digest with that key would violate the one-time guarantee. Spending the
  recovered output requires an independent path already authorized by the
  locking script. If the script provides no such path, locating the output
  may leave the wallet without a safe spend.

Keep the original signed child for byte-for-byte rebroadcast while its funding
outpoint is still valid. Apply the same confirmation check before signing each
new link in a payment chain.

### Unlocking script encodings

The wallet emits a canonical unlocking script for the transaction it builds.
With functional unlocking, different scripts can leave the same stack for the
lock. Canonical stack values still leave room for different serialized bytes.
Consensus and relay rules govern which encodings are accepted. A new lock with
stricter stack-field checks would require its own script fingerprint and newly
funded outputs.

## One-time means one disclosure, not one confirmed transaction

Never use a key for two messages, two inputs, two UTXOs, fee replacements, alternate
transactions, channels or retries that change the digest. Unconfirmed signatures
already disclose secrets. Backups and process restarts do not reset that fact.

The wallet receives a public key and an external `signer(digest32)` callback.
It checks the funding outpoint and template before calling the signer once,
then verifies the returned signature against the public key. The signer
must persist key consumption before releasing the signature. Persist the
resulting transaction for rebroadcast, and treat callback errors as potentially
consumed keys. A crash may sacrifice availability to prevent a second disclosure.

The reference `OneTimeSigner` demonstrates the one-use rule within a process.
Production use requires durable state that survives restarts, parallel requests,
and rollback. The callback owner must approve the transaction, sighash and fee
before disclosure. A digest alone cannot communicate those choices.

The payment helper rejects change to any recognized profile of the same key.
Script cannot remember that the same public key appears elsewhere. Treat a key
as consumed across profiles as soon as any signature leaves the signer.
The tests deliberately show that two signatures on complementary raw digests
reveal all blocks and allow forgery for any third digest. This is a primitive-level
demonstration, not an assertion that real transaction hashes can be chosen freely.

## Detached digest verifier is intentionally unsafe as a payment lock

An attacker can copy its digest and signature to a different transaction. The node
test proves both differently directed spends pass that verifier. The payment helper requires a canonical transaction-bound template.

## Test scope

Positive/negative tests cover every digest bit and every signature block,
all-zero/all-one/alternating digests, malformed lengths, wrong keys/messages,
concurrent reuse, DER edge values, s=0 rejection, reordered signature blocks,
extra/missing stack items, forged preimages, amounts, sequences, outpoints,
transaction version, locktime, outputs, multiple inputs and fresh-key change.
Both the development interpreter and the pinned independent chain-gang engine
run the complete-input matrix. BSV Node checks the same matrix through verifyscript
with explicit synthetic prevouts; it also demonstrates the detached-proof replay.
The funded regtest covers local mempool admission and mining for direct exits
and for one same-template turnover before exit on the Forth profile.
Both suites use test keys and local regtest data. [Validation receipts](validation.md)
