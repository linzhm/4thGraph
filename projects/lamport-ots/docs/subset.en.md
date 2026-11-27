# Fixed-weight Lamport one-time signature

[简体中文](subset.zh-CN.md) · [Project overview](../README.md)

## Scope and version

`committed-key-forth-subset` is an opt-in research candidate for Lamport payments with smaller proofs. It uses independent 32-byte random secrets, full 32-byte SHA-256 commitments and an injective fixed-weight code for the 32-byte authorization digest. Lamport described equal-size subsets in his original one-way-function signature paper. This project maps each digest byte to its own subset and keeps the same BSV transaction-binding rules. [Lamport's original paper](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/12/Constructing-Digital-Signatures-from-a-One-Way-Function.pdf) · [Reference signer](../reference/subset.py) · [Payment rules](spec.md#sighash-modes)

## Inputs and encodings

There are 32 groups of 11 slots, one group per digest byte. Every slot has an independently generated secret and its SHA-256 hash. Sort the 11-bit masks that have exactly four set bits by unsigned numerical value. There are 330 such masks. Ten slots would have at most 252 equal-size subsets, too few for a byte. Digest byte `d` selects entry `d` from the first 256 masks. The Script lookup table encodes each mask as two little-endian bytes. Within each group, slot zero corresponds to the least-significant mask bit.

| Item | Encoding | Bytes |
| --- | --- | ---: |
| Secret key | All 352 secrets in group and slot order | 11,264 |
| Public key | All 352 SHA-256 hashes in the same order | 11,264 |
| Raw signature | Four selected secrets per group, in ascending slot order | 4,096 |
| Committed proof | One item per slot, using the secret if selected and its public hash otherwise | 11,264 |
| Output commitment | SHA-256 of the ordered public key | 32 |

The external signer receives the 32-byte transaction authorization digest and returns the raw signature. The wallet verifies the four selections per group and builds the proof using the full public key. The unlocking stack contains the authorized preimage, proof and ordinary or companion selector. [Wallet integration](sdk.en.md#fixed-weight-candidate)

## Validation and failures

Script independently derives each mask from the preimage digest, hashes the four selected slots in each group, and compares SHA-256 of the assembled key with the lock commitment. It checks the proof length and applies the existing native input-binding checks to the same digest. The verifier always hashes 128 selected secrets on success, regardless of which digest bytes are present. [Forth verifier](../forth/subset-verifier.fth) · [Acceptance tests](../reference/test_acceptance.py)

Distinct digest bytes select distinct four-element subsets. Because the subsets have equal size, neither contains the other. Any different digest therefore selects at least one slot whose secret was absent from the first signature. For independently generated keys and a single signing disclosure, a successful forgery for a different digest against the same public key supplies a preimage of an unopened SHA-256 commitment. In a single-target reduction, guessing that slot among 352 positions gives a reduction loss of at most 352, compared with the analogous 512-position bound for bit-pair Lamport. This is an argument about the one-time signature primitive. Binding a different public key to the same committed lock additionally requires breaking its SHA-256 commitment. Coverage of transaction fields and the fixed-r native binding follow the existing payment security analysis. [Security and recovery](security.md)

## Compatibility and evidence

Use a fresh independently generated key per output, including change. Classic Lamport and fixed-weight Lamport use different key sizes and raw signature encodings. The unified wallet reports `lamport-ots-subset` for this profile. A second signature can reveal additional secrets, so signer state must make the first disclosure durable across failures, concurrency and backup restores. [Signer lifecycle](security.md#one-time-means-one-disclosure-not-one-confirmed-transaction)

The proof is 5,120 bytes smaller than the v0.2.0 committed proof. The candidate lock is 1,478 bytes larger. The BIP143 size delta is therefore `1,478 × candidate outputs − 5,120 × candidate inputs` when the serialization widths and other fields match. This favors exits and input-heavy payments. The full-key classic profile still carries the smallest BIP143 witness among the Lamport profiles. [Comparative measurements](optimization.md#fixed-weight-candidate) · [Validation receipts](validation.md#fixed-weight-candidate-replay)
