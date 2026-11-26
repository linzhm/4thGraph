# P2PKH-SM2 v1.0.0

[简体中文](spec.zh-CN.md) · [Project overview](../README.md)

This specification describes the v1.0.0 baseline and the authorization rules shared by the locking templates. A BRC number has yet to be assigned. [v1.5.0 candidate](../README.md#v150)

## Payment and authorization

A payer creates an output from the recipient's HASH160 of a 65-byte uncompressed public key on curveSM2 (`04 || X_BE32 || Y_BE32`). On spend, the owner reveals that key and provides one SM2 signature for the current input. The witness never includes a parent transaction or an earlier signature.

The program uses existing BSV Script opcodes. It computes SM3 and verifies SM2 in Script; native `OP_CHECKSIG` remains secp256k1 ECDSA and binds the supplied transaction preimage through the public PUSHTX construction. Only the SM2 private key is required from the owner.

## Exact signing semantics

The template fixes the SM2 identity to the 16 ASCII bytes `1234567812345678`, with ENTLA `0080` (bit length, big endian). All curve parameters and coordinates are 32-byte big endian values.

```text
ZA = SM3(ENTLA || IDA || a || b || Gx || Gy || Qx || Qy)
H  = SHA256(SHA256(P))
e  = SM3(ZA || H)
```

A standard SM2 message-sign API receives **H and IDA**. An explicitly prehashed SM2 API receives **e**. Do not hash e again through a message API. The script recomputes ZA and e; it does not accept either as a trusted witness. The first 128 bytes of the ZA input are fixed, so their SM3 midstate is a program constant. The remaining two ZA compression blocks and both message-hash blocks execute on chain.

## SM2 verification

The verifier requires a valid point on curveSM2 with coordinates in `[0,p)`.
The curve has cofactor 1. Decode the signature as two 32-byte big-endian
integers, then check the following conditions.

1. Both scalars are in `[1,n)`.
2. `t = (r + s) mod n` is nonzero.
3. `R = sG + tQ` is a finite point.
4. `r = (e + x(R)) mod n`.

The script uses four-bit windows and projective coordinates. Set
`x₀ = (r - e) mod n`. Check `X = x₀ Z mod p` or, if `x₀ + n < p`,
`X = (x₀ + n) Z mod p`. These are the only candidates because `p < 2n`.
The witness supplies no inverse. Keep the original SM2 value of `s`.
Replacing it with `n - s` can invalidate the signature.

Template `3` reduces each intermediate projective coordinate to a signed residue in `(-p, p)`. The point formulas are field polynomials, so each signed residue represents the same field element as its nonnegative representative. Within this range, `Z = 0` detects infinity. The final comparisons use the nonnegative representatives of X and Z.

## Transaction scope and bytes

Each input selects a base mode, optional ANYONECANPAY (ACP), and digest algorithm. The table lists the hexadecimal type byte used by native transaction signing. The preimage carries the type as a four-byte little-endian value with the upper 24 bits set to zero. All twelve types set the `SIGHASH_FORKID` bit (`0x40`). Chronicle permits the additional OTDA bit `0x20` at spend time, including when the spent output predates Chronicle.

| Output coverage | BIP143 | BIP143 + ACP | Chronicle OTDA | OTDA + ACP |
|---|---|---|---|---|
| ALL | `41` | `c1` | `61` | `e1` |
| NONE | `42` | `c2` | `62` | `e2` |
| SINGLE | `43` | `c3` | `63` | `e3` |

ALL covers every output. NONE leaves outputs open. Paired SINGLE covers the output with the current input's index. Without ACP all input outpoints are covered. Only ALL without ACP covers the other inputs’ sequences. Every owner authorization binds the current outpoint, current sequence, version and locktime.

Ordinary checks execute after the final `OP_CODESEPARATOR`, giving scriptCode `ac`. BIP143 includes the previous amount. Its 158-byte preimage is:

```text
versionLE32 || hashPrevouts || hashSequence || outpoint || 01ac ||
amountLE64 || sequenceLE32 || hashOutputs || locktimeLE32 || typeLE32
```

OTDA serializes the selected inputs and outputs in the original format and appends the four-byte type. It omits the spent amount. Under paired SINGLE, each earlier output is a null placeholder (`ffffffffffffffff00`), including with ACP. No complete parent transaction enters the witness.

**Unpaired SINGLE.** BIP143 uses zero hashOutputs. Native OTDA returns the constant `uint256(1)` in this case, which leaves the current input unbound. For `63` or `e3`, the SM2 owner signs the BIP143 SINGLE companion (`43` or `c3`). Its scriptCode is `ad68abac`, including the unexecuted separator. The lock checks the companion’s zero hashOutputs, verifies its native binding against the actual input and separately checks the original OTDA type against the native constant. Adding a paired output or changing the current outpoint invalidates this authorization. With ACP other inputs can still change.

| Item | Encoding |
|---|---|
| Canonical lock / owner slot | 144,925 bytes / zero-based `[168,188)` |
| Three witness items | preimage P, uncompressed key Q (65 bytes), raw r‖s (64 bytes) |
| BIP143 scriptSig | 291 bytes |
| Ordinary OTDA scriptSig | `len(push(P)) + 131` bytes, transaction-dependent |
| Unpaired OTDA SINGLE scriptSig | 294 bytes (161-byte companion P) |

Recognition compares every fixed byte of the locking program. The layout manifest records the length, owner offset, SHA-256 of the zero-owner script, and the fingerprint of the fixed bytes. The generator can write raw bytes or hex. [Layout manifest](../versions/v1.0.0/layout.json) · [Script generator](../reference/generate_lock.py)

## Integration

[The Python API](../reference/p2pkh_sm2.py) exports output generation from a hash or validated public key, full-template recognition (`identify` returns template version `1` and owner), `current_input_unlock`, `sign_input`, and `sign_payment`. The payment helper validates the funding output, key, outputs and explicit fee, calls `signer(H, IDA)`, verifies its returned raw signature and serializes the spend.

`sign_payment` uses `0x41`. For a prepared transaction, call `sign_input(tx, index, funding_raw, key, signer, sighash_type, chronicle_active=active)`. The wallet matches the funding outpoint and signs only that input. `chronicle_active` defaults to `True`; callers handling pre-activation spends must supply `False`. The wallet rejects OTDA before invoking the signer in that context. [Mode vectors](../versions/v1.0.0/sighash-modes.json) cover all twelve paired modes and four unpaired SINGLE cases.

The caller authenticates the funding transaction and confirmation state and obtains approval of recipients, change and fees. Secret-key signing belongs in an external signer. The pure-Python arithmetic and explicit-nonce fixture signer are not constant-time production signing implementations. Treat the SM2 user ID as an algorithm input. Establish signer identity and certificate trust separately.

## Evidence and boundaries

Tests cover the published SM2 vector, OpenSSL signing, SM3 block boundaries and fixed-prefix hashing, invalid points and scalars, wrong identities, t=0, infinity, the rare x≥n branch, transaction/preimage substitution and three consecutive payments. Local opcode evaluation is a development harness without consensus flags or resource limits. [Complete-input tests](../reference/test_node.py) separately exercise BSV Node 1.2.3 and pinned chain-gang with explicit UTXOs and flags.

Regtest results cover script verification under the supplied flags. Mainnet activation, relay policy, fees, and hardware integration depend on the deployment environment.

## Sources

- RFC 8998 specifies the curve parameters and SM2 identity semantics. [RFC 8998 §3.2.1](https://www.rfc-editor.org/rfc/rfc8998.html#section-3.2.1)
- The OpenSSL test suite includes the published SM2 test vectors. [OpenSSL standard vector](https://github.com/openssl/openssl/blob/openssl-3.5.0/test/sm2_internal_test.c)
- The SM3 Internet-Draft describes the compression functions and message expansion. [SM3 Internet-Draft](https://datatracker.ietf.org/doc/html/draft-sca-cfrg-sm3-02)
- PUSHTX uses a public transaction-binding construction. [WP1605](https://nchain.com/wp-content/uploads/2022/03/WP1605_PUSHTX-and-its-Building-Blocks.pdf) · [BRC-21](https://github.com/bsv-blockchain/BRCs/blob/master/scripts/0021.md)
- The R1 project supplies the basis for the windowed projective arithmetic and the public native signature construction. P2PKH-SM2 uses its own curve constants and signature equation. [P2PKH-R1](../../p2pkh-r1/README.md)
