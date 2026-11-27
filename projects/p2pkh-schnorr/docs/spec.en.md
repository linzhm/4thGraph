# P2PKH-Schnorr payment format

[简体中文](spec.zh-CN.md) · [Project overview](../README.md)

The owner field is HASH160 of the 32-byte BIP340 x-only public key. The rest of the file is fixed. Fill the owner slot identified in the manifest when creating a receive output. When recognizing an output, compare its length and all fixed bytes before taking the owner hash. [Frozen template](../versions/v0.14.0/template.hex) · [Layout](../versions/v0.14.0/layout.json)

Versions 0.6.0 through 0.14.0 use the same `scriptCode` fragments for the current-input binding and the same witness encoding. A wallet can spend outputs from different versions in one transaction. [Version catalog](../versions/index.json)

The wallet builds the BSV sighash preimage for the current input. The external signer receives SHA256d of that preimage as the 32-byte BIP340 message and returns the standard signature bytes. The lock verifies the signature and binds the same message to the current input with PUSHTX. BIP143 ALL is the wallet default. A wallet must supply trusted Chronicle activation context for OTDA and a same-index output for SINGLE. [Forth contract](../reference/schnorr.fth)

| Unlock stack item | Encoding |
| --- | --- |
| Signing preimage | The chosen BSV sighash preimage with the template's scriptCode |
| Packed witness | Public x (32 bytes), even public y (32 bytes), BIP340 signature (64 bytes), even nonce y (32 bytes) |
| Mode selector | Script number 0 for the ordinary payment path |

The wallet derives both extra ordinates from public data after signing. They are unsigned, big-endian field elements. Script checks the field bounds, even parity, and public-point equation. The checker calculates the tagged challenge over r, public x, and the message. It evaluates sG − eP, rejects infinity, and compares both projective coordinates with the finite even nonce point using field congruences. This verifies the nonce coordinates without executing a square root or field inversion inside Script. [BIP340 verification](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) · [Complete addition formulas](https://eprint.iacr.org/2015/1060)

After checking the witness lengths, the verifier hashes the original `r`, public x and message with the BIP340 tag. It joins the four coordinates, signature scalar and challenge hash into six 32-byte fields. Five masked swaps exchange adjacent blocks of 1, 2, 4, 8 and 16 bytes. The mask repeats within each 32-byte field, so each field reverses in place. The verifier reads the reversed fields as unsigned integers, checks the coordinate bounds and curve equation against the field prime, and uses one copy of the group order to check the signature scalar and compute `n − e`. [Challenge preparation](../../../src/fourthgraph/stdlib/bip340.fth)

The detached verifier consumes message, public x, public y, signature, and nonce y. Use it for conformance tests. Use the fixed payment template to lock a UTXO. The copied official CSV fixture is pinned to the Bitcoin BIPs commit below. [Official test vectors](https://github.com/bitcoin/bips/blob/200f9b26fe0a2f235a2af8b30c4be9f12f6bc9cb/bip-0340/test-vectors.csv)

<a name="compact-doubling"></a>

## Compact doubling

The accumulator uses homogeneous coordinates with `X³ = Y²Z − 7Z³` modulo the field prime. Substituting equal points into complete addition gives the cross terms `2XY`, `2XZ`, and `2YZ`. Applying the curve equation gives the following coordinates for the doubled point. [Forth kernel](../../../src/fourthgraph/stdlib/secp256k1.fth)

- Set `a = Y²`, `t = 21Z²`, and `q = 3t`.
- Compute `X' = 2XY(a − q)`, `Y' = a(a + 2q) − q*t`, and `Z' = 8Y³Z` modulo the field prime.

For infinity `(0:Y:0)` with nonzero `Y`, the result is `(0:Y⁴:0)`.

In each pair of doublings, the first doubling reduces `Y'` and `Z'` immediately. The second doubling computes `Y''` and `Z''` solely from those two coordinates, and `X''` is linear in `X'`. One reduction after the pair therefore suffices for X. The absolute value of the factor multiplying X in each doubling is below `126p³`. Starting with coordinates of absolute value below the field prime `p`, the unreduced X after two doublings is bounded by `126²p⁷`, which fits in a 226-byte ScriptNum.

## Joint scalar multiplication

Let `k = n − e` and `B = 2^128`. The lock splits `s` into `s0 + B*s1` and uses the fixed base `H = B*G`. The secp256k1 endomorphism `φ(x,y) = (βx,y)` satisfies `φ(P) = λP`. The lock splits `k` into signed components with `k ≡ k1 + λ*k2 (mod n)`. The magnitudes of all four components fit in 128 bits. [Window code](../../../src/fourthgraph/stdlib/bip340.fth) · [secp256k1 lattice basis](https://github.com/bitcoin-core/secp256k1/blob/v0.6.0/src/scalar_impl.h#L78-L135)

The lattice basis obeys `ai + bi*λ ≡ 0 (mod n)` and has determinant `n`. The lock computes `c1 = round(k*b2/n)` and `c2 = round(-k*b1/n)` with exact integer division. Subtracting the two basis multiples from `(k, 0)` gives the signed pair `(k1, k2)`. Each coordinate error is bounded by half the sum of the absolute basis components in that coordinate. The lock also checks both magnitudes against `B`. When `e = 0`, the split of `k = n` gives zero in both components. [Scalar split](../../../src/fourthgraph/stdlib/secp256k1.fth)

The verifier computes `s0*G + s1*H + k1*P + k2*φ(P)` in 64 two-bit windows. It uses a fixed affine table for `G,H` and a projective table for `P,φ(P)` with the respective signs applied. Each row of the variable table is constructed by repeatedly adding the validated affine point P. Each window selects one entry from each table with `4*highDigit + lowDigit`. After the first window, the accumulator doubles twice before each selection. The initial accumulator is infinity. Index zero skips addition. Variable table construction and fixed point accumulation use complete addition specialized to a right-hand point with `Z = 1`. [Mixed addition](../../../src/fourthgraph/stdlib/secp256k1.fth)

The verifier packs the four 128-bit components into a 64-byte value. For lane `ℓ` in `(s0, s1, |k1|, |k2|)` and two-bit digit `d = 4q + r` counted from the least significant end, the concatenated little-endian encoding places that digit at bit-pair position `j = 64ℓ + 4(15 − q) + r`. Six masked swaps implement `rotl8(j, 2) XOR 0xf0 = 4d + ℓ`. Each resulting byte carries the fixed digit in its low nibble and the variable digit in its high nibble. [Index packing](../../../src/fourthgraph/stdlib/bip340.fth)

The verifier computes stack depths before iteration. v0.14.0 widens each packed byte to a variable digit followed by a fixed digit and stores all 64 pairs in one stream. For each digit `i`, a mask computes a presence bit `m`. The common depth is `3m + 2i`. Adding `79m − 5i` to the variable bytes yields their depth `82m − 3i`. Both depths are zero at index zero, and the arithmetic neither carries nor borrows across byte boundaries. Each window splits off its two bytes before unpacking the depths. [Depth computation](../../../src/fourthgraph/stdlib/bip340.fth)

v0.12.0 reads the depth bytes directly. A zero byte is false in the point-addition branch, and a nonzero byte is already a minimally encoded positive ScriptNum. When constructing the variable point table, let `ε` be the relative sign of the two variable bases, so `Q = εφ(P)`. The verifier obtains `2Q` and `3Q` from `2P` and `3P` by multiplying X by β modulo the field prime and Y by ε. The projective Z coordinate stays unchanged. [Point-table construction](../../../src/fourthgraph/stdlib/bip340.fth)

After constructing the point tables, the verifier places the field prime directly below the accumulator. Doubling and addition consume their operands above the prime, so the compiler can emit a fixed stack depth for each coordinate reduction. The fixed-base table is pushed in descending index order. Counting the top accumulator coordinate as depth zero, the x-coordinate for index `i > 0` is at depth `2i + 3`. [Window loop](../../../src/fourthgraph/stdlib/bip340.fth) · [Point arithmetic](../../../src/fourthgraph/stdlib/secp256k1.fth)
