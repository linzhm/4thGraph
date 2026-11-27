# P2PKH-Schnorr payment format

[简体中文](spec.zh-CN.md) · [Project overview](../README.md) · [Wallet SDK](sdk.en.md#quickstart)

## Lock and spend

A receive output commits to HASH160 of a 32-byte BIP340 x-only public key. Fill the owner slot defined by the selected release. A wallet identifies the release by comparing the script length and every fixed byte. The published v0.6.0 through v0.17.0 templates use the same binding `scriptCode` fragments and the same stack layout after unlocking. [Current template and owner slot](../versions/v0.17.0/layout.json) · [Release index](../versions/index.json)

| Step | Actor and enforced condition |
| --- | --- |
| Fund | The payer places the selected Schnorr lock and amount in a transaction output. The receiving wallet identifies the outpoint and checks its amount, template and owner. |
| Authorize | The wallet prepares the current input's signing preimage under the approved sighash. The external signer receives its SHA256d as the 32-byte BIP340 message and releases a 64-byte signature. |
| Assemble | The wallet verifies the signature and derives the two public ordinates before building the input script. Each ordinate is an unsigned big-endian field element. |
| Verify | Script checks the owner hash and BIP340 relation. PUSHTX binds the verified message to the actual input through native `OP_CHECKSIG`. The node evaluates the spend against its previous output and chain context. |

[Payment Forth](../reference/schnorr.fth) · [Wallet signing flow](../reference/payment.py) · [Authorization inputs](../../../src/fourthgraph/bsv/spend_authorization.py)

## Unlock stack and sighash

Read from bottom to top after the input script runs.

| Stack item | Encoding |
| --- | --- |
| Signing preimage | Complete BSV preimage for the ordinary or companion branch. |
| Packed witness | Public x (32 B), even public y (32 B), BIP340 `r \|\| s` (64 B), and even nonce y (32 B), in that order. |
| Mode selector | Script number 0 for ordinary binding or 1 for unpaired OTDA SINGLE companion binding. |

The wallet defaults to BIP143 ALL (`0x41`). For ALL, NONE, and SINGLE, output coverage follows the chosen BSV sighash. ANYONECANPAY changes input coverage. The SDK requires trusted Chronicle activation context for OTDA and a same-index output for SINGLE. The lock also implements the separately tested unpaired OTDA SINGLE companion branch. That branch binds the Schnorr message to a BIP143 SINGLE preimage with zero `hashOutputs` and checks the corresponding native OTDA SINGLE condition. The standard wallet path requires a paired output. [Binding and sighash checks](../reference/schnorr.fth) · [Acceptance cases](../reference/test_schnorr.py)

### OTDA preimage encoding

In an active version-2 OTDA ALL or paired OTDA SINGLE spend, including ANYONECANPAY forms, the assembler can choose a shorter program. It ranks valid encodings of the same full preimage, and copies unrecognized output scripts as literal bytes when reconstructing a mixed template. The signer and lock consume the same preimage in either encoding. The transaction ID depends on the final serialized unlocking script. [Selection rules](../../../src/fourthgraph/compiler/preimage.py) · [Constructor results](high-level-forth.en.md#otda-constructor)

## BIP340 verification

Script checks the four coordinate bounds, the even parity of both ordinates and the public-point curve equation. It checks the signature scalar against the group order, and computes the challenge from the original `r`, x-only key and message with the BIP340 tag. It evaluates `sG − eP`, checks that `Z` is nonzero and compares both resulting projective coordinates with the finite nonce point by field congruences. The public coordinate witnesses let Script evaluate these checks without computing a square root or inversion. [Verifier](../../../src/fourthgraph/stdlib/bip340.fth) · [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)

The implementation decodes the four coordinates, signature scalar and challenge hash as six separate unsigned 32-byte fields. Five masked block swaps reverse each field in place before integer conversion. The detached entry accepts message, public x, public y, signature, and nonce y, and the payment lock uses the 32-byte preimage hash as the message. [Shared decoding](../../../src/fourthgraph/stdlib/script-fragments.fth) · [Pinned official vectors](../versions/v0.6.0/bip340-vectors.csv)

## Coordinate scaling

The verifier uses the original secp256k1 coordinates for the witness checks and challenge hash. For point arithmetic it maps `(X:Y:Z)` to `(u²X:u³Y:Z)` over the same field, using a fixed nonzero `u` with `21u⁶ = 1 mod p`. This maps `y² = x³ + 7` to `y² = x³ + 1/3`, preserves the group law, and fixes infinity. The public and nonce points are scaled in Script. The fixed table contains the scaled generator multiples. Endpoint comparisons are performed on the scaled curve. [Shared curve kernels](../../../src/fourthgraph/stdlib/secp256k1.fth)

To derive the constant, set `t = 21⁻¹ mod p` and `m = (p−1)/3`. Here `t^m = 1`, `3` is invertible modulo `m`, and `p ≡ 3 mod 4`. Compute `A = t^(3⁻¹ mod m) mod p` and `B = t^((p+1)/4) mod p`. Then `A³ = B² = t` and `u = B/A` has `u² = A` and `u³ = B`. [Scale constant and independent arithmetic tests](../../../tests/test_secp256k1_library.py)

<a name="compact-doubling"></a>

## Compact doubling

For the scaled curve, `X³ = Y²Z − Z³/3` modulo the field prime. Substituting equal points into complete addition gives the cross terms `2XY`, `2XZ`, and `2YZ`. Applying the curve equation gives the following coordinates for the doubled point. [Forth kernel](../../../src/fourthgraph/stdlib/secp256k1.fth)

- Set `a = Y²`, `t = Z²`, and `q = 3t`.
- Compute `X' = 2XY(a − q)`, `Y' = a(a + 2q) − q*t`, and `Z' = 8Y³Z` modulo the field prime.

For infinity `(0:Y:0)` with nonzero `Y`, the result is `(0:Y⁴:0)`.

In each pair of doublings, the first doubling reduces `Y'` and `Z'` immediately. The second doubling computes `Y''` and `Z''` solely from those two coordinates, and `X''` is linear in `X'`. One reduction after the pair therefore suffices for X. On the scaled curve the absolute value of the factor multiplying X in each doubling is below `6p³`. Starting with reduced coordinates, the unreduced X after two doublings is bounded by `36p⁷`, which fits in a 225-byte ScriptNum.

## Joint scalar multiplication

Let `k = n − e` and `B = 2^128`. The lock splits `s` into `s0 + B*s1` and uses the fixed base `H = B*G`. The secp256k1 endomorphism `φ(x,y) = (βx,y)` satisfies `φ(P) = λP`. The lock splits `k` into signed components with `k ≡ k1 + λ*k2 (mod n)`. The magnitudes of all four components fit in 128 bits. [Window code](../../../src/fourthgraph/stdlib/bip340.fth) · [secp256k1 lattice basis](https://github.com/bitcoin-core/secp256k1/blob/v0.6.0/src/scalar_impl.h#L78-L135)

Write `A = a1 = b2` and `D = −b1`. The two basis vectors are `(A, −D)` and `(A+D, A)`, with `A² + AD + D² = n` and `ai + bi*λ ≡ 0 mod n`. The lock reuses the order from challenge reduction to compute `c1 = floor((kA + floor(n/2))/n)` and `c2 = floor((kD + floor(n/2))/n)`. It returns `k1 = k − A(c1+c2) − Dc2` and `k2 = Dc1 − Ac2`. [Scalar split](../../../src/fourthgraph/stdlib/secp256k1.fth)

The rounding errors `ε1 = kA/n − c1` and `ε2 = kD/n − c2` each have magnitude at most one half. The determinant identity gives `k1 = Aε1 + (A+D)ε2` and `k2 = −Dε1 + Aε2`. Their magnitudes are at most `(2A+D)/2` and `(A+D)/2`, both below `2^128`. This bound covers the entire input interval `0 ≤ k ≤ n`. At `k = n` both components are zero. [Rounding tests](../../../tests/test_secp256k1_library.py)

The verifier computes the scaled image of `s0*G + s1*H + k1*P + k2*φ(P)` in 64 two-bit windows. The fixed affine table contains scaled images of `G,H` combinations. The projective table uses scaled `P,φ(P)` with the respective signs applied. Each row of the variable table is constructed by repeatedly adding the scaled affine point P. Each window selects one entry from each table with `4*highDigit + lowDigit`. The accumulator starts at infinity. In v0.17.0, the first variable selection copies its projective point directly into the accumulator, using `O + P = P`. A zero selector leaves infinity in place. The fixed selection then uses complete affine addition where its index is nonzero. In the remaining 63 windows the accumulator doubles twice before accumulating any selected points, and each zero selector skips addition. Variable table construction and fixed point accumulation use complete addition specialized to a right-hand point with `Z = 1`. [Mixed addition](../../../src/fourthgraph/stdlib/secp256k1.fth)

The verifier packs the four 128-bit components into a 64-byte value. For lane `ℓ` in `(s0, s1, |k1|, |k2|)` and two-bit digit `d = 4q + r` counted from the least significant end, the concatenated little-endian encoding places that digit at bit-pair position `j = 64ℓ + 4(15 − q) + r`. Six masked swaps implement `rotl8(j, 2) XOR 0xf0 = 4d + ℓ`. Each resulting byte carries the fixed digit in its low nibble and the variable digit in its high nibble. [Index packing](../../../src/fourthgraph/stdlib/bip340.fth)

The verifier computes stack depths before iteration. v0.14.0 widens each packed byte to a variable digit followed by a fixed digit and stores all 64 pairs in one stream. For each digit `i`, a mask computes a presence bit `m`. The common depth is `3m + 2i`. Adding `79m − 5i` to the variable bytes yields their depth `82m − 3i`. Both depths are zero at index zero, and the arithmetic neither carries nor borrows across byte boundaries. Each window splits off its two bytes before unpacking the depths. [Depth computation](../../../src/fourthgraph/stdlib/bip340.fth)

v0.12.0 reads the depth bytes directly. A zero byte is false in the point-addition branch, and a nonzero byte is already a minimally encoded positive ScriptNum. When constructing the variable point table, let `ε` be the relative sign of the two variable bases, so `Q = εφ(P)`. The verifier obtains `2Q` and `3Q` from `2P` and `3P` by multiplying X by β modulo the field prime and Y by ε. The projective Z coordinate stays unchanged. [Point-table construction](../../../src/fourthgraph/stdlib/bip340.fth)

After constructing the point tables, the verifier places the field prime directly below the accumulator. Doubling and addition consume their operands above the prime, so the compiler can emit a fixed stack depth for each coordinate reduction. The fixed-base table is pushed in descending index order. Counting the top accumulator coordinate as depth zero, the x-coordinate for index `i > 0` is at depth `2i + 3`. [Window loop](../../../src/fourthgraph/stdlib/bip340.fth) · [Point arithmetic](../../../src/fourthgraph/stdlib/secp256k1.fth)
