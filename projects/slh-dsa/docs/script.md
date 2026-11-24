# SLH-DSA-SHA2-128s Script verifier

The lock embeds a 32-byte public key in `PK.seed || PK.root` format. The
payment witness carries the transaction preimage, the 7,856-byte SLH-DSA
signature and the native binding selector. The signer receives
`SHA256d(preimage)` as the pure-mode message. The Script prepends `00 00`
for pure SLH-DSA with empty context before evaluating `H_msg`.

## Code generation

The emitter is adapted from the Rúnar Python generator, fixed to the FIPS 205
SHA2-128s parameter set. It emits Script bytes through the shared encoder.
Byte strings that coincide with small Script numbers use minimal push opcodes.
The key-independent verifier bytes are cached in memory and the wallet inserts
the public key for each lock. [Pinned Rúnar source](https://github.com/icellan/runar/blob/0159f4f2caeb2ecb26d22bf6e69e34b3950c4e32/compilers/python/runar_compiler/codegen/slh_dsa.py) · [MIT license](../reference/LICENSE.runar) · [FIPS 205](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)

The verifier computes `H_msg`, reconstructs the FORS public key, walks the seven
XMSS layers and compares the final root with `PK.root`. The verifier consumes
the signature and message. The standalone stack test checks that its execution
preserves the caller's existing items on both stacks. For payment, the saved
digest and mode on the alternate stack then feed the current-input binding.
[Generator](../reference/runar_slh.py) · [Wrapper](../reference/script.py) · [Stack tests](../reference/test_script.py)

## Chronicle context

The verifier uses opcodes available under Genesis. The transaction wrapper uses
two plain `OP_NOP` tags in each `scriptCode` suffix to distinguish the payment
domain from the earlier Lamport and WOTS+ templates. ForkID uses the ordinary
suffix `616168ac`. Unpaired OTDA `SINGLE` runs the native constant check followed
by the companion ForkID binding with suffix `616163ad67ab616168ac`. Full-input
validation must set the spend height, Chronicle activation height and each
prevout creation height, including for outputs created before Chronicle.
[Shared native binding](../../../shared/pushtx.py)

## Script resource measurements

| Item | Size or count |
|---|---:|
| Key-independent Script verifier | 188,849 bytes |
| Payment locking script | 189,819 bytes |
| Raw signature | 7,856 bytes |
| ForkID `ALL` unlocking script | 8,023 bytes |
| `OP_SHA256` instructions in verifier bytecode | 4,161 |

The static instruction count includes both sides of conditional branches.
From the code structure, an upper bound on executed `OP_SHA256` instructions
in the verifier is 3,825. This uses 2 for `H_msg`, 183 for FORS, and at most
520 per XMSS layer. Each XMSS layer has at most 510 WOTS+ chain steps, one
endpoint compression and nine parent hashes. The measurements isolate the
verifier and its payment Script. Node `verifyscript`, mempool and block checks
have their own resource settings and validation procedures.

The SHA-256 digest of the key-independent Script verifier is
`0dd1dbe07b6d0d3d9ce3e5e98845513b4db2e79a98b816b0f0b7f6f17bc5a831`.
