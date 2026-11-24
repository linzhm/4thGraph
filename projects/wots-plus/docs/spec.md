# WOTS+ wire and Script specification

## One-time signature

The hash chains use the `WOTSP-SHA2_256` parameter set from RFC 8391.
Elements are 32 bytes and the Winternitz parameter `w` is 16. Split a
32-byte digest into 64 base-16 digits, most significant nibble first in each
byte. Append the three big-endian hex digits of the checksum
`sum(15 - digit)` over all 64 digest digits.

Each of the 67 chains has 15 steps. Let `U32(x)` serialize a 32-bit unsigned
word in big-endian order and `U256(x)` serialize a 256-bit word the same way.
For chain `i`, step `j` and selector `k`, use the address
`zero[20] || U32(i) || U32(j) || U32(k)`. The first five words fix the
layer, tree, address type and OTS address at zero. The remaining words are
the chain address, hash address and key-and-mask selector.

```text
PRF(seed, addr) = SHA256(U256(3) || seed || addr)
key             = PRF(public_seed, addr(i, j, 0))
mask            = PRF(public_seed, addr(i, j, 1))
step(value)     = SHA256(U256(0) || key || (value XOR mask))
```

The reference signer draws a fresh 32-byte secret seed and a separate 32-byte
public seed. It derives the starting value of chain `i` as
`SHA256(U256(4) || secret_seed || public_seed || addr(i, 0, 0))`, following the
optional deterministic expansion used by the XMSS C reference implementation.

Signature element `i` exposes the value after the number of steps specified by
digit `i`. Verification continues the same chain to step 15. The witness
signature concatenates all 67 elements in chain order, totaling 2,144 bytes.
The payment format serializes the public key as `public_seed ||
SHA256(endpoint[0] || … || endpoint[66])`, totaling 64 bytes. Script recovers
all endpoints and checks their commitment. This commitment and the packed
witness are BSV-specific encodings. XMSS uses WOTS+ within a Merkle tree and
derives its leaf through an L-tree.

## Payment authorization

The unlocking script pushes three items in order. They are the preimage, the
packed signature and a selector. The selector is the empty byte string for
ordinary spends and `01` for the unpaired Chronicle `SINGLE` path. The signing
digest is `SHA256d(preimage)` in both cases. The fixed-r PUSHTX construction
uses native `OP_CHECKSIG` to bind the preimage to the current input. The WOTS+
signature supplies the owner's authorization.

| Output coverage | ForkID | ForkID + ANYONECANPAY | Chronicle OTDA | OTDA + ANYONECANPAY |
|---|---|---|---|---|
| `ALL` | `41` | `c1` | `61` | `e1` |
| `NONE` | `42` | `c2` | `62` | `e2` |
| `SINGLE` | `43` | `c3` | `63` | `e3` |

An ordinary spend uses the selected native mode and serializes the corresponding
input-specific preimage. The script checks the sighash type from the preimage's
four-byte little-endian suffix. The ordinary `scriptCode` is three bytes and the
companion `scriptCode` is eight bytes. `OP_NOP` tags separate these payment
digests from the Lamport template's digests. `ALL` covers every output. `NONE`
covers no outputs. `SINGLE` covers the output at the current input index when
one exists. `ANYONECANPAY` allows other inputs to change. The exact input and
output commitments follow the selected BIP143 or OTDA serialization.

If an OTDA `SINGLE` input has no output with the same index, the node returns a
constant for that mode. The script checks for the native constant using the
requested `63` or `e3` and binds the owner authorization to a companion
ForkID `SINGLE` preimage with type `43` or `c3`, respectively. The companion
uses a separate `scriptCode`, binds the current outpoint and amount, and
requires zero `hashOutputs`. The owner's WOTS+ signature always authorizes the
companion digest in this case. See the [Lamport transaction-binding analysis](../../lamport-ots/docs/security.md)
for the fixed-r relation and its security assumptions.

## Key lifecycle and validation scope

Allocate one fresh one-time key per UTXO and sign at most one digest with it.
The signer must persist consumption before disclosing a signature and retain
the signed transaction for idempotent rebroadcast. Process restarts, backup
restores, concurrent requests and fee replacements must preserve the one-use
rule. Deterministic test seeds are public fixtures for synthetic transactions.

The conformance target is complete-input validation by BSV Node, chain-gang and the Lean evaluator
under the recorded test configuration. These checks use synthetic prevouts.
Mainnet relay, confirmation and end-to-end post-quantum security require
separate evidence.

## Sources

- [RFC 8391, Sections 3.1 and 5](https://www.rfc-editor.org/rfc/rfc8391.html#section-3.1)
- [Pinned XMSS C reference implementation](https://github.com/XMSS/xmss-reference/blob/171ccbd26f098542a67eb5d2b128281c80bd71a6/wots.c)
- [Rúnar WOTS+ and Script verification, prior art](https://runar.build/docs/api-reference/contract-decorators-and-types/#post-quantum-verification)
