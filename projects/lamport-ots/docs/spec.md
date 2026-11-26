# Lamport SHA-256 v1 wire and Script specification

## Primitive

For i=0..255 and b=0,1, independently generate a uniformly random 32-byte secret
x[i][b]. Publish y[i][b]=SHA256(x[i][b]). Serialize in order x[0][0], x[0][1],
x[1][0], x[1][1], ...; the public key uses the same order. Both are 16,384 bytes.
The 32-byte digest D is read in byte order, **LSB-first within each byte**:
b[i]=(D[i//8] >> (i%8)) & 1. Signature block i is x[i][b[i]], giving 8,192 bytes.
Verify exactly 256 SHA-256 preimages against the selected public commitments.
Reject every incorrect length; there is no padding or truncation.

This is an explicit repository encoding of Lamport OTS, not a NIST-standardized
signature format. The public deterministic fixture is a regression vector, not
an official standard test vector. `generate_keypair()` uses OS-backed randomness;
the fixture derivation is deliberately separate and must never hold funds.

## Witness and payment profiles

The payment witness pushes the preimage P, packed proof, and selector in that
order. The selector is the empty byte string for ordinary authorization or
the single byte `01` for the unpaired Chronicle SINGLE path. The lock checks
the proof length before evaluating the Lamport verifier.

| Profile | Key data in the lock | Proof layout |
| --- | --- | --- |
| `full-key` | 512 ordered public hashes | 256 selected secrets, 8,192 bytes |
| `committed-key` | SHA-256 of the ordered public key | 256 pairs of selected secret and sibling hash, 16,384 bytes |
| `committed-key-forth` | Same 32-byte commitment | Same 16,384-byte proof |
| `committed-key-forth-compact` | Same 32-byte commitment | Same 16,384-byte proof |
| `committed-key-forth-v0.2.0` | Same 32-byte commitment | Same 16,384-byte proof |

For committed profiles, record i is `x[i][b[i]] || y[i][1-b[i]]`. The lock
hashes the secret and orders the two hashes as `y[i][0] || y[i][1]` according to
digest bit i. The hash of the concatenated pairs must match the commitment. The
wallet needs the full ordered public key to construct this proof. All five
profiles enforce the same preimage and selector rules and leave one true item
and an empty altstack on success. [Forth implementation and costs](optimization.md)

## Sighash modes

| Output coverage | BIP143 | BIP143 + ANYONECANPAY | Chronicle OTDA | OTDA + ANYONECANPAY |
|---|---|---|---|---|
| ALL | `41` | `c1` | `61` | `e1` |
| NONE | `42` | `c2` | `62` | `e2` |
| SINGLE | `43` | `c3` | `63` | `e3` |

All twelve types set `SIGHASH_FORKID` (`0x40`). The hash type is the final
four little-endian bytes of P.
The script verifies the exact type, including zero high bytes, and uses the
authenticated byte on the native signature. The wallet default is `41`.

## Ordinary payment digest

Lamport signs SHA256d(P). The last executed code separator sets native scriptCode
to `68ac` in the ordinary path. Ordinary BIP143 checks that P is 159 bytes and
contains `02 68 ac` at offset 104. Its fields are version, hashPrevouts,
hashSequence, current outpoint, length-prefixed scriptCode, previous amount,
current sequence, hashOutputs, locktime, and the four-byte type.
OTDA uses the original transaction serializer with other inputs' scripts
blanked, the active input's script replaced with `68ac`, and a type-specific
input/output selection. Its preimage has variable length and omits the prevout
amount. The node authenticates the serialized fields through the fixed-r
signature relation described in [security.md](security.md).

An opted-in version-2 unlock can reconstruct P for OTDA ALL or paired SINGLE,
including ANYONECANPAY, from matching compact Forth and v0.2.0 outputs. The functional
unlock leaves the identical preimage, proof and selector on the main stack and
an empty altstack. The verifier binds the resulting preimage to the spending
input in the same way as a literal push. [Reconstruction design](optimization.md#otda-unlocking-reconstruction)

ALL covers all outputs, NONE covers no outputs, and SINGLE covers the output
at the signing input index when it exists. The current outpoint, sequence,
version and locktime are committed. Without ANYONECANPAY, all input outpoints
are covered. Other inputs' sequences are covered only by ALL without
ANYONECANPAY. Other inputs' scripts and prevout amounts are outside the
authorization. BIP143 SINGLE with ANYONECANPAY permits movement of the
input-output pair together. OTDA SINGLE commits to its output index through
the serialized null outputs before the selected output.

## SINGLE with no paired output

BIP143 SINGLE still binds the current input, using a zero hashOutputs. OTDA
SINGLE instead returns the native constant `01 00…00`. For requested `63` or
`e3` in this case, Lamport signs the BIP143 `43` or `c3` digest with distinct
scriptCode `63ad67ab68ac`. The script requires this exact 163-byte preimage
layout, the matching type, and zero hashOutputs. It first checks a script-derived
signature for the native OTDA constant using the requested type, then performs
the BIP143 current-input binding. The intervening code separator is not
executed in this branch, so the BIP143 scriptCode includes it. The owner
never signs the constant.

## Previous template and detached verification

`legacy_locking_script(key)` emits the original byte-identical two-push
BIP143 ALL template with 158-byte preimage and scriptCode `ac`.
`sign_spend` recognizes it and requires type `41`. New locks from
`locking_script(key)` use the universal format. The digest-only variant takes
a 32-byte digest and signature and provides detached verification.

## Compatibility and resources

The code uses Genesis-era SPLIT, CAT, arithmetic and large pushed elements, and
requires post-Genesis resource rules (an 8,192-byte element and thousands of
opcodes exceed historical 520-byte/201-op limits). The conformance runner tests
BSV Node 1.2.3 in isolated regtest with Genesis height 1, Chronicle height 2,
synthetic prevout height 3, explicit flags and a 100 MB stack-memory limit. It
never broadcasts or mines the transactions. This demonstrates Script acceptance
under those settings, not mainnet relay policy, fee acceptance, UTXO existence,
or network-wide consensus testing. Node tests also cross-check pinned chain-gang.

Static opcode counts in `measurements.json` describe the v0.1.0 vectors. The
full-key lock has 256 SHA256 instructions. Each commitment lock has 257 SHA256
instructions, including the final public-key hash. The payment wrapper adds
one HASH256 and two native signature instructions. The ordinary path executes
one native check, and the companion path executes both.
Node-native signature hashing performs additional work not counted by this static
Script census. Timings include adapters and are local wall-clock samples.

## Sources

- [Lamport, Constructing Digital Signatures from a One Way Function](https://www.microsoft.com/en-us/research/publication/constructing-digital-signatures-one-way-function/).
- [BSV protocol specifications](https://github.com/bitcoin-sv-specs/protocol), including Genesis and Chronicle.
- [BSV Node releases](https://github.com/bitcoin-sv/bitcoin-sv/releases).
- The existing R1 project credits PUSHTX research; its fixed-key DER construction
  and the local SM2 experiment informed this binding, without changing R1 bytes.
