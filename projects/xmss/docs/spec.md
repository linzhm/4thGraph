# XMSS payment format

## Key and owner signature

The public key follows the XMSS reference encoding for `XMSS-SHA2_10_256`.
It consists of the four-byte OID `00000001`, the 32-byte root and the 32-byte
public seed. The signature contains the four-byte big-endian leaf index, the
32-byte message randomizer, the 2,144-byte WOTS+ signature and 10 consecutive
32-byte authentication nodes. The index must be in the range 0 through 1,023.

XMSS signs `SHA256d(preimage)` as its message. The Script computes RFC 8391
`H_msg` using that message, the supplied randomizer, the committed root and
the leaf index. It then recovers all 67 WOTS+ chain endpoints at the index's
OTS address, compresses them with the L-tree and walks the authentication path.
The computed root must equal the root embedded in the funding script. The
detached message verifier is provided for algorithm tests.

## Spending transaction

The witness pushes `preimage`, `signature` and a selector. The selector is
`0` for an ordinary spend and `1` for the companion binding. The template
uses opcodes available under Genesis. Chronicle enables the OTDA modes at
the spending height. Plain `OP_NOP` tags distinguish both XMSS `scriptCode`
suffixes from the previous templates.

| Output coverage | ForkID | ForkID + ANYONECANPAY | Chronicle OTDA | OTDA + ANYONECANPAY |
|---|---|---|---|---|
| `ALL` | `41` | `c1` | `61` | `e1` |
| `NONE` | `42` | `c2` | `62` | `e2` |
| `SINGLE` | `43` | `c3` | `63` | `e3` |

If `63` or `e3` lacks an output at the current input index, the wrapper
checks the native digest constant and requires the owner to sign a companion
ForkID `SINGLE` preimage. The companion binds the current outpoint and amount.
All outputs remain mutable in that case. See the
[fixed-r binding assumptions](../../lamport-ots/docs/security.md).

## Signing state

The callback uses an XMSS signer with durable state. Before releasing a
signature, the signer must reserve a previously unused leaf index for that
message and persist the consumed index. It tracks indices per XMSS root
across all UTXOs, processes and devices. An unbroadcast or unconfirmed
signature consumes its leaf. Recovery and backup restoration must preserve
the highest reserved index, and the wallet must plan a fresh root before
exhaustion. The payment wrapper verifies the returned signature against the
approved message. The fixture driver uses public test material throughout.

[RFC 8391](https://www.rfc-editor.org/rfc/rfc8391.html) · [NIST SP 800-208](https://csrc.nist.gov/pubs/sp/800/208/final)
