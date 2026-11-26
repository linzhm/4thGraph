# WOTS+ validation record

| Check | Result |
|---|---|
| Python and development Script tests | 7 passed, including all 67 signature-chain mutations, concurrent signer use and 16 deterministic payment vectors |
| Independent XMSS C reference | Public endpoint commitment and four complete signatures matched revision `171ccbd26f098542a67eb5d2b128281c80bd71a6`, built against OpenSSL |
| chain-gang complete inputs | All 1,230 declared payment rows matched at revision `74676b9c002c452e7f21a9ed9265f4972bef03f6`. The fixture covers all 12 modes, unpaired `SINGLE`, malformed witnesses and explicit Chronicle contexts. |
| Existing templates | All 12 Lamport regression tests and both repository layout tests passed, including existing signature vectors and canonical R1 bytes |
| BSV Node 1.2.3 | All 1,230 declared payment rows matched on isolated Linux x86-64 regtest. Every response returned the supplied script flags. |
| bsv-script-lean | The existing replay matched 125 of 125 fixtures, including two pre-Chronicle spends. The executable from the `1c051eaef1077cc95e5d1618686d5efacc4aa097` checkout reported `spec@unknown` and had SHA-256 `e0451889b7259997aceaaf119c3d1075b2336ecd7004f3a37f13a5d18061d699`. |

## Compact profile

Starting at PR #68 commit `bc6fe95`, the compact lock reduced the
`cached-steps` size from 33,956 to 29,217 bytes. BSV Node 1.2.3 and
chain-gang at `74676b9` matched all 1,230 rows for each of the four
profiles, including 442 accepted and 788 rejected rows per profile.
Both engines rejected each of the 67 signature-chain mutations for
each profile.

The complete transaction tests pin the compact sizes for 2×2, 3×2 and
2×3 payments in BIP143 ALL and the four reconstructible OTDA modes.
They compare the literal and reconstructed witness stacks and exercise
mixed compact, cached-steps and native outputs. Lean `spec@1c051ea`
matched all 125 compact fixtures. The wallet replay passed in Python,
TypeScript, Go and Rust. [Measurements and replay commands](../README.md#compact-profile)

## Compact v2 profile

With the compiler at `454456f`, `compact-v2` builds a 27,070-byte lock
and a 2,358-byte reconstruction program. Its detached tests exercise all
16 starting digits. BSV Node 1.2.3 and chain-gang at `74676b9` matched the
1,230 payment outcomes and rejected all 67 signature-chain mutations.
The matrix also passed for the four older profiles.

The two engines checked the 2×2, 3×2 and 2×3 compact-v2 sizes. They
validated mixed OTDA ALL transactions containing all three supported
reconstruction formats alongside a native output. Lean `spec@1c051ea`
matched all 125 compact-v2 fixtures. The Python, TypeScript, Go and Rust
wallet replays passed. [Measurements and replay commands](../README.md#compact-profile)

## Compact v3 profile

The compiler at `454456f` builds a 25,965-byte lock and a 1,979-byte
reconstruction program. Focused tests check all 16 starting digits,
all 256 sighash flag bytes, and DER construction around the ECDSA
modulus and low-S boundary.

BSV Node 1.2.3 and chain-gang at `74676b9` matched the 1,230 payment
outcomes and rejected all 67 signature-chain mutations. They checked
the measured transaction sizes and reconstructed mixed OTDA ALL
outputs using all four dictionaries. Lean `spec@1c051ea` matched all 125
fixtures. Python, TypeScript, Go and Rust wallet replays passed.
[Measurements and replay commands](../README.md#compact-profile)

## Compact v4 profile

Compiler revision `6699658` builds a 23,296-byte lock and a 1,884-byte
reconstruction program. Focused checks exercise all 16 starting digits
and compare the signatures and public keys passed to native CHECKSIG
on both the ordinary and companion paths.

BSV Node 1.2.3 and chain-gang at `74676b9` matched all 1,230 payment
outcomes and rejected all 67 signature-chain mutations. Both engines
validated the measured transaction sizes and mixed OTDA ALL outputs
using all five dictionaries. Lean `spec@1c051ea` matched all 125 fixtures.
Python, TypeScript, Go and Rust wallet replays passed, along with 24
Lamport regression tests. [Measurements and replay commands](../README.md#compact-profile)

## Compact v5 profile

Compiler revision `6699658` builds a 22,494-byte lock and a 1,126-byte
reconstruction program. The artifact tests compare the reconstructed
fixed parts byte for byte. The signature tests exercise all 16 starting
digits.

BSV Node 1.2.3 and chain-gang at `74676b9` matched all 1,230 payment
outcomes and rejected all 67 signature-chain mutations. Both engines
validated the measured transaction sizes and mixed OTDA ALL outputs
using all six dictionaries. Lean `spec@1c051ea` matched all 125 fixtures.
Python, TypeScript, Go and Rust wallet replays passed, along with 24
Lamport regression tests. [Measurements and replay commands](../README.md#compact-profile)

## Compact v6 profile

Compiler revision `6699658` builds a 21,982-byte lock and a 1,076-byte
reconstruction program. Focused tests exercise the address increment with
zero and high-bit public seeds. They also compare the exact signatures and
public keys passed to both CHECKSIG paths against the earlier binding.

BSV Node 1.2.3 and chain-gang at `74676b9` matched all 1,230 payment
outcomes and rejected all 67 signature-chain mutations. Both engines
validated the measured transaction sizes and mixed OTDA ALL outputs
using all seven dictionaries. Lean `spec@1c051ea` matched all 125 fixtures.
Python, TypeScript, Go and Rust wallet replays passed, along with 24
Lamport regression tests. [Measurements and replay commands](../README.md#compact-profile)

## Compact v7 profile

Compiler revision `6699658` builds a 21,774-byte lock and a 957-byte
reconstruction program. Focused tests compare both digest decoders across
all 256 byte values and check all 256 companion flags, mutations in each
byte of the companion zero hash, and addresses with zero and high-bit
public seeds. The compatibility comparison matched 57 existing artifact
fingerprints and 20 existing transaction fingerprints.

BSV Node 1.2.3 and chain-gang at `74676b9` matched all 1,230 payment
outcomes and rejected all 67 signature-chain mutations. Both engines
validated the measured transaction sizes and mixed OTDA ALL outputs
using all eight dictionaries. Lean `spec@1c051ea` matched all 125 fixtures.
Python, TypeScript, Go and Rust wallet replays passed, along with 24
Lamport regression tests. [Measurements and replay commands](../README.md#compact-profile)

## Bounded coverage of complete payments

The [acceptance fixture](../reference/test_acceptance.py) builds the expected key
set from the payment specification. It checks the fixture generators against
that set and judges each spend independently using the documented sighash
commitments and Chronicle activation.

| Base case family | Required labels |
|---|---:|
| 12 modes × original paired spend and six mutations | 84 |
| Four `SINGLE` modes × five pairing and unpaired-output cases | 20 |
| Two OTDA `SINGLE` modes × two companion witness mutations | 4 |
| Named malformed witness and preimage cases | 15 |
| Total | 123 |

Each label is crossed with transaction versions 1 and 2 and five height
contexts. With Chronicle activation at height 3, those contexts are spending
at height 2 with input creation heights `(1, 1)`, and spending at height 4
with each of `(1, 1)`, `(1, 3)`, `(3, 1)`, and `(3, 3)`. The product has
`123 × 2 × 5 = 1,230` distinct rows. An assertion rejects duplicate or
unexpected rows, and exact set equality after validation detects any missing
row. The table of accepted flags is written independently of the generator's
sighash masks. It admits 25 base cases before activation and 49 in each
post-activation context, so the product must contain exactly 442 accepted
and 788 rejected rows. A chain-gang rejection must report script failure.
The native RPC run also compares the exact flags for the selected input.
An in-memory mutation check independently removed a generated label,
duplicated a label, and flipped a fixture's expected verdict. The suite
reported all three changes as failures.

One additional complete spend pins the packed length of 67 chains and tests
flipping the low bit of each chain's first byte separately. The reference spend and the
67 mutations are checked in both engines. This proves coverage of the 67
selected positions in that witness. Arbitrary Script bytes, all keys and
signature mutations, other chain heights, miner policy and persistent key
management fall outside the finite payment proof. [WOTS+ specification](spec.md)

<a name="forkid-all-measurements"></a>

## BIP143 `ALL` measurements

Both measurements used a single-input, single-output synthetic payment. Lock
and unlock columns are Script bytes, excluding transaction wire overhead. The
timings are the median of 30 warm complete-transaction checks in the same
chain-gang build on macOS arm64 with Python 3.12.

| Template | Raw signature | Lock | Unlock | Lock + unlock | Chain-gang |
|---|---:|---:|---:|---:|---:|
| Lamport OTS | 8,192 B | 22,780 B | 8,357 B | 31,137 B | 0.289 ms |
| WOTS+ | 2,144 B | 42,266 B | 2,310 B | 44,576 B | 1.028 ms |

WOTS+ saves 6,047 bytes on the spend's unlocking script. This implementation
adds 19,486 bytes to the funding lock, largely because the Script unrolls the
keyed and masked chain steps. Across both scripts it adds 13,439 bytes, or 43%.

Run the suites and regenerate the vectors using the
[project README](../README.md#run-the-checks) and `reference/fixtures.py`.
