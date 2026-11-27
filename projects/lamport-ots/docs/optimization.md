# Forth committed-key optimization

[English overview](../README.md) · [中文开发指南](developer.zh-CN.md#optimization) · [Wire format](spec.md) · [Validation](validation.md)

`committed-key-forth` reduces the committed-key payment lock from **7,746 to 7,042 bytes**. `committed-key-forth-compact` reduces it further to **6,830 bytes**, 11.8% below the original commitment lock. Both profiles use the existing commitment, 16,384-byte proof and preimage checks. The wallet SDK exposes both experimental profiles. [4thGraph PR #68](https://github.com/linzhm/4thGraph/pull/68) · [Reference factories](../reference/script.py)

## Reconstruction and compiler boundary

The original committed verifier converts each digest byte to an unsigned ScriptNum, then uses `MOD 2` and `DIV 2` to walk its bits from least to most significant. For each bit it hashes the disclosed secret and concatenates that hash with the sibling hash in public-key order. Each group of eight pairs forms a 512-byte chunk. SHA-256 of the concatenated chunks must equal the 32-byte commitment in the lock.

The Forth word keeps one raw digest byte and applies masks `01 02 04 08 10 20 40 80`. The predicate `(digest_byte AND mask) == mask` produces a canonical Script boolean, including for `80`, which would be negative zero if used directly as a Script truth value. Bit zero orders the selected hash first. Bit one swaps the hashes. The loop keeps appending 512-byte chunks and checks that both proof and digest are fully consumed. The per-byte stack invariant is `[accumulated_key, remaining_proof, remaining_digest]` from bottom to top. The word balances its own alternate-stack entries and preserves the selector, type and digest that the transaction-binding wrapper saved there. [Forth source](../forth/committed-verifier.fth) · [Shared PUSHTX code](../../../src/fourthgraph/bsv/pushtx.py)

| Reconstruction component | Original bytes | Forth bytes |
| --- | ---: | ---: |
| Initialize and finish | 8 | 8 |
| Stack transitions per digest byte | 20 | 11 |
| Eight pair steps per digest byte | 192 | 179 |
| Core across all 32 digest bytes | 6,792 | 6,088 |
| Commitment push, equality check and payment wrapper | 954 | 954 |
| Complete lock | 7,746 | 7,042 |

The adapter uses #68's typed native vocabulary for operations such as `OP_SPLIT`, `OP_SHA256`, `OP_EQUAL` and `OP_CAT`. It type-checks and lowers the three Forth words, then repeats the compiled one-byte fragment 32 times. The project supplies local words for the empty byte string, alternate-stack moves, bitwise AND, the fixed-depth copy and the conditional swap. The compiler checks the main-stack effects. The source and execution tests check the alternate-stack discipline. Baseline, safe and stack lowering produced the same fragment sizes of 3, 190 and 5 bytes. The candidate uses baseline lowering. The size gain comes from the algorithm and stack layout. [Compiler adapter](../reference/forth_verifier.py)

## Compact transaction binding

The compact profile keeps the 6,088-byte Forth reconstruction core and uses the shared compact fixed-r DER builder. The builder reverses bytes on the main stack and reuses one push of the curve order. It constructs the compressed public key from the fixed `r` already in DER. The companion check reuses that key via `OP_OVER`. The last executed code separator selects the same `68ac` or `63ad67ab68ac` scriptCode as before.

| Binding change | Bytes saved |
| --- | ---: |
| Compact DER construction | 158 |
| Construct public key from fixed `r` | 21 |
| Reuse public key in the companion check | 33 |
| Total, 712 to 500 bytes | 212 |

For the first input of each 2×2 fixture, the main-stack peak increases from 8 to 32 items and the altstack peak drops from 34 to 5. Combined payload peaks at 16,707 bytes in both BIP143 fixtures. OTDA's shorter signing preimage lowers its peak from 44,795 to 43,947 bytes. The development evaluator counts payload and stack items. A focused test checks that each native call receives the original signature and public-key bytes in both paths. [Binding code](../../../src/fourthgraph/bsv/pushtx.py) · [Verification](validation.md#compact-binding-replay-on-latest-main)

## OTDA unlocking reconstruction

The compact lock repeats the 190-byte Forth byte step 32 times. The unlocking program pushes the step once and doubles it with five `OP_DUP OP_CAT` pairs. A 928-byte program produces the two fixed parts of the 6,830-byte lock as data. The shared reconstruction helper inserts each output's commitment in its original position and emits the serialized outputs in order. It matches every fixed byte before using the pattern and copies unmatched outputs verbatim. The signer still authorizes the exact preimage. The program reproduces the same `[preimage, proof, selector]` stack. [Template construction](../reference/script.py) · [Shared reconstruction](../../../src/fourthgraph/bsv/otda_reconstruction.py)

The wallet offers reconstruction as an opt-in encoding for Chronicle version-2 transactions. It covers OTDA ALL and paired OTDA SINGLE, including their ANYONECANPAY variants. It uses the literal encoding for other modes and whenever the reconstructed witness is at least as large as the literal one. A serialized witness change changes the txid. [SDK options](sdk.en.md#reconstruct-otda-preimages) · [Security and recovery](security.md#unconfirmed-parent-txids)

For OTDA ALL 2×2, each input falls from 30,171 to 17,526 bytes. The transaction drops by **25,290 bytes (34.1%)** to 48,830. The benchmark still observes a 43,947-byte peak combined stack payload because Script consumes the full reconstructed preimage. In a native P2PKH exit the wallet uses the literal encoding because no output matches the compact lock.

## Version 0.2.0 candidate

The candidate splits both 32-byte proof fields before hashing the selected secret. This leaves the selected hash above its sibling, so `OP_NOTIF` swaps them for a clear bit. The same byte mask produces a canonical boolean. One fewer `OP_SWAP` in each of 256 pair steps saves 256 bytes, and the compiled digest-byte fragment shrinks from 190 to 182 bytes.

The sighash guard requires `(type & 0x5c) == 0x40` and a nonzero `(type & 3)`. This requires ForkID, clears the three reserved bits and admits the three base modes with Chronicle and ANYONECANPAY as independent options. The companion branch masks off ANYONECANPAY and requires `0x43`. The guard still requires zero high type bytes and applies the same preimage shape and scriptCode checks. These changes save another 49 bytes in the guard. [Forth source](../forth/committed-verifier.fth) · [Authorization code](../../../src/fourthgraph/bsv/pushtx.py)

The SDK creates `committed-key-forth-v0.2.0` from a pinned 6,525-byte template with one 32-byte commitment field. Its 871-byte OTDA program is pinned alongside it. With reconstruction enabled, the wallet compares both single-template programs and a mixed program for old compact and v0.2.0 outputs, then selects the shortest usable encoding. In the 2×2 workloads this saves 610 bytes in BIP143 ALL and 724 bytes in reconstructed OTDA ALL relative to the previous compact profile. Direct exits to native P2PKH still carry a 16,384-byte proof per Lamport input. [Pinned layout](../versions/v0.2.0/layout.json) · [Versioned measurements](../versions/v0.2.0/measurements.json)

## Fixed-weight candidate

`committed-key-forth-subset` uses four-of-eleven selection per digest byte. It
retains full SHA-256 hashes and independent 32-byte secrets. The typed Forth
build emits a 7,310-byte proof verifier using a 512-byte mask table and a
212-byte word repeated for each digest byte. The complete lock is 8,003 bytes.
Its OTDA dictionary program is 1,420 bytes and can be used alongside older
dictionaries by the shortest-encoding selection. [Protocol and security argument](subset.en.md) · [Forth source](../forth/subset-verifier.fth)

| Measurement (bytes) | v0.2.0 | Fixed-weight | Change |
| --- | ---: | ---: | ---: |
| Raw signature | 8,192 | 4,096 | −4,096 |
| Committed proof | 16,384 | 11,264 | −5,120 |
| Lock per output | 6,525 | 8,003 | +1,478 |
| BIP143 ALL unlock per input | 16,549 | 11,429 | −5,120 |
| BIP143 ALL 2×2 payment | 46,266 | 38,982 | −7,284 |
| Chronicle OTDA ALL 2×2, literal | 72,290 | 70,918 | −1,372 |
| Chronicle OTDA ALL 2×2, reconstruction enabled | 48,106 | 41,920 | −6,186 |
| BIP143 ALL direct exit to native P2PKH | 33,262 | 23,022 | −10,240 |
| Chronicle OTDA ALL direct exit to native P2PKH | 33,276 | 23,036 | −10,240 |

Direct exits spend two Lamport inputs and create native P2PKH outputs.
The 2×2 payments create two fresh same-profile outputs. For BIP143 ALL with
fixed serialization widths, replacing a v0.2.0 input saves 5,120 bytes, while
replacing a v0.2.0 output adds 1,478 bytes. At a uniform fee rate the candidate
reduces spend bytes below about 3.46 candidate outputs per candidate input. In literal OTDA ALL, the bigger locks also appear in
each input's preimage. With reconstruction, each OTDA ALL 2×2 unlock is 12,898
bytes, down from 17,469. [Dual-engine and funded results](validation.md#fixed-weight-candidate-replay)

## Transaction and lifecycle costs

`0x41` is BIP143 ALL. `0x61` is Chronicle OTDA ALL. The 2×2 workload spends two Lamport outputs and creates two new ones under the same template. Marginal columns compare with the 3×2 and 2×3 workloads. In the lifecycle workloads a native P2PKH input funds two Lamport outputs, then both exit to native P2PKH. The turnover path adds one Lamport-to-Lamport payment before exit. All sizes are serialized bytes.

| Profile | Mode | Unlock per input, 2×2 | 2×2 | Extra input | Extra output | Fund and exit | One turnover |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `full-key` | `0x41` | 8,357 | 62,392 | 8,400 | 22,791 | 62,617 | 125,010 |
| `full-key` | `0x61` | 53,879 | 153,436 | 54,045 | 68,381 | 62,631 | 216,068 |
| `committed-key` | `0x41` | 16,549 | 48,708 | 16,592 | 7,757 | 48,933 | 97,641 |
| `committed-key` | `0x61` | 32,003 | 79,616 | 32,169 | 23,271 | 48,948 | 128,564 |
| `committed-key-forth` | `0x41` | 16,549 | 47,300 | 16,592 | 7,053 | 47,526 | 94,825 |
| `committed-key-forth` | `0x61` | 30,595 | 75,392 | 30,761 | 21,159 | 47,539 | 122,932 |
| `committed-key-forth-compact` | `0x41` | 16,549 | 46,876 | 16,592 | 6,841 | 47,102 | 93,978 |
| `committed-key-forth-compact` | `0x61` | 30,171 | 74,120 | 30,337 | 20,523 | 47,115 | 121,236 |
| Compact, reconstruction enabled | `0x41` | 16,549 | 46,876 | 16,592 | 6,841 | 47,102 | 93,978 |
| Compact, reconstruction enabled | `0x61` | 17,526 | 48,830 | 17,692 | 6,945 | 47,116 | 95,946 |
| v0.2.0 | `0x41` | 16,549 | 46,266 | 16,592 | 6,536 | 46,492 | 92,758 |
| v0.2.0 | `0x61` | 29,561 | 72,290 | 29,727 | 19,608 | 46,506 | 118,795 |
| v0.2.0, reconstruction enabled | `0x41` | 16,549 | 46,266 | 16,592 | 6,536 | 46,491 | 92,757 |
| v0.2.0, reconstruction enabled | `0x61` | 17,469 | 48,106 | 17,635 | 6,640 | 46,506 | 94,611 |
| Fixed-weight | `0x41` | 11,429 | 38,982 | 11,472 | 8,014 | 39,208 | 78,190 |
| Fixed-weight | `0x61` | 27,397 | 70,918 | 27,563 | 24,042 | 39,221 | 110,139 |
| Fixed-weight, reconstruction enabled | `0x41` | 11,429 | 38,982 | 11,472 | 8,014 | 39,207 | 78,189 |
| Fixed-weight, reconstruction enabled | `0x61` | 12,898 | 41,920 | 13,064 | 8,118 | 39,222 | 81,141 |

The Forth lock saves **1,408 B (2.9%)** for 2×2 BIP143 ALL and **4,224 B (5.3%)** for 2×2 OTDA ALL relative to the original commitment profile. With the same serialization field widths and `I` Lamport inputs and `O` changed Lamport outputs, the BIP143 ALL savings are `704 × O`. OTDA ALL increases that to `704 × O × (1 + I)` because each ordinary Lamport input carries the serialized outputs in its preimage. The formula assumes the same mode and widths on all affected witnesses. Adding only inputs to a BIP143 consolidation into ordinary outputs yields identical spend bytes for the two committed profiles.

Versus full-key, the Forth commitment trades **15,738 fewer bytes per output** for **8,192 extra BIP143 proof bytes per input**. For an otherwise identical BIP143 transaction at one fee rate, the break-even output/input ratio is `8,192 / 15,738 ≈ 0.521`. For an output funded and later spent at different rates, the same threshold applies to the funding/exit fee-rate ratio. Native P2PKH DER signatures in separate lifecycle fixtures can vary by a byte, which accounts for one-byte differences around the exact lock and proof deltas.

The compact profile saves another 424 bytes in BIP143 and 1,272 bytes in OTDA ALL for the same 2×2 layout. Its break-even output/input ratio versus full-key is `8,192 / 15,950 ≈ 0.514`. Both compact and first-round Forth inputs measure 16,549 bytes under BIP143 ALL. [Benchmark runner and reproduction](../../../docs/benchmark.md) · [Validation scope](validation.md)

## Further optimization

- The WOTS+ project provides a comparison with a hash-chain signature. Its proof and verifier use a different layout and hashing workload. Compare whole transactions and verification work when evaluating smaller witnesses. [WOTS+ project measurements](../../wots-plus/README.md)

Each profile has its own output script bytes. A transaction that changes profiles has a different txid when all other transaction bytes are equal, so the new outpoint requires its own authorization. Keep keys unique across profiles. BSV Node 1.2.3 accepted and mined funding, one turnover and exit for each Forth profile under default regtest transaction policy for both ALL modes. The version catalog lists v0.2.0 as the next candidate. [Security and recovery](security.md) · [Funded regtest results](validation.md#funded-regtest) · [Version catalog](../versions/index.json)
