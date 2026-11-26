# Forth committed-key optimization

[English overview](../README.md) · [中文开发指南](developer.zh-CN.md#optimization) · [Wire format](spec.md) · [Validation](validation.md)

`committed-key-forth` reduces the committed-key payment lock from **7,746 to 7,042 bytes** (9.1%). The candidate targets output size while retaining the existing commitment, 16,384-byte proof, preimage checks and native transaction-binding suffix. It is an experimental profile selectable through the wallet SDK. [4thGraph PR #68](https://github.com/linzhm/4thGraph/pull/68) · [Reference factories](../reference/script.py)

## Reconstruction and compiler boundary

The original committed verifier converts each digest byte to an unsigned ScriptNum, then uses `MOD 2` and `DIV 2` to walk its bits from least to most significant. For each bit it hashes the disclosed secret and concatenates that hash with the sibling hash in public-key order. Each group of eight pairs forms a 512-byte chunk. SHA-256 of the concatenated chunks must equal the 32-byte commitment in the lock.

The Forth word keeps one raw digest byte and applies masks `01 02 04 08 10 20 40 80`. The predicate `(digest_byte AND mask) == mask` produces a canonical Script boolean, including for `80`, which would be negative zero if used directly as a Script truth value. Bit zero orders the selected hash first. Bit one swaps the hashes. The loop keeps appending 512-byte chunks and checks that both proof and digest are fully consumed. The per-byte stack invariant is `[accumulated_key, remaining_proof, remaining_digest]` from bottom to top. The word balances its own alternate-stack entries and preserves the selector, type and digest that the transaction-binding wrapper saved there. [Forth source](../reference/committed-verifier.fth) · [Shared PUSHTX code](../../../src/fourthgraph/bsv/pushtx.py)

| Reconstruction component | Original bytes | Forth bytes |
| --- | ---: | ---: |
| Initialize and finish | 8 | 8 |
| Stack transitions per digest byte | 20 | 11 |
| Eight pair steps per digest byte | 192 | 179 |
| Core across all 32 digest bytes | 6,792 | 6,088 |
| Commitment push, equality check and payment wrapper | 954 | 954 |
| Complete lock | 7,746 | 7,042 |

The adapter uses #68's typed native vocabulary for operations such as `OP_SPLIT`, `OP_SHA256`, `OP_EQUAL` and `OP_CAT`. It type-checks and lowers the three Forth words, then repeats the compiled one-byte fragment 32 times. The project supplies local words for the empty byte string, alternate-stack moves, bitwise AND, the fixed-depth copy and the conditional swap. The compiler checks the main-stack effects. The source and execution tests check the alternate-stack discipline. Baseline, safe and stack lowering produced the same fragment sizes of 3, 190 and 5 bytes. The candidate uses baseline lowering. The size gain comes from the algorithm and stack layout. [Compiler adapter](../reference/forth_verifier.py)

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

The Forth lock saves **1,408 B (2.9%)** for 2×2 BIP143 ALL and **4,224 B (5.3%)** for 2×2 OTDA ALL relative to the original commitment profile. With the same serialization field widths and `I` Lamport inputs and `O` changed Lamport outputs, the BIP143 ALL savings are `704 × O`. OTDA ALL increases that to `704 × O × (1 + I)` because each ordinary Lamport input carries the serialized outputs in its preimage. The formula assumes the same mode and widths on all affected witnesses. Adding only inputs to a BIP143 consolidation into ordinary outputs yields identical spend bytes for the two committed profiles.

Versus full-key, the Forth commitment trades **15,738 fewer bytes per output** for **8,192 extra BIP143 proof bytes per input**. For an otherwise identical BIP143 transaction at one fee rate, the break-even output/input ratio is `8,192 / 15,738 ≈ 0.521`. For an output funded and later spent at different rates, the same threshold applies to the funding/exit fee-rate ratio. Native P2PKH DER signatures in separate lifecycle fixtures can vary by a byte, which accounts for one-byte differences around the exact lock and proof deltas.

On the first 2×2 input, both commitment profiles peak at 16,707 bytes of combined stack payload for BIP143. For OTDA the Forth fixture drops from 47,611 to 44,795 bytes as the carried preimage shrinks. The main-stack peak increases from seven to eight items and the altstack peak stays at 34 in those fixtures. The development evaluator measures these payloads and item counts. BSV Node and chain-gang check the complete input verdicts. [Benchmark runner and reproduction](../../../docs/benchmark.md) · [Validation scope](validation.md)

## Further optimization

- The current binding wrapper gives a smaller, separable opportunity. The shared library already emits a 390-byte compact DER construction, versus the 548-byte construction used here. A binding-only candidate could measure that 158-byte static difference and replay both code-separator paths and the DER boundary cases. The Forth candidate keeps the existing binding so its measured effect comes from reconstruction. [Shared binding implementation](../../../src/fourthgraph/bsv/pushtx.py)
- The 16,384-byte proof dominates BIP143 input cost. Reducing it requires changing what the verifier receives or changing the signature construction. The existing WOTS+ project is a useful comparison when input size matters. Compare full transactions and verification work before selecting either construction. [WOTS+ project measurements](../../wots-plus/README.md)
- OTDA preimage reconstruction targets a different source of witness bytes. It is most relevant when many inputs carry large output scripts. The shared reconstruction code and WOTS+ experiments give implementation baselines for a follow-up with explicit sighash coverage. [OTDA reconstruction code](../../../src/fourthgraph/bsv/otda_reconstruction.py) · [WOTS+ experiments](../../wots-plus/README.md)

The candidate has its own output script bytes. A transaction that creates it has a different txid when all other transaction bytes are equal, so the new outpoint requires its own authorization. Keep keys unique across profiles. BSV Node 1.2.3 accepted and mined funding, one turnover and exit under default regtest transaction policy for both ALL modes. Promoting the profile would require a frozen template and evidence for the intended deployment policy. [Security and recovery](security.md) · [Funded regtest results](validation.md#funded-regtest)
