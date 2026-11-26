# P2PKH-R1 v0.2.0

[简体中文](README.zh-CN.md) · [BSV Script Lab](../../README.md)

## Developer resources

**[Wallet SDK quickstart](docs/sdk.en.md#quickstart)** · [Unified wallet SDK](../../shared/sdk/README.md#quickstart)

Create a P-256 receive script and sign an approved payment. The unified client supports prepared inputs and Chronicle OTDA.

[Protocol](docs/spec.en.md) · [Security](docs/developer.en.md#security) · [Verify](reference/acceptance.md) · [Transaction costs](#complete-transactions-and-stack-measurements)

P2PKH-R1 locks a BSV output to the HASH160 of the recipient's uncompressed secp256r1 (P-256) public key. The payer fills a 20-byte owner field. On spend, the wallet supplies the public key and one verified 64-byte `r || s` signature for the selected input.

## Current template

v0.2.0 is the current development version. Its [46,302-byte fixed lock](template/v0.2.0/template.hex) and [binary layout](template/v0.2.0/layout.json) define the format for new outputs. The 59,582-byte [v0.1.0 lock](template/template.hex) remains recognized and spendable. Both use the same owner field at offsets 208 through 227 and support all twelve ForkID and Chronicle OTDA sighash combinations. The wallet verifies the fixed bytes of the actual prevout to identify its template.

Ordinary payments use ForkID ALL (`0x41`) and a 326-byte unlock. The v0.2.0 two-input, two-output fixture is 93,374 bytes, compared with 119,934 bytes for v0.1.0. OTDA is available after Chronicle activation. On version 2 transactions, the reference wallet can reconstruct recognized outputs for OTDA ALL and same-index outputs for paired SINGLE. An unpaired SINGLE uses the companion path.

## Wallet integration

Use the [TypeScript, Rust and Go SDK guide](docs/sdk.en.md) for receiving and ordinary ForkID ALL payments. The [Python reference wallet](reference/README.md) supports selecting a sighash per input, including mixed spends and Chronicle OTDA. Authenticate the funding outpoint, amount and script before asking an external signer to approve the intended outputs and fee.

```sh
cd projects/p2pkh-r1/reference
python -m pip install -r requirements.txt
python generate_lock.py --owner-hash160 "${R1_OWNER_HASH160:?Set the recipient HASH160}"
bash verify.sh
```

See the [protocol specification](docs/spec.en.md), [acceptance matrix](reference/acceptance.md), and [payment vector](template/v0.2.0/spend-all.json). Fixture keys are public test data. Independent review and physical-device validation remain open.

## Complete transactions and stack measurements

These deterministic fixtures use commit `beeb4dd`. BSV Node 1.2.3 and the project's pinned chain-gang validate the complete inputs. The node replays scripts with supplied prevouts. Funded mempool and mining tests have separate records. Scripts and transactions are measured in bytes. Script sizes follow input and output order. `× n` indicates n equal sizes. Stack peaks refer to input zero, with independent peaks for main-stack items, altstack items, and combined payload. The development evaluator measures stack payload bytes on the successful path.

| Template and mode | Inputs×outputs | Previous locks | Unlocks | New locks | Total | Main / alt items | Stack payload |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `v0.1.0` · `0x41` | 2×2 | 59,582 × 2 | 326 × 2 | 59,582 × 2 | 119,934 | 122 / 133 | 4,146 |
| `v0.1.0` · `0x61` | 2×2 | 59,582 × 2 | 119,454 × 2 | 59,582 × 2 | 358,194 | 122 / 133 | 238,734 |
| `compiled-literal` · `0x41` | 2×2 | 47,510 × 2 | 326 × 2 | 47,510 × 2 | 95,790 | 111 / 131 | 3,471 |
| `compiled-literal` · `0x61` | 2×2 | 47,510 × 2 | 95,310 × 2 | 47,510 × 2 | 285,762 | 111 / 131 | 190,446 |
| `compiled-reconstructed` · `0x41` | 2×2 | 47,510 × 2 | 326 × 2 | 47,510 × 2 | 95,790 | 111 / 131 | 3,473 |
| `compiled-reconstructed` · `0x61` | 2×2 | 47,510 × 2 | 6,176 × 2 | 47,510 × 2 | 107,490 | 111 / 131 | 190,446 |
| `compiled-shared-kernels` · `0x41` | 2×2 | 47,510 × 2 | 326 × 2 | 47,510 × 2 | 95,790 | 111 / 131 | 3,479 |
| `compiled-shared-kernels` · `0x61` | 2×2 | 47,510 × 2 | 4,272 × 2 | 47,510 × 2 | 103,682 | 111 / 131 | 190,446 |
| `v0.2.0` · `0x41` | 2×2 | 46,302 × 2 | 326 × 2 | 46,302 × 2 | 93,374 | 113 / 131 | 3,479 |
| `v0.2.0` · `0x61` | 2×2 | 46,302 × 2 | 4,264 × 2 | 46,302 × 2 | 101,250 | 113 / 131 | 185,613 |
| `compiled + v0.2.0` · `0x61` · before | 2×2 | 46,302 / 47,510 | 50,549 × 2 | 46,302 / 47,510 | 195,028 | 113 / 131 | 188,029 |
| `compiled + v0.2.0` · `0x61` · after | 2×2 | 46,302 / 47,510 | 8,186 × 2 | 46,302 / 47,510 | 110,302 | 113 / 131 | 188,030 |
| `compiled + v0.2.0` · `0xe1` · before | 2×2 | 46,302 / 47,510 | 50,507 × 2 | 46,302 / 47,510 | 194,944 | 113 / 131 | 187,947 |
| `compiled + v0.2.0` · `0xe1` · after | 2×2 | 46,302 / 47,510 | 8,144 × 2 | 46,302 / 47,510 | 110,218 | 113 / 131 | 187,947 |
| `v0.2.0` · `0x63` · after | 2×2 | 46,302 × 2 | 4,224 / 4,233 | 46,302 × 2 | 101,179 | 113 / 131 | 92,987 |
| `v0.2.0` · `0xe3` · after | 2×2 | 46,302 × 2 | 4,182 / 4,191 | 46,302 × 2 | 101,095 | 113 / 131 | 92,905 |

## Marginal and lifecycle costs

Each marginal cell shows the **change in total bytes (output locks / input unlocks / other bytes)**. Other bytes include values, outpoints, sequence numbers, and CompactSize fields. Previous locks identify the coins being spent and belong to their funding transactions. Both lifecycle totals include native P2PKH funding and exit. The second adds one payment between project outputs.

| Template and mode | Added-input shape | Added-input bytes | Added-output shape | Added-output bytes | Fund and exit | One turnover |
| --- | --- | --- | --- | --- | --- | --- |
| `v0.1.0` · `0x41` | 3×2 | 369 (0 / 326 / 43) | 2×3 | 59,593 (59,582 / 0 / 11) | 120,160 | 240,093 |
| `v0.1.0` · `0x61` | 3×2 | 119,622 (0 / 119,577 / 45) | 2×3 | 178,779 (59,582 / 119,186 / 11) | 120,173 | 478,367 |
| `compiled-literal` · `0x41` | 3×2 | 369 (0 / 326 / 43) | 2×3 | 47,521 (47,510 / 0 / 11) | 96,015 | 191,806 |
| `compiled-literal` · `0x61` | 3×2 | 95,478 (0 / 95,433 / 45) | 2×3 | 142,563 (47,510 / 95,042 / 11) | 96,029 | 381,791 |
| `compiled-reconstructed` · `0x41` | 3×2 | 369 (0 / 326 / 43) | 2×3 | 47,521 (47,510 / 0 / 11) | 96,016 | 191,806 |
| `compiled-reconstructed` · `0x61` | 3×2 | 6,342 (0 / 6,299 / 43) | 2×3 | 47,601 (47,510 / 80 / 11) | 96,030 | 203,520 |
| `compiled-shared-kernels` · `0x41` | 3×2 | 369 (0 / 326 / 43) | 2×3 | 47,521 (47,510 / 0 / 11) | 96,016 | 191,806 |
| `compiled-shared-kernels` · `0x61` | 3×2 | 4,438 (0 / 4,395 / 43) | 2×3 | 47,601 (47,510 / 80 / 11) | 96,030 | 199,712 |
| `v0.2.0` · `0x41` | 3×2 | 369 (0 / 326 / 43) | 2×3 | 46,313 (46,302 / 0 / 11) | 93,600 | 186,973 |
| `v0.2.0` · `0x61` | 3×2 | 4,430 (0 / 4,387 / 43) | 2×3 | 46,393 (46,302 / 80 / 11) | 93,614 | 194,864 |
| `compiled + v0.2.0` · `0x61` · before | 3×2 | 50,715 (0 / 50,672 / 43) | 2×3 | 48,793 (46,302 / 2,480 / 11) | 94,822 | 289,850 |
| `compiled + v0.2.0` · `0x61` · after | 3×2 | 8,352 (0 / 8,309 / 43) | 2×3 | 46,393 (46,302 / 80 / 11) | 94,821 | 205,124 |
| `compiled + v0.2.0` · `0xe1` · before | 3×2 | 50,550 (0 / 50,507 / 43) | 2×3 | 48,793 (46,302 / 2,480 / 11) | 94,740 | 289,683 |
| `compiled + v0.2.0` · `0xe1` · after | 3×2 | 8,187 (0 / 8,144 / 43) | 2×3 | 46,393 (46,302 / 80 / 11) | 94,740 | 204,958 |
| `v0.2.0` · `0x63` · after | 3×2 | 455 (0 / 412 / 43) | 2×3 | 46,313 (46,302 / 0 / 11) | 93,555 | 194,733 |
| `v0.2.0` · `0xe3` · after | 3×2 | 373 (0 / 330 / 43) | 2×3 | 46,313 (46,302 / 0 / 11) | 93,472 | 194,567 |

[Unified benchmark and reproduction](../../shared/benchmark.md) · [Matched sCrypt comparison](docs/scrypt-matched.en.md)
