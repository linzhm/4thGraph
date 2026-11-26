# Native P2PK and P2PKH baseline

[简体中文](README.zh-CN.md) · [4thGraph](../../README.md) · [Project index](../README.md)

## Developer resources

**[Wallet SDK quickstart](docs/sdk.en.md#quickstart)** · [Unified wallet SDK](../../sdk/README.md#quickstart)

Receive to P2PK or P2PKH, then sign a payment with your secp256k1 signer.

[Protocol](docs/developer.en.md#protocol) · [Security](docs/developer.en.md#security) · [Verify](#run) · [Transaction costs](#complete-transactions-and-stack-measurements)

Native P2PKH is the first wallet integration example and the transaction-cost baseline for 4thGraph. P2PK uses the same secp256k1 signer and provides a control for placing the public key in the output lock. Both templates have public fixtures that you can replay as you integrate another project.

[Build locks from Forth](forth/README.md) · [Reproduce the benchmark](../../docs/benchmark.md)

## Use cases and trade-offs

Start here when bringing up a transaction builder, a secp256k1 signing device, or a wallet migration. Check serialization with the public vector first. Then connect your own signer and use the same workflow to compare another signature scheme.

P2PKH is the usual choice when a payment request provides a public-key hash. The spending wallet reveals the full public key with the signature. P2PK is useful as a control when the payer already has the recipient's public key. For BIP143 ALL, P2PK moves 10 bytes into each receive output and saves about 34 bytes per spending input. Compare both sides if your wallet batches funding or consolidates many inputs. [Transaction costs](#complete-transactions-and-stack-measurements)

## Run

From `projects/p2pk-p2pkh-baseline/reference/`, with Python 3.12, a Rust
toolchain and uv. [uv documentation](https://docs.astral.sh/uv/)

```sh
uv run --no-project --with-requirements requirements.txt python script_lab.py
```

The first run may download and build the pinned dependency. The script itself
has no network operations. After provisioning, add `--offline` after `uv run`.
It exits nonzero on a script encoding or validation mismatch and otherwise
emits raw parent/spend transactions, ASM, script hex and per-case outcomes.
`../template/baseline.json` is the checked-in output. To check reproducibility,
pipe the same command into `cmp - ../template/baseline.json`.

## Fixture contract

| Template | Unlocking script | Expected verification |
| --- | --- | --- |
| P2PKH | Signature and full compressed pubkey | Correct pair passes; wrong signature fails at CHECKSIG; wrong public key fails at EQUALVERIFY |
| P2PK | Signature only | Correct signature passes; wrong signature fails at CHECKSIG |

Fixture key scalars are public constants (1 and 2). Never use them to hold
funds. The parent references a made-up outpoint; the spend is verified by
supplying that parent directly to the library. Both use version 1 and the
signer uses BIP143 ALL (`SIGHASH_ALL | SIGHASH_FORKID`, `0x41`). These tests exercise parent-aware script
validation, not prior-outpoint existence, node policy, regtest mining, or
mainnet. Do not broadcast these fixtures.

The offline generator and acceptance tests share the repository's Chronicle
pin of the chain-gang Python binding. Projects using that exact pin can share
the same environment. The Rust-backed binding supplies assembly, signing,
and validation. [Shared dependency](../../tools/requirements-chronicle.txt)

To reproduce the original upstream control in its own environment, run
`uv run --no-project --with 'tx-engine==0.13.1' python script_lab.py`.
It reproduces the same checked-in baseline vector. [Upstream package](https://pypi.org/project/tx-engine/0.13.1/)

## Node cross-check

The five checked-in fixtures were also passed to BSV Node 1.2.3
`verifyscript` in isolated Apple Container regtest. The RPC used each raw
spend at input 0 and its synthetic prevout's exact script, amount and height
3, with Genesis at height 1 and Chronicle at height 2. The node agreed with
the pinned offline engine on two accepts and three rejects. This checks
script execution with an explicit prevout. Funded UTXO, mempool and block
acceptance are separate milestones for issue #1.

The [native acceptance matrix](reference/acceptance.md) exhaustively covers
2,880 complete-input combinations in its declared domain, including all
12 paired BIP143 and Chronicle OTDA sighash combinations. It also checks
80 unpaired SINGLE mutation cases and 192 cases around Chronicle activation.
Explicit transaction commitments determine the expected result for each row.

## Developer and wallet integration

A normal P2PK output carries a compressed public key and CHECKSIG. Its input
supplies a signature and the selected sighash byte. P2PKH outputs carry a
20-byte HASH160. That input supplies the signature and the public key whose
hash matches the lock. Use these fixtures to validate an existing wallet's
serialization and signature handling. Authenticate the funding outpoint,
value and locking script before requesting a signature.

With the BIP143 ALL benchmark, moving from P2PK to P2PKH saves 10 bytes
on each output lock and adds about 34 bytes to each input unlock. The
whole-transaction cost therefore depends on the number of each. The
complete-input tests use the modes and activation contexts in the
[acceptance matrix](reference/acceptance.md). The offline example and the unified benchmarks use separate fixtures with the shared Chronicle pin.

## Complete transactions and stack measurements

These deterministic fixtures use commit `beeb4dd`. BSV Node 1.2.3 and the project's pinned chain-gang validate the complete inputs. The node replays scripts with supplied prevouts. Funded mempool and mining tests have separate records. Scripts and transactions are measured in bytes. Script sizes follow input and output order. `× n` indicates n equal sizes. Stack peaks refer to input zero, with independent peaks for main-stack items, altstack items, and combined payload. The development evaluator measures stack payload bytes on the successful path.

| Template and mode | Inputs×outputs | Previous locks | Unlocks | New locks | Total | Main / alt items | Stack payload |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `p2pk` · `0x41` | 2×2 | 35 × 2 | 73 × 2 | 35 × 2 | 326 | 2 / 0 | 105 |
| `p2pk` · `0x61` | 2×2 | 35 × 2 | 72 / 73 | 35 × 2 | 325 | 2 / 0 | 104 |
| `p2pkh` · `0x41` | 2×2 | 25 × 2 | 107 × 2 | 25 × 2 | 374 | 4 / 0 | 145 |
| `p2pkh` · `0x61` | 2×2 | 25 × 2 | 107 × 2 | 25 × 2 | 374 | 4 / 0 | 145 |

## Marginal and lifecycle costs

Each marginal cell shows the **change in total bytes (output locks / input unlocks / other bytes)**. Other bytes include values, outpoints, sequence numbers, and CompactSize fields. Previous locks identify the coins being spent and belong to their funding transactions. Both lifecycle totals include native P2PKH funding and exit. The second adds one payment between project outputs.

| Template and mode | Added-input shape | Added-input bytes | Added-output shape | Added-output bytes | Fund and exit | One turnover |
| --- | --- | --- | --- | --- | --- | --- |
| `p2pk` · `0x41` | 3×2 | 113 (0 / 72 / 41) | 2×3 | 43 (35 / -1 / 9) | 550 | 877 |
| `p2pk` · `0x61` | 3×2 | 113 (0 / 72 / 41) | 2×3 | 45 (35 / 1 / 9) | 549 | 875 |
| `p2pkh` · `0x41` | 3×2 | 146 (0 / 105 / 41) | 2×3 | 34 (25 / 0 / 9) | 598 | 972 |
| `p2pkh` · `0x61` | 3×2 | 146 (0 / 105 / 41) | 2×3 | 33 (25 / -1 / 9) | 599 | 970 |

[Unified benchmark and reproduction](../../docs/benchmark.md)

[Compile the Forth locking scripts](forth/README.md).
