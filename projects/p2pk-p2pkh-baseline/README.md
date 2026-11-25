# Native P2PK and P2PKH baseline

**Status** · v0.1 development baseline.

Offline examples for conventional P2PKH and P2PK locking scripts. This is a
test lab, not a wallet, production signer, covenant implementation, or node.

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
signer uses SIGHASH_ALL with FORKID. These tests exercise parent-aware script
validation, not prior-outpoint existence, node policy, regtest mining, or
mainnet. Do not broadcast these fixtures.

The offline generator and acceptance tests share the repository's Chronicle
pin of the chain-gang Python binding. Projects using that exact pin can share
the same environment. The Rust-backed binding supplies assembly, signing,
and validation. [Shared dependency](../../shared/requirements-chronicle.txt)

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
12 paired ForkID and Chronicle OTDA sighash combinations. It also checks
80 unpaired SINGLE mutation cases and 192 cases around Chronicle activation.
Explicit transaction commitments determine the expected result for each row.
