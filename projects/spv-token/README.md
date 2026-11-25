# BSV SPV Token

This project develops an experimental BSV UTXO token protocol with receiver-side verification. Its first bridge application uses an EVM reserve to back a BSV token with source-chain USDC. The current test profile is the **Two-Slot Lifecycle**, named for its two business input and output slots.

[Design conditions](#design-conditions) · [Implementation challenges](#implementation-challenges) · [Current progress](#current-progress) · [Roadmap](#roadmap) · [Replay the evidence](#replay-the-evidence)

## Design conditions

- **Verify the exact coin received.** A receiver starts from a specific `txid:vout` and checks its amount, owner, policy, and provenance back to an authorized issuance anchor. The receiver verifies headers and inclusion evidence and can inspect the required direct parents. A full token index and a walk through all token ancestors are outside the wallet's data requirements.
- **Conserve each asset.** Every actual token input and every recognized token output participates in the accounting. Only authorized minting and burning change supply. The USDC example uses six-decimal integer units and accounts for BSV satoshis separately.
- **Let holders pay independently.** Ordinary transfers use holder authorization. Any payer can create the required verifier funding, and a receiving wallet should be able to make the next payment from a single received coin. Issuer and manager roles have explicit authority for minting and management actions under the asset policy.
- **Bound the cost of history.** For a fixed input and output shape, transaction and witness sizes must stay constant as transfers accumulate. Measure preparation, verifier funding, settlement, and recipient verification together. Measure the cost of adding an input or output separately.
- **Make the bridge trust model explicit.** Source-chain finality, reserve attestations, and redemption are bridge responsibilities. The BSV rules bind authorized minting and burn receipts to actual transactions. Each deposit or release must settle at most once.

Bitcoin inclusion evidence establishes that the receiving transaction appeared in the adopted chain. A wallet also needs a current view of spends and conflicts before it marks the coin as spendable.

## Implementation challenges

| Challenge | What the implementation must establish |
| --- | --- |
| A copied lock can look like a token | Bind the rule and proof to actual input outpoints, canonical parent outputs, and the complete ordered outputs of the spending transaction. This also covers an extra token output appended after an otherwise balanced transfer. |
| A proof must stay tied to real transaction bytes | Authenticate the executing transaction with BSV Script and its ForkID preimage. Use a direct-parent SHA-256 checkpoint to authenticate provenance without carrying ancestor transactions in the witness. Bind the expected verification key and policy to the verifier that the transaction actually spends. |
| Payer-created verifier outputs must enforce the same rules | Authenticate the actual verifier funding output and its complete lock. The verifier and its funding are a large part of the measured cost even when the Groth16 proof is short. |
| A recipient needs to spend as well as verify | Handle one-input payments and single-coin operations. Keep confirmation, freeze state, spend status, and reorg recovery distinct in the wallet. |
| Reproducing a proof requires matching artifacts | Keep the circuit, witness assignments, public inputs, and verification key tied to the same setup. Measure Metal and host curve operations independently when profiling. |

## Current progress

| Evidence | Scope |
| --- | --- |
| **Two-Slot Lifecycle** | Independent BSV Node 1.2.3 regtest and a local Anvil reserve confirmed three mints, two successive transfers with different parents, freeze and unfreeze, partial burn, and final burn. Both redemptions settled. The reserve and outstanding BSV supply ended at **225** fixture units each. |
| **Receiver verification and size** | All nine recorded BSV actions can be replayed from the stored headers, transactions, and Merkle branches. Bob re-spent a verified receipt. Two successive transfers in the same shape showed **0 B** of history growth. Settlement was **212,506 B** per action. An ordinary transfer used **673,539 B** including verifier and companion funding. |
| **Python Groth16 proving** | The prover consumes standard BLS12-381 `.zkey` and `.wtns` inputs, runs number-theoretic transforms on Metal, and uses arkworks for curve operations. Standard-parameter component runs include a split and a real token parent checkpoint. The nine lifecycle witness assignments were also checked in Python. |
| **Where verification stops today** | The recorded full lifecycle used its original test parameters. The standard Python lifecycle still needs a matching `2^24` parameter setup and fresh node inclusion. Ordinary transfers in the tested profile require two active token inputs and two positive token outputs. Public testnet work has reached read-only preflight. |

[Lifecycle evidence and measurements](docs/two-slot-lifecycle.md) · [Python proving and parameters](docs/python-proving.md) · [Requirements and evidence walkthrough](docs/protocol-requirements-walkthrough.md)

## Roadmap

1. **Enable payment from a single received coin.** Support `1→1`, change, and single-coin freeze and redemption. Prove on regtest that an independent recipient can re-spend with only the received coin and a BSV fee input.
2. **Reproduce the complete lifecycle with standard Python proving.** Publish the pinned circuit and assignment artifacts, obtain or generate matching BLS12-381 parameters, and repeat the nine actions and negative cases on an independent node.
3. **Reduce complete payment cost and measure width.** Reduce repeated verifier funding and reconstruction bytes. Measure baseline and marginal input/output cost for small shapes, then test wider distinct-parent batches with both node and wallet acceptance.
4. **Exercise the bridge on public testnets.** Deploy a test reserve, fund the signing and BSV paths, and verify deposit, mint, burn, release, replay protection, and reconciliation under the available node policy.

## Replay the evidence

From the Script Lab root, use a Python environment with the pinned chain-gang dependency. The replay consumes the existing test transactions and runs their input verification locally.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r shared/requirements-chronicle.txt ecdsa pycryptodome
export PYTHONPATH=.:projects/spv-token:projects/spv-token/reference:projects/spv-token/recursion:projects/groth16/reference
python projects/spv-token/recursion/run_prepared_lifecycle_regtest.py \
  --out projects/spv-token/fixtures/two-slot-lifecycle-regtest --replay
```

For the fresh-proof path and its optional GPU dependencies, use the [proving guide](docs/python-proving.md). See the [recorded negative cases](fixtures/two-slot-lifecycle-regtest/summary.json) and [public testnet preflight](fixtures/two-slot-lifecycle-regtest/public-preflight.json) for the underlying evidence.
