# BSV SPV Token

This project develops a BSV token protocol with verifiable provenance, conservation, and independent SPV payment verification. Its first bridge application issues BSV tokens backed by source-chain USDC. The initial test flow uses CCTP on supported networks and a separate BSV bridge with test reserves and attestations. A production xReserve connection depends on Circle confirming the BSV domain, interfaces and operating responsibilities.

## Specification and implementation

- [Development plan and acceptance milestones](docs/development-plan.md)
- [Development handoff](docs/handoff.md)
- [Transfer commitment reference profile](docs/transfer-commitment.md)
- [Actual transaction relation and acceptance boundary](docs/actual-transaction-relation.md)
- [Independent parent binding and dual verifier sighashes](docs/parent-binding.md)
- [Capacity acceptance](docs/capacity.md)
- [v2 token lifecycle and node results](docs/v2-lifecycle.md)
- [Mint covenant and cross-chain adapter](docs/mint.md)
- [Base Sepolia source-chain candidate](docs/base-sepolia-plan.md)

- [Bridge and token protocol specification](docs/bsv-usdc-bridge-spec.md)
- [Implementation checklist and evidence](docs/bsv-usdc-token-checklist.md)
- [Issuer freeze, pause and unfreeze](docs/issuer-freeze.md)
- [Burn, redemption and release](docs/burn-redemption.md)

The first acceptance scenario is test USDC deposit, one mint of 1,024 units, split into 640 and 384, freeze and unfreeze, merge, burn, and one release on the source chain. Cases must record which layer validates each transition.

The existing [Groth16 project](../groth16/README.md) supplies the general verifier, transaction binding, MIMO constraints and local issuance fixture. The bridge will reuse those components. The current [1,024-unit runner](../groth16/docs/regtest.md) exercises local transactions with arithmetic proofs. The cross-chain adapters and issuer paths are implementation items in this project.

## Local regression

Run from the Script Lab root using the project Python environment with the pinned chain-gang dependency. Node-backed tests enable their isolated regtest settings separately.

```sh
export PYTHONPATH=.:projects/spv-token:projects/spv-token/reference:projects/spv-token/recursion:projects/groth16/reference
../cctp-test-tools/venv/bin/python -m unittest discover -s projects/spv-token/reference -v
../cctp-test-tools/venv/bin/python -m unittest discover -s projects/spv-token/recursion -v
../cctp-test-tools/venv/bin/python -m unittest discover -s projects/spv-token/evm -v
```
