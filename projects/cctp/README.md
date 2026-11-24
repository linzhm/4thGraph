# CCTP and BSV stablecoin bridge

This project specifies a BSV token backed by source-chain USDC. The initial test flow uses CCTP on supported networks and a separate BSV bridge with test reserves and attestations. A production xReserve connection depends on Circle confirming the BSV domain, interfaces and operating responsibilities.

## Specification and implementation

- [Development plan and acceptance milestones](docs/development-plan.md)
- [Transfer commitment reference profile](docs/transfer-commitment.md)

- [Bridge and token protocol specification](docs/bsv-usdc-bridge-spec.md)
- [Implementation checklist and evidence](docs/bsv-usdc-token-checklist.md)
- [Issuer freeze, pause and unfreeze](docs/issuer-freeze.md)
- [Burn, redemption and release](docs/burn-redemption.md)

The first acceptance scenario is test USDC deposit, one mint of 1,024 units, split into 640 and 384, freeze and unfreeze, merge, burn, and one release on the source chain. Cases must record which layer validates each transition.

The existing [Groth16 project](../groth16/README.md) supplies the general verifier, transaction binding, MIMO constraints and local issuance fixture. The bridge will reuse those components. The current [1,024-unit runner](../groth16/docs/regtest.md) exercises local transactions with arithmetic proofs. The cross-chain adapters and issuer paths are implementation items in this project.
