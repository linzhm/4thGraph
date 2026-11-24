# Public testnet preparation

This entry point checks Base Sepolia and a separately configured Bitcoin SV testnet node. It builds a review draft for the independent test reserve, checks an externally signed deployment offline, and reads finalized public-chain receipts. Public lifecycle acceptance stays gated on recursive provenance and transaction binding being integrated and exercised with funded, authorized signers and a confirmed BSV broadcast policy. The CLI makes read-only RPC calls and never manages keys or broadcasts.

Base Sepolia uses chain ID 84532 and Circle test USDC at `0x036CbD53842c5426634e7929541eC2318f3dCF7e`. Base ETH pays for gas. Circle's Base Sepolia faucet is separate from ETH funding. BSV requires a synchronized Chronicle-capable Bitcoin SV node with transaction indexing, an authenticated loopback RPC, and test BSV for the issuance anchor and fee sponsors. [Base endpoints](https://docs.base.org/get-started/connect-to-base) · [Base funds](https://docs.base.org/get-started/get-funds) · [Circle test USDC contracts](https://developers.circle.com/stablecoins/usdc-contract-addresses) · [BSV testnet setup](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/installation/sv-node/network-environments/testnet)

The 2026-11-24 read-only probe found that the Base public RPC served `latest` and `finalized`, Circle's deployed token code and six-decimal query pinned to a canonical block hash. The BSV explorer returned public testnet height 1,770,804 and identified the block at Chronicle activation height 1,713,168. An authorized BSV Node RPC is still needed to check the active chain, wallet outputs and transaction ancestry. [Chronicle activation](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release) · [Activation block lookup](https://api.whatsonchain.com/v1/bsv/test/block/height/1713168)

From the repository root, install the EVM Python dependencies alongside the CCTP reference tests and compile the reviewed contract.

```sh
../cctp-test-tools/venv/bin/python -m pip install -r projects/cctp/evm/requirements.txt
forge build --root projects/cctp/evm
export PYTHONPATH=.:projects/cctp/reference
../cctp-test-tools/venv/bin/python -m projects.cctp.evm.public_testnet preflight
```

For a funded preflight, provide an operator-owned JSON request with public addresses and a BSV issuance anchor. The suggested bridge identifiers below are distinct from the current local fixtures and Circle's domain numbering. Use the same values in the finalized BSV asset configuration. Hashes use display order in the request and the script converts the BSV outpoint to wire order.

```json
{
  "deployer": "<20-byte 0x-prefixed Base address>",
  "nonce": 0,
  "admin": "<20-byte 0x-prefixed Base address>",
  "pause_guardian": "<separate 20-byte 0x-prefixed Base address>",
  "release_signer": "<separate 20-byte 0x-prefixed Base address>",
  "fee_recipient": "<20-byte 0x-prefixed Base address>",
  "depositor": "<20-byte 0x-prefixed Base address>",
  "relayer": "<20-byte 0x-prefixed Base address>",
  "bsv_testnet_txid": "<32-byte 0x-prefixed BSV issuance txid in display order>",
  "bsv_testnet_vout": 0,
  "bsv_network": 2,
  "reserve_domain": 84532,
  "policy_id": "<32-byte 0x-prefixed asset policy identifier>"
}
```

Set `CCTP_BASE_SEPOLIA_RPC` only if using a different Base provider with finalized and canonical-block state queries. Set `CCTP_BSV_TESTNET_COOKIE` to the local Bitcoin SV testnet RPC cookie file path and pass `--bsv-rpc-port` if it differs from 18332. The preflight checks the deployer nonce, ETH/USDC balances, BSV chain checkpoint, and an unspent issuance anchor. The optional deployment estimate covers L2 execution gas, with Base L1 data fees and future transactions requiring additional funds. Address balances alone cannot establish control of the signers.

```sh
../cctp-test-tools/venv/bin/python -m projects.cctp.evm.public_testnet preflight \
  --request /path/to/review.json --estimate-deploy
../cctp-test-tools/venv/bin/python -m projects.cctp.evm.public_testnet plan-deployment \
  /path/to/review.json > /path/to/unsigned-review.json
```

The draft commits the deployer, nonce, chain, initcode, constructor scope, artifact digest and predicted address. After the public gates are satisfied, an external signer can produce an EIP-1559 envelope using operator-reviewed gas and fee caps. Keep the signed envelope in a private local file. Review its recovered signer, destination, chain, nonce, exact initcode and L2 fee cap before the operator submits it.

```sh
../cctp-test-tools/venv/bin/python -m projects.cctp.evm.public_testnet verify-signed-deployment \
  /path/to/review.json /private/path/to/signed-transaction.hex
```

For an independently submitted deployment, verify the canonical finalized receipt, transaction position, compiled runtime and configured reserve roles. Then verify an actual deposit with the receipt-local log ordinal and intended BSV owner. For an already executed release, pair the finalized EVM settlement digest with the exact confirmed BSV receipt and signer epoch. Paired settlement checks establish receipt correspondence. Recursive proof acceptance remains independently required.

```sh
../cctp-test-tools/venv/bin/python -m projects.cctp.evm.public_testnet verify-deployment \
  /path/to/review.json <0x-deployment-txid>
../cctp-test-tools/venv/bin/python -m projects.cctp.evm.public_testnet verify-deposit \
  /path/to/review.json <0x-deployment-txid> <0x-deposit-txid> <receipt-log-ordinal> \
  --expected-owner <0x-compressed-BSV-public-key> --expected-quantity 1024
../cctp-test-tools/venv/bin/python -m projects.cctp.evm.public_testnet verify-paired-settlement \
  /path/to/review.json <0x-deployment-txid> <BSV-burn-txid> <burn-vout> \
  <BSV-burn-block-hash> <BSV-burn-height> <signer-epoch> --bsv-confirmations 2
```

Verification is tied to the reviewed roles. A vault that has since rotated those roles will require a separate deployment and authority history review. Evaluate funded anchor control, peer relay and miner limits for the final serialized BSV transactions before a public lifecycle run.

The test suite uses disposable loopback Anvil with the Base chain number and a mock token at the Circle address. It exercises a real signed envelope, local publication, finalized deployment and deposit receipts, asset and role mismatch, BSV test chain/anchor scope and paired settlement digest checks.

```sh
PYTHONPATH=.:projects/cctp/reference ../cctp-test-tools/venv/bin/python -m unittest -v \
  projects.cctp.evm.test_public_testnet
```
