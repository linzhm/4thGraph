# EVM test reserve

`TestUsdcReserve` holds one configured six-decimal ERC-20 for one BSV bridge asset. Its constructor fixes the EVM chain ID, bridge reserve domain, BSV network, BSV asset ID, and reserve token address. Configure the Base Sepolia candidate using its chain ID and the verified test USDC deployment. The bridge reserve domain is a separate protocol identifier.

A depositor approves the vault and calls `deposit(quantity, owner)` with an integer in USDC base units and a 33-byte compressed secp256k1 key for the BSV owner. The vault verifies the public key and the exact token credit before emitting the deposit. Deposit v1 charges zero fee.

`reserve_rpc.py` reads the receipt from a configured trusted EVM RPC. It checks the chain ID, receipt success, block canonicality, transaction position, finalized checkpoint and specified receipt-local log. The adapter validates the emitting reserve, ERC-20 and BSV asset identities, domains, owner and quantity. The BSV mint callback in `mint_adapter.py` converts the result to the canonical mint payload. The mint event identity uses chain, reserve domain, vault, EVM transaction hash and the zero-based offset in the receipt's full logs array. The block-level RPC `logIndex` and the vault's monotonically increasing nonce are available for diagnostics. The tests exercise a receipt with a token Transfer event before the Deposit event.

A reorg before finality leaves the observer without a signable event. The RPC remains the adapter's trust root. A post-mint deep reorg requires pausing and reconciling outstanding cross-chain obligations. Use an endpoint that accurately implements the `finalized` tag.

## Release contract

The release authority signs the [EIP-712](https://eips.ethereum.org/EIPS/eip-712) `Redemption` struct declared in the contract. Its EIP-712 domain uses name `BSV USDC Test Reserve`, version `1`, the EVM chain ID and the vault address. The struct binds the BSV network, source burn txid and vout, observed BSV block hash, BSV asset ID, destination reserve domain, recipient, gross quantity, fee and active signer epoch. Use the 32-byte BSV wire order for both hashes. Amounts are USDC base units. The signature is 65 bytes in `r || s || v` form, with low S and V equal to 27 or 28.

The signer must validate the canonical BSV burn transaction, verified token provenance and required BSV confirmations before attesting. The vault checks that signature and immutable scope. Anyone can relay the signed request. One payment per BSV network, burn txid and burn vout is enforced even if the same event is signed again with a new block observation or signer epoch. Query `settled(burnId)` and the corresponding `Release` event to recover the outcome after a duplicate submission or service restart. A reverted payout rolls back both the token movements and the settlement record, so the original attestation can be retried under the same signer epoch.

The vault pays the signed fee to the configured fee recipient and reduces the tracked net reserve by the full burn quantity. Unsolicited ERC-20 transfers do not increase its tracked reserve. The emergency guardian can independently halt deposits or releases. The administrator can resume each operation, rotate or revoke the signer or guardian, and transfer administration in two steps. Each signer change invalidates authorizations from earlier epochs. BSV minting also requires its own issuance controls. Maintain one canonical vault for this asset. A future vault migration must preserve settlement history or use an explicit cutover in the signed claim scope.

## Outbound adapter

The BSV evidence reader accepts a burn reference containing the BSV wire-order txid and block hash, block height, and exact burn output index. It pins the trusted BSV RPC to the configured node chain and genesis hash, checks active-chain inclusion of the transaction and the configured confirmation depth, recomputes the txid from raw bytes, and decodes the specified burn output. The source is rechecked around signing and when resuming a request. A stale block reference fails and needs a fresh observation and provenance validation.

Pass a provenance verifier to `authorize_release` that checks the observed transaction, designated burn output, and authenticated token history under the specific asset policy. The adapter supplies the full canonical transaction to that verifier. The external signer receives the independently computed typed digest only after the verifier accepts. The adapter checks that the returned signature recovers the vault's configured release authority in the current epoch, then builds release calldata for a separate relayer.

`read_settlement` recovers the original digest from block-pinned EVM state. It reports whether the payment is still pending finality or finalized. The endpoint must support `eth_call` with a canonical block hash under [EIP-1898](https://eips.ethereum.org/EIPS/eip-1898). Persist the original `ReleaseAuthorization` to retry the same signature after an unsuccessful broadcast. Pass it back as `resume` to recheck provenance, source-chain inclusion, signer epoch and settlement before obtaining calldata again. If the EVM settlement remains after a source-chain reorg, pause release and reconcile using the recorded digest and the original authorization.

## Local verification

Run from the repository root with Foundry and the CCTP Python environment available. The verification used Foundry 1.10.0 and Solidity 0.8.28.

```sh
../cctp-test-tools/venv/bin/python -m pip install -r projects/spv-token/evm/requirements.txt
forge test --root projects/spv-token/evm -vv
PYTHONPATH=.:projects/spv-token:projects/spv-token/reference ../cctp-test-tools/venv/bin/python -m unittest -v \
  evm.test_reserve_rpc evm.test_reserve_anvil \
  evm.test_release_adapter
```

The Solidity tests check replay after re-signing, role and epoch changes, chain/vault/asset/recipient scoping, pause, and atomic retry after the fee transfer fails. The receipt tests exercise stale or invalid chain evidence. The Anvil test uses real local EVM receipts for deposit of 1,024 and release of 640, leaving 384 both in the vault and in tracked reserve. The Anvil release uses a synthetic BSV attestation to test the EVM boundary. Full BSV provenance, reorg reconciliation and public Base Sepolia deployment remain separate acceptance work.

The outbound Anvil test compares Python's digest to Solidity's digest, spends using Python-generated calldata and recovers the digest at pending and finalized heights. It uses synthetic BSV evidence. The optional BSV Node evidence test mines a deliberately unproven receipt, checks that the bridge still refuses to sign, then replaces the containing block to exercise stale-reference rejection. Run it only against a disposable BSV regtest with `txindex` enabled because it mines blocks and calls `invalidateblock`.

```sh
CCTP_RELEASE_BSV_RPC=http://127.0.0.1:19446 \
CCTP_RELEASE_BSV_COOKIE=/path/to/disposable/regtest/.cookie \
PYTHONPATH=.:projects/spv-token:projects/spv-token/reference:projects/groth16/reference \
  ../cctp-test-tools/venv/bin/python -m unittest -v evm.test_bsv_burn_evidence_regtest
```
