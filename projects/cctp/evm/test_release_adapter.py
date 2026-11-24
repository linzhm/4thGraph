from dataclasses import replace
from hashlib import sha256
import subprocess
import unittest

from ecdsa import SECP256k1, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_string, sigencode_string_canonize

from burn_receipt import BurnReceipt
from shared.transaction import Input, Output, Transaction
from statement import AssetDescriptor

from projects.cctp.evm.anvil_fixture import CHAIN_ID, HAS_FOUNDRY, start_anvil
from projects.cctp.evm.bsv_burn_evidence import BsvConfirmationPolicy, BurnEvidenceError, BurnReference
from projects.cctp.evm.release_adapter import (
    ReleaseAuthorization, ReleaseEvidenceError, _hash, authorize_release, burn_event_id, read_settlement,
)
from projects.cctp.evm.reserve_rpc import ReserveScope


def word(n):
    return n.to_bytes(32, "big")


def hx(value):
    return "0x" + value.hex()


def fixture_signer():
    # Public local test key.
    return SigningKey.from_secret_exponent(0xC0FFEE, curve=SECP256k1)


def sign(digest, signer):
    signature = signer.sign_digest_deterministic(digest, hashfunc=sha256, sigencode=sigencode_string_canonize)
    matches = VerifyingKey.from_public_key_recovery_with_digest(
        signature, digest, curve=SECP256k1, sigdecode=sigdecode_string,
    )
    recovery_id = matches.index(signer.verifying_key)
    return signature + bytes([27 + recovery_id])


class ReleaseAdapterTest(unittest.TestCase):
    def setUp(self):
        self.asset = AssetDescriptor(1, b"i" * 36, 6, 7, bytes(12) + b"u" * 20, b"p" * 32)
        self.scope = ReserveScope(84532, 7, 1, b"v" * 20, b"u" * 20, self.asset.asset_id())
        self._reset_burn(b"r" * 20)
        self.policy = BsvConfirmationPolicy(self.asset.network, "regtest", b"g" * 32, 6)
        self.rpc_chain = "regtest"
        self.rpc_genesis = self.policy.genesis_hash
        self.active_hash = self.reference.block_hash
        self.tip_height = 125
        self.tip_hash = b"b" * 32
        self.active_tip_hash = self.tip_hash
        self.signer = fixture_signer()
        self.known_signer = _hash(self.signer.verifying_key.to_string())[-20:]
        self.epoch = 1
        self.paused = False
        self.authenticated = True
        self.provenance_calls = []
        self.signer_calls = []
        self.latest_digest = None
        self.finalized_digest = None
        self.returned_token = self.scope.reserve_asset

    def _reset_burn(self, recipient):
        self.burn = BurnReceipt(self.asset.asset_id(), self.asset.reserve_domain, recipient, 640, 5)
        self.tx = Transaction((Input(b"s" * 32, 0),), (Output(1, b"\x51"), self.burn.output()))
        self.reference = BurnReference(self.tx.txid_wire(), 1, bytes(range(32)), 120)
        self.block_transactions = [self.tx.txid()]
        self.raw_tx = self.tx.serialize().hex()

    def bsv_rpc(self, method, *params):
        if method == "getblockchaininfo":
            return {"chain": self.rpc_chain, "blocks": self.tip_height, "bestblockhash": self.tip_hash[::-1].hex()}
        if method == "getblockhash":
            height, = params
            if height == 0:
                return self.rpc_genesis[::-1].hex()
            if height == self.reference.block_height:
                return self.active_hash[::-1].hex()
            self.assertEqual(height, self.tip_height)
            return self.active_tip_hash[::-1].hex()
        if method == "getblock":
            self.assertEqual(params, (self.reference.block_hash[::-1].hex(), 1))
            return {"hash": params[0], "height": self.reference.block_height, "tx": self.block_transactions}
        if method == "getrawtransaction":
            self.assertEqual(params, (self.tx.txid(), False))
            return self.raw_tx
        self.fail(f"unexpected BSV RPC {method}")

    def evm_rpc(self, method, *params):
        if method == "eth_chainId":
            return hex(self.scope.chain_id)
        if method == "eth_getBlockByNumber":
            name, full = params
            self.assertFalse(full)
            if name == "latest":
                return {"number": "0xa", "hash": hx(b"l" * 32)}
            if name == "finalized":
                return {"number": "0x1", "hash": hx(b"f" * 32)}
        if method == "eth_call":
            request, block = params
            self.assertEqual(request["to"], hx(self.scope.vault))
            self.assertTrue(block["requireCanonical"])
            self.assertIn(block["blockHash"], (hx(b"l" * 32), hx(b"f" * 32)))
            digest = self.latest_digest if block["blockHash"] == hx(b"l" * 32) else self.finalized_digest
            selectors = (
                (b"settled(bytes32)", word(int(digest is not None))),
                (b"settledDigest(bytes32)", digest),
                (b"deploymentChainId()", word(self.scope.chain_id)),
                (b"assetId()", self.scope.asset_id),
                (b"reserveDomain()", word(self.scope.reserve_domain)),
                (b"bsvNetwork()", word(self.scope.bsv_network)),
                (b"token()", bytes(12) + self.returned_token),
                (b"releasesPaused()", word(int(self.paused))),
                (b"signerEpoch()", word(self.epoch)),
                (b"releaseSigner()", bytes(12) + self.known_signer),
            )
            for name, response in selectors:
                if request["data"].startswith(hx(_hash(name)[:4])):
                    if name in (b"settled(bytes32)", b"settledDigest(bytes32)"):
                        self.assertEqual(request["data"][10:], burn_event_id(self.asset.network, self.reference).hex())
                    return hx(response)
        self.fail(f"unexpected EVM RPC {method}")

    def verify(self, evidence, asset):
        self.provenance_calls.append(evidence)
        self.assertEqual(evidence.transaction, self.tx)
        self.assertEqual(evidence.receipt, self.burn)
        self.assertEqual(evidence.confirmations, 6)
        self.assertEqual(asset, self.asset)
        return self.authenticated

    def signer_callback(self, digest):
        self.signer_calls.append(digest)
        return sign(digest, self.signer)

    def authorize(self, **changes):
        params = dict(
            bsv_rpc=self.bsv_rpc, evm_rpc=self.evm_rpc, policy=self.policy, scope=self.scope, asset=self.asset,
            reference=self.reference, verify_provenance=self.verify, sign_digest=self.signer_callback,
        )
        return authorize_release(**(params | changes))

    def test_authenticates_canonical_burn_and_resumes_same_signature(self):
        result = self.authorize()
        self.assertIsInstance(result, ReleaseAuthorization)
        self.assertEqual(result.claim.burn_txid, self.tx.txid_wire())
        self.assertEqual(result.claim.burn_block_hash, self.reference.block_hash)
        self.assertEqual(result.claim.burn_vout, 1)
        self.assertEqual(result.claim.recipient, self.burn.recipient)
        self.assertEqual(result.claim.quantity, 640)
        self.assertEqual(result.claim.fee, 5)
        self.assertEqual(result.claim.signer_epoch, 1)
        self.assertEqual(result.digest, result.claim.digest(self.scope))
        self.assertEqual(result.calldata()[324:356], word(352))
        self.assertEqual(result.calldata()[356:388], word(65))
        self.assertEqual(result.calldata()[388:453], result.signature)

        resumed = self.authorize(resume=result)
        self.assertEqual(resumed, result)
        self.assertEqual(len(self.provenance_calls), 2)
        self.assertEqual(self.signer_calls, [result.digest])

    def test_already_settled_recovers_pending_and_finalized_digest(self):
        original = self.authorize()
        self.latest_digest = original.digest
        pending = self.authorize(resume=original)
        self.assertFalse(pending.finalized)
        self.assertEqual(pending.digest, original.digest)
        self.finalized_digest = self.latest_digest
        self.assertTrue(read_settlement(self.evm_rpc, self.scope, self.reference).finalized)
        self.assertEqual(self.authorize(resume=original).digest, original.digest)
        self.assertEqual(self.signer_calls, [original.digest])
        self.active_hash = b"r" * 32
        with self.assertRaisesRegex(BurnEvidenceError, "active BSV chain"):
            self.authorize(resume=original)
        self.assertTrue(read_settlement(self.evm_rpc, self.scope, self.reference).finalized)

    def test_refuses_inconsistent_evm_finality(self):
        self.finalized_digest = b"f" * 32
        with self.assertRaisesRegex(ReleaseEvidenceError, "differs from current settlement"):
            self.authorize()
        self.assertEqual(self.signer_calls, [])

    def test_refuses_confirmed_unproven_burn(self):
        self.authenticated = False
        with self.assertRaisesRegex(ReleaseEvidenceError, "provenance was not authenticated"):
            self.authorize()
        self.assertEqual(len(self.provenance_calls), 1)
        self.assertEqual(self.signer_calls, [])

    def test_refuses_stale_or_unconfirmed_bsv_references(self):
        self.tip_height = 124
        with self.assertRaisesRegex(BurnEvidenceError, "confirmation policy"):
            self.authorize()
        self.tip_height = 125
        self.active_hash = b"r" * 32
        with self.assertRaisesRegex(BurnEvidenceError, "active BSV chain"):
            self.authorize()
        self.active_hash = self.reference.block_hash
        self.active_tip_hash = b"r" * 32
        with self.assertRaisesRegex(BurnEvidenceError, "tip changed"):
            self.authorize()
        self.assertEqual(self.provenance_calls, [])
        self.assertEqual(self.signer_calls, [])

    def test_refuses_wrong_bsv_network_position_and_forged_raw_bytes(self):
        self.rpc_chain = "main"
        with self.assertRaisesRegex(BurnEvidenceError, "RPC chain"):
            self.authorize()
        self.rpc_chain = self.policy.rpc_chain
        self.rpc_genesis = b"x" * 32
        with self.assertRaisesRegex(BurnEvidenceError, "genesis hash"):
            self.authorize()
        self.rpc_genesis = self.policy.genesis_hash

        self.block_transactions = []
        with self.assertRaisesRegex(BurnEvidenceError, "absent from the BSV block"):
            self.authorize()
        self.block_transactions = [self.tx.txid()]
        with self.assertRaisesRegex(BurnEvidenceError, "invalid burn receipt"):
            self.authorize(reference=replace(self.reference, vout=0))
        self.raw_tx = replace(self.tx, locktime=4).serialize().hex()
        with self.assertRaisesRegex(BurnEvidenceError, "different hash"):
            self.authorize()
        self.assertEqual(self.signer_calls, [])

    def test_rechecks_canonical_block_after_external_signing(self):
        def reorg_while_signing(digest):
            result = self.signer_callback(digest)
            self.active_hash = b"r" * 32
            return result

        with self.assertRaisesRegex(BurnEvidenceError, "active BSV chain"):
            self.authorize(sign_digest=reorg_while_signing)

    def test_refuses_paused_reserve_and_outdated_or_wrong_signature(self):
        original = self.authorize()
        self.paused = True
        with self.assertRaisesRegex(ReleaseEvidenceError, "releases are paused"):
            self.authorize(resume=original)
        self.paused = False
        self.returned_token = b"z" * 20
        with self.assertRaisesRegex(ReleaseEvidenceError, "does not match release scope"):
            self.authorize()
        self.returned_token = self.scope.reserve_asset
        self.epoch += 1
        with self.assertRaisesRegex(ReleaseEvidenceError, "different burn, vault, or signer epoch"):
            self.authorize(resume=original)
        with self.assertRaisesRegex(ReleaseEvidenceError, "does not match the configured signer"):
            self.authorize(sign_digest=lambda digest: sign(digest, SigningKey.from_secret_exponent(7, curve=SECP256k1)))
        self.assertEqual(len(self.signer_calls), 1)


    @unittest.skipUnless(HAS_FOUNDRY, "requires Foundry")
    def test_python_authorization_and_settlement_against_live_anvil(self):
        with start_anvil() as evm:
            admin, guardian, payer, recipient, treasury = evm.accounts()[:5]
            token = evm.deploy("test/TestUsdcReserve.t.sol:MockUsdc", admin)
            self.asset = replace(self.asset, reserve_asset=bytes(12) + bytes.fromhex(token[2:]))
            self._reset_burn(bytes.fromhex(recipient[2:]))
            vault = evm.deploy(
                "src/TestUsdcReserve.sol:TestUsdcReserve", admin,
                f"({CHAIN_ID},7,1,{hx(self.asset.asset_id())},{token},{admin},{guardian},"
                f"{hx(self.known_signer)},{treasury})",
            )
            self.scope = ReserveScope(
                CHAIN_ID, 7, self.asset.network, bytes.fromhex(vault[2:]),
                bytes.fromhex(token[2:]), self.asset.asset_id(),
            )
            evm.send(token, "mint(address,uint256)", payer, "1024", sender=admin)
            evm.send(token, "approve(address,uint256)", vault, "1024", sender=payer)
            owner = "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            evm.send(vault, "deposit(uint64,bytes)", "1024", owner, sender=payer)
            evm.mine_finality()

            # Synthetic BSV RPC and test provenance. The EVM uses real transactions.
            result = self.authorize(evm_rpc=evm.rpc)
            tuple_type = "(uint32,bytes32,uint32,bytes32,bytes32,uint32,address,uint64,uint64,uint64)"
            msg = (
                f"(1,{hx(self.tx.txid_wire())},1,{hx(self.reference.block_hash)},"
                f"{hx(self.asset.asset_id())},7,{recipient},640,5,1)"
            )
            solidity_digest = evm.call(vault, f"releaseDigest({tuple_type})(bytes32)", msg)
            self.assertEqual(hx(result.digest), solidity_digest)
            subprocess.run(
                ["cast", "send", "--rpc-url", evm.url, "--from", payer, "--unlocked",
                 "--data", hx(result.calldata()), vault],
                capture_output=True, timeout=30, check=True,
            )
            pending = read_settlement(evm.rpc, self.scope, self.reference)
            self.assertEqual(pending.digest, result.digest)
            self.assertFalse(pending.finalized)
            evm.mine_finality()
            recovered = self.authorize(evm_rpc=evm.rpc, resume=result)
            self.assertEqual(recovered.digest, result.digest)
            self.assertTrue(recovered.finalized)
            self.assertEqual(len(self.signer_calls), 1)
            self.assertEqual(evm.call(vault, "netReserve()(uint256)"), "384")
            self.assertEqual(evm.call(token, "balanceOf(address)(uint256)", recipient), "635")
            self.assertEqual(evm.call(token, "balanceOf(address)(uint256)", treasury), "5")


if __name__ == "__main__":
    unittest.main()
