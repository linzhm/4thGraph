"""Host evidence checks for certified burns using a simulated Node RPC.

These tests exercise exact transaction and verifier binding. The fixture proof
bytes do not stand in for actual Script execution or node acceptance.
"""

from dataclasses import replace
from importlib.util import find_spec
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from bridge_ledger import BridgeLedger
from bridge_service import BridgeService
from burn_receipt import BurnReceipt
from certified_burn_provenance import CertifiedBurnProvenance
from mint import MintPolicy, authorize_mint, prepare_mint
from mint_events import Deposit, DepositPosition, EMPTY_ROOT, MintEvents
from operational_token import ordinary_witness
from projects.cctp.evm import test_release_adapter as release_fixture
from projects.cctp.evm.bsv_burn_evidence import (
    BsvConfirmationPolicy, BsvTransactionLocation, BurnEvidenceError, BurnReference, read_confirmed_burn,
)
from projects.cctp.evm.release_adapter import ReleaseAuthorization, burn_event_id
from shared.script import asm
from shared.transaction import Input, Output, Transaction
from test_operational_token import fixture_signer


class FixtureNode:
    def __init__(self, transactions):
        self.hashes = {height: bytes([height + 1]) * 32 for height in range(21)}
        self.transactions = {}
        self.locations = {}
        self.blocks = {height: [] for height in self.hashes}
        self.subversion = "/Bitcoin SV:1.2.3/"
        self.raw_reads = []
        for height, transaction in transactions:
            self.include(height, transaction)

    def include(self, height, tx):
        txid = tx.txid_wire()
        self.transactions[txid] = tx.serialize().hex()
        self.locations[txid] = BsvTransactionLocation(self.hashes[height], height)
        self.blocks[height].append(txid)

    def reference(self, tx, vout=0):
        txid = tx.txid_wire()
        location = self.locations[txid]
        return BurnReference(txid, vout, location.block_hash, location.height)

    def __call__(self, method, *args):
        if method == "getnetworkinfo":
            return {"subversion": self.subversion}
        if method == "getblockchaininfo":
            return {"chain": "regtest", "blocks": 20, "bestblockhash": self.hashes[20][::-1].hex()}
        if method == "getblockhash":
            return self.hashes[args[0]][::-1].hex()
        if method == "getblock":
            block_hash, verbosity = args
            assert verbosity == 1
            height, = [h for h, digest in self.hashes.items() if digest[::-1].hex() == block_hash]
            return {"height": height, "hash": block_hash, "tx": [item[::-1].hex() for item in self.blocks[height]]}
        if method == "getrawtransaction":
            txid, verbose = args
            assert verbose is False
            key = bytes.fromhex(txid)[::-1]
            self.raw_reads.append(key)
            return self.transactions[key]
        raise AssertionError(f"unexpected BSV RPC method {method}")


@unittest.skipUnless(find_spec("continuity_verifier"), "requires the CCTP recursion reference path")
class CertifiedBurnProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from committed_verifier import load_artifact
        from continuity_statement import ParentReceipt
        from continuity_verifier import ContinuityVerifier

        artifact = Path(__file__).resolve().parents[1] / "recursion/testdata/bsb22-proof.json"
        key, commitment, _, cls.proof = load_artifact(json.loads(artifact.read_text()))
        evm = release_fixture.ReleaseAdapterTest()
        evm.setUp()
        cls.asset = evm.asset
        issuer, sign_mint = fixture_signer(13)
        freeze, _ = fixture_signer(12)
        owner, sign_owner = fixture_signer(11)
        cls.owner = owner
        template = MintPolicy(cls.asset, evm.scope.chain_id, evm.scope.vault, issuer, lambda _: b"")
        cls.verifier = ContinuityVerifier(template, freeze, key, commitment, b"k" * 32,
                                         certified_mints=True, certified_admin=True, certified_burns=True)
        cls.mint_policy = cls.verifier.mint_policy
        outpoint = cls.asset.issuance_outpoint
        issuance = Input(outpoint[:32], int.from_bytes(outpoint[32:], "little"))
        genesis = Transaction((issuance,), (Output(50_000, cls.mint_policy.state_lock(EMPTY_ROOT)),))

        def funding(index):
            return Transaction((Input(bytes([index]) * 32, 0),), (Output(100_000, cls.verifier.lock),))

        cls.mint_funding, cls.burn_funding, cls.full_funding = (funding(i) for i in (1, 2, 3))
        deposit = Deposit(DepositPosition(evm.scope.chain_id, cls.asset.reserve_domain, evm.scope.vault,
                                           b"u" * 32, 0),
                          cls.asset.reserve_asset, cls.asset.network, cls.asset.asset_id(), 1024, 0, owner)
        plan = prepare_mint(cls.mint_policy, genesis, MintEvents(), deposit, Input(cls.mint_funding.txid_wire(), 0),
                            receipt=ParentReceipt(()), verifier_parent=cls.mint_funding)
        mint = authorize_mint(plan, lambda _: deposit, sign_mint)
        cls.mint = mint.with_script(1, cls.verifier.mint_witness(cls.proof, mint, cls.mint_funding, genesis))

        def burn(funder, parent, support, vout, quantity, change=None):
            redemption = BurnReceipt(cls.asset.asset_id(), cls.asset.reserve_domain, b"r" * 20, quantity, 5)
            receipt = ParentReceipt((cls.verifier.proof_digest(parent, support),))
            change_outputs = () if change is None else (cls.mint_policy.token_output(change, owner),)
            tx = Transaction((Input(funder.txid_wire(), 0), Input(parent.txid_wire(), vout)),
                             (redemption.output(), *change_outputs, receipt.output()))
            proof = cls.verifier.burn_witness(cls.proof, tx, funder, (parent,), (support,))
            holder = ordinary_witness(tx, 1, parent, cls.verifier.policy, funder, sign_owner)
            return tx.with_script(0, proof).with_script(1, holder), redemption

        cls.partial, cls.redemption = burn(cls.burn_funding, cls.mint, cls.mint_funding, 1, 640, 384)
        cls.full, cls.full_redemption = burn(cls.full_funding, cls.partial, cls.burn_funding, 1, 384)
        cls.transactions = ((1, cls.mint_funding), (2, cls.burn_funding), (3, cls.full_funding),
                            (4, genesis), (6, cls.mint), (9, cls.partial), (12, cls.full))

    def setUp(self):
        self.node = FixtureNode(self.transactions)
        self.policy = BsvConfirmationPolicy(self.asset.network, "regtest", self.node.hashes[0], 2)
        self.provenance = CertifiedBurnProvenance(self.verifier, self.node.locations.get)

    def check(self, tx, vout=0):
        reference = self.node.reference(tx, vout)
        evidence = read_confirmed_burn(self.node, self.policy, reference, self.asset)
        return self.provenance.verify(evidence, self.node, self.policy)

    def test_exact_certified_witness_context_and_full_burn_of_verified_change(self):
        result = self.check(self.partial)
        self.assertEqual(result.receipt, self.redemption)
        self.assertEqual(result.verifier_outpoint, self.partial.inputs[0].outpoint())
        self.assertEqual(result.verifier_hash, self.mint_policy.certified_verifier_hash)
        self.assertEqual(result.proof_digest, self.verifier.proof_digest(self.partial, self.burn_funding))
        result = self.check(self.full)
        self.assertEqual(result.receipt, self.full_redemption)
        self.assertEqual(result.proof_digest, self.verifier.proof_digest(self.full, self.full_funding))

    def test_rejects_wrong_vout_altered_context_or_nonburn_layout(self):
        reference = self.node.reference(self.partial)
        evidence = read_confirmed_burn(self.node, self.policy, reference, self.asset)
        with self.assertRaisesRegex(BurnEvidenceError, "wrong certified burn transaction or vout"):
            self.provenance.verify(replace(evidence, reference=replace(reference, vout=1)), self.node, self.policy)

        old_witness = self.partial.inputs[0].script
        changed = replace(self.partial, outputs=(replace(self.redemption, recipient=b"x" * 20).output(),
                                                *self.partial.outputs[1:]))
        self.assertEqual(changed.inputs[0].script, old_witness)
        self.node.include(15, changed)
        with self.assertRaisesRegex(BurnEvidenceError, "does not attest"):
            self.check(changed)

        extra_output = replace(self.partial, outputs=(*self.partial.outputs, self.redemption.output()))
        self.node.include(16, extra_output)
        with self.assertRaisesRegex(BurnEvidenceError, "unexpected certified burn"):
            self.check(extra_output)

    def test_rejects_unrelated_verifier_and_fake_full_node(self):
        rogue_funding = replace(self.burn_funding, outputs=(Output(100_000, asm("OP_1")),))
        self.node.include(7, rogue_funding)
        rogue = replace(self.partial, inputs=(replace(self.partial.inputs[0], txid=rogue_funding.txid_wire()),
                                              self.partial.inputs[1]))
        self.node.include(10, rogue)
        with self.assertRaisesRegex(ValueError, "invalid verifier parent"):
            self.check(rogue)
        self.node.subversion = "/Fake indexer/"
        with self.assertRaisesRegex(BurnEvidenceError, "independent Bitcoin SV"):
            self.check(self.partial)

    def test_rejects_stale_or_changed_predecessor_at_same_outpoint(self):
        original = self.node.hashes[6]
        self.node.hashes[6] = b"x" * 32
        with self.assertRaisesRegex(BurnEvidenceError, "not on the adopted chain"):
            self.check(self.partial)
        self.node.hashes[6] = original
        self.node.transactions[self.mint.txid_wire()] = replace(self.mint, locktime=1).serialize().hex()
        with self.assertRaisesRegex(BurnEvidenceError, "different hash"):
            self.check(self.partial)

    def test_refuses_missing_or_late_parent_occurrence_even_if_raw_is_available(self):
        parent = self.mint.txid_wire()
        location = self.node.locations[parent]
        self.node.locations[parent] = BsvTransactionLocation(self.node.hashes[8], 8)
        with self.assertRaisesRegex(BurnEvidenceError, "absent from its claimed occurrence block"):
            self.check(self.partial)
        self.node.locations[parent] = BsvTransactionLocation(self.node.hashes[9], 9)
        self.node.blocks[9].append(parent)
        with self.assertRaisesRegex(BurnEvidenceError, "does not precede its spend"):
            self.check(self.partial)
        self.node.locations[parent] = location
        del self.node.locations[self.mint_funding.txid_wire()]
        with self.assertRaisesRegex(BurnEvidenceError, "missing confirmed BSV predecessor"):
            self.check(self.partial)

    def test_service_uses_certified_adapter_without_legacy_fallback(self):
        evm = release_fixture.ReleaseAdapterTest()
        evm.setUp()
        evm.reference = self.node.reference(self.partial)
        claimed_burn = self.redemption

        class LegacyBypass:
            mint_policy = self.mint_policy

            def burn(self, *_):
                return claimed_burn

        with TemporaryDirectory() as temp:
            ledger = BridgeLedger(Path(temp) / "bridge.sqlite3", self.asset, evm.scope.chain_id, evm.scope.vault)
            service = BridgeService(ledger, self.mint_policy, evm.scope, evm.evm_rpc)
            event = burn_event_id(self.asset.network, evm.reference)
            with self.assertRaisesRegex(ValueError, "configured certified or legacy"):
                service.authorize_release(self.node, self.policy, evm.reference, LegacyBypass(), evm.signer_callback)
            self.assertIsNone(ledger.state(event))
            self.assertEqual(evm.signer_calls, [])

            result = service.authorize_release(self.node, self.policy, evm.reference, self.provenance, evm.signer_callback)
            self.assertIsInstance(result, ReleaseAuthorization)
            self.assertEqual(result.claim.quantity, 640)
            self.assertEqual(result.claim.fee, 5)
            self.assertEqual(ledger.state(event).authorization, result.digest)
            self.assertEqual(len(evm.signer_calls), 1)


if __name__ == "__main__":
    unittest.main()
