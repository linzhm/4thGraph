"""Exercise wallet creation evidence with a simulated full-node RPC."""

from dataclasses import replace
from decimal import Decimal
from importlib.util import find_spec
import json
from pathlib import Path
import unittest

from burn_receipt import BurnReceipt
from certified_wallet_provenance import CertifiedWalletError, CertifiedWalletProvenance
from mint import MintPolicy, authorize_mint, prepare_mint
from mint_events import Deposit, DepositPosition, EMPTY_ROOT, MintEvents
from operational_token import freeze_witness, ordinary_witness
from projects.cctp.evm.bsv_burn_evidence import BsvConfirmationPolicy, BsvTransactionLocation, BurnEvidenceError
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, hash256
from statement import AssetDescriptor
from test_certified_burn_provenance import FixtureNode
from test_operational_token import fixture_signer
from wallet_receipt import BlockInclusion, SpendStatus, verify_payment


@unittest.skipUnless(find_spec("continuity_verifier"), "requires the CCTP recursion reference path")
class CertifiedWalletFixture(unittest.TestCase):
    align_output_count = False

    @classmethod
    def setUpClass(cls):
        from committed_verifier import load_artifact
        from continuity_statement import ParentReceipt
        from continuity_verifier import ContinuityVerifier, SINGLE_OUTPUT_MARKER

        artifact = Path(__file__).resolve().parents[1] / "recursion/testdata/bsb22-proof.json"
        key, commitment, _, proof = load_artifact(json.loads(artifact.read_text()))
        issuer, sign_mint = fixture_signer(13)
        freeze, sign_admin = fixture_signer(12)
        cls.owner, sign_owner = fixture_signer(11)
        anchor = Input(b"i" * 32, 0)
        cls.asset = asset = AssetDescriptor(1, anchor.outpoint(), 6, 7, b"u" * 32, b"p" * 32)
        template = MintPolicy(asset, 31337, b"v" * 20, issuer, lambda _: b"")
        verifier = ContinuityVerifier(template, freeze, key, commitment, b"k" * 32, certified_mints=True,
                                      certified_admin=True, certified_burns=True, certified_single_output=True,
                                      align_output_count=cls.align_output_count)
        cls.verifier = verifier
        policy = verifier.policy
        mint_policy = verifier.mint_policy

        def funding(index):
            return Transaction((Input(bytes([index]) * 32, 0),), (Output(100_000, verifier.lock),))

        def state_output(quantity):
            return mint_policy.token_output(quantity, cls.owner)

        def receipt(*previous):
            return ParentReceipt(tuple(verifier.proof_digest(parent, sponsor) for parent, sponsor in previous))

        def ordinary(funder, previous, outputs, *, burn=False):
            parents = tuple(parent for parent, _, _ in previous)
            supporters = tuple(supporter for _, _, supporter in previous)
            tx = Transaction(
                (Input(funder.txid_wire(), 0), *(Input(parent.txid_wire(), vout) for parent, vout, _ in previous)),
                (*outputs, receipt(*zip(parents, supporters, strict=True)).output()),
            )
            method = verifier.burn_witness if burn else verifier.witness
            signed = tx.with_script(0, method(proof, tx, funder, parents, supporters))
            for index, parent in enumerate(parents, 1):
                signed = signed.with_script(index, ordinary_witness(tx, index, parent, policy, funder, sign_owner))
            return signed

        def toggle(parent, prior_vout, prior_funding, funder):
            previous = parent.outputs[prior_vout]
            state = policy.parse(previous.script)
            next_output = replace(previous, script=policy.lock(replace(state, frozen=not state.frozen)))
            tx = Transaction((Input(parent.txid_wire(), prior_vout), Input(funder.txid_wire(), 0)),
                             (next_output, receipt((parent, prior_funding)).output()))
            owner = freeze_witness(tx, 0, parent, policy, sign_admin, verifier_parent=funder)
            verifier_witness = verifier.admin_witness(proof, tx, funder, parent, prior_funding)
            return tx.with_script(0, owner).with_script(1, verifier_witness)

        funders = tuple(funding(i) for i in range(1, 8))
        cls.funders = funders
        genesis = Transaction((anchor,), (Output(50_000, mint_policy.state_lock(EMPTY_ROOT)),))
        deposit = Deposit(DepositPosition(31337, asset.reserve_domain, template.reserve_contract, b"d" * 32, 1),
                          asset.reserve_asset, asset.network, asset.asset_id(), 1024, 0, cls.owner)
        plan = prepare_mint(mint_policy, genesis, MintEvents(), deposit, Input(funders[0].txid_wire(), 0),
                            receipt=ParentReceipt(()), verifier_parent=funders[0])
        minted = authorize_mint(plan, lambda _: deposit, sign_mint)
        cls.mint = minted.with_script(1, verifier.mint_witness(proof, minted, funders[0], genesis))
        cls.split = ordinary(funders[1], ((cls.mint, 1, funders[0]),), (state_output(640), state_output(384)))
        cls.frozen = toggle(cls.split, 0, funders[1], funders[2])
        cls.unfrozen = toggle(cls.frozen, 0, funders[2], funders[3])
        cls.single = ordinary(funders[4], ((cls.unfrozen, 0, funders[3]), (cls.split, 1, funders[1])),
                              (state_output(1024), SINGLE_OUTPUT_MARKER))
        partial = BurnReceipt(asset.asset_id(), asset.reserve_domain, b"r" * 20, 640)
        cls.partial = ordinary(funders[5], ((cls.single, 0, funders[4]),),
                               (partial.output(), state_output(384)), burn=True)
        cls.full = ordinary(funders[6], ((cls.partial, 1, funders[5]),),
                            (replace(partial, quantity=384).output(),), burn=True)
        cls.transactions = (
            *enumerate(funders, 1), (8, genesis), (9, cls.mint), (10, cls.split), (11, cls.frozen),
            (12, cls.unfrozen), (13, cls.single), (14, cls.partial), (15, cls.full),
        )

    def setUp(self):
        self.node = FixtureNode(self.transactions)
        self.policy = BsvConfirmationPolicy(self.asset.network, "regtest", self.node.hashes[0], 2)
        self.wallet = CertifiedWalletProvenance(self.verifier, self.node, self.policy, self.node.locations.get)


class CertifiedWalletTests(CertifiedWalletFixture):
    def test_exact_vout_for_all_certified_creation_operations(self):
        cases = (
            (self.mint, 1, "mint", 1024, False, 1),
            (self.split, 0, "transfer", 640, False, 0),
            (self.split, 1, "transfer", 384, False, 0),
            (self.single, 0, "single", 1024, False, 0),
            (self.frozen, 0, "freeze", 640, True, 1),
            (self.unfrozen, 0, "unfreeze", 640, False, 1),
            (self.partial, 1, "burn-change", 384, False, 0),
        )
        for tx, vout, operation, quantity, frozen, vin in cases:
            with self.subTest(operation=operation, vout=vout):
                result = self.wallet.check_creation(tx, vout)
                self.assertEqual((result.operation, result.state.quantity, result.state.frozen),
                                 (operation, quantity, frozen))
                self.assertEqual((result.txid_wire, result.vout), (tx.txid_wire(), vout))
                self.assertEqual(result.verifier_outpoint, tx.inputs[vin].outpoint())
                self.assertEqual(result.verifier_hash, self.verifier.mint_policy.certified_verifier_hash)
                self.assertEqual(result.location, self.node.locations[tx.txid_wire()])

    def test_rejects_mint_state_metadata_and_administrative_or_burn_receipts(self):
        for tx, index in ((self.mint, 0), (self.mint, 2), (self.mint, 3), (self.frozen, 1), (self.single, 1),
                          (self.partial, 0), (self.partial, 2), (self.full, 0), (self.full, 1)):
            with self.subTest(vout=index, size=len(tx.outputs)):
                self.assertFalse(self.wallet.valid_creation(tx, index))

    def test_same_token_lock_and_layout_are_insufficient_after_verifier_replacement(self):
        wrong_funding = replace(self.funders[5], outputs=(Output(100_000, asm("OP_1")),))
        self.node.include(7, wrong_funding)
        counterfeit = replace(self.partial, inputs=(
            replace(self.partial.inputs[0], txid=wrong_funding.txid_wire()), self.partial.inputs[1],
        ))
        self.node.include(16, counterfeit)
        self.assertEqual(counterfeit.outputs[1], self.partial.outputs[1])
        with self.assertRaisesRegex(ValueError, "invalid verifier parent"):
            self.wallet.check_creation(counterfeit, 1)

        unsigned = self.partial.with_script(0, b"")
        self.node.include(16, unsigned)
        with self.assertRaisesRegex(CertifiedWalletError, "does not attest"):
            self.wallet.check_creation(unsigned, 1)

    def test_refuses_wrong_policy_changed_wire_bytes_or_adopted_chain(self):
        other_freeze, _ = fixture_signer(99)
        other_verifier = replace(self.verifier, freeze_key=other_freeze)
        wrong = CertifiedWalletProvenance(other_verifier, self.node, self.policy, self.node.locations.get)
        self.assertFalse(wrong.valid_creation(self.partial, 1))
        with self.assertRaisesRegex(CertifiedWalletError, "network mismatch"):
            CertifiedWalletProvenance(self.verifier, self.node, replace(self.policy, network=2),
                                      self.node.locations.get)

        txid = self.partial.txid_wire()
        old = self.node.transactions[txid]
        self.node.transactions[txid] = replace(self.partial, locktime=2).serialize().hex()
        with self.assertRaisesRegex(BurnEvidenceError, "different hash"):
            self.wallet.check_creation(self.partial, 1)
        self.node.transactions[txid] = old
        self.node.hashes[14] = b"x" * 32
        with self.assertRaisesRegex(BurnEvidenceError, "not on the adopted chain"):
            self.wallet.check_creation(self.partial, 1)

    def test_composes_with_merkle_evidence_and_independent_known_spend_status(self):
        txid = self.partial.txid_wire()
        header = bytes(36) + txid + bytes(12)
        block = BlockInclusion.from_block(header, 14, (txid,), 0)
        self.node.hashes[14] = block.block_hash()
        self.node.locations[txid] = BsvTransactionLocation(block.block_hash(), 14)
        result = verify_payment(
            self.partial, 1, self.asset, self.verifier.policy, block,
            adopted_depth=lambda height, digest: 7 if self.node.hashes[height] == digest else None,
            valid_creation=self.wallet.valid_creation, lookup_spend=lambda _: SpendStatus.UNKNOWN,
            minimum_confirmations=2, expected_owner=self.owner,
        )
        self.assertEqual((result.quantity, result.confirmations, result.spend_status), (384, 7, SpendStatus.UNKNOWN))
        self.assertEqual(result.outpoint, txid + b"\x01\x00\x00\x00")

    def test_spendable_requires_exact_order_and_current_mempool_view(self):
        tx, vout = self.partial, 1
        txid = tx.txid_wire()
        header = bytes(36) + txid + bytes(12)
        block = BlockInclusion.from_block(header, 14, (txid,), 0)
        self.node.hashes[14] = block.block_hash()
        self.node.locations[txid] = BsvTransactionLocation(block.block_hash(), 14)
        tip = self.node.hashes[20]
        output = tx.outputs[vout]
        coin = {"bestblock": tip[::-1].hex(), "confirmations": 7,
                "scriptPubKey": {"hex": output.script.hex()}, "value": Decimal(output.value).scaleb(-8)}
        current = coin

        def rpc(method, *args):
            if method == "getblockheader":
                self.assertEqual(args, (block.block_hash()[::-1].hex(), False))
                return header.hex()
            if method == "gettxout":
                self.assertEqual(args, (tx.txid(), vout, True))
                return current
            return self.node(method, *args)

        wallet = replace(self.wallet, bsv_rpc=rpc)
        order = {"expected_quantity": 384, "expected_owner": self.owner}
        payment = wallet.check_spendable(tx, vout, **order)
        self.assertEqual(payment.inclusion, block)
        self.assertEqual((payment.tip_height, payment.tip_hash), (20, tip))
        self.assertEqual(payment.receipt.spend_status, SpendStatus.UNSPENT)
        self.assertEqual(payment.receipt.outpoint, txid + vout.to_bytes(4, "little"))
        self.assertEqual(payment, wallet.check_spendable(tx, vout, inclusion=block, **order))

        for changed in ({"expected_quantity": 385}, {"expected_owner": fixture_signer(77)[0]}):
            with self.subTest(changed=changed), self.assertRaisesRegex(CertifiedWalletError, "expected owner and quantity"):
                wallet.check_spendable(tx, vout, **(order | changed))
        with self.assertRaisesRegex(CertifiedWalletError, "frozen"):
            wallet.check_spendable(self.frozen, 0, expected_quantity=640, expected_owner=self.owner)
        with self.assertRaisesRegex(CertifiedWalletError, "transaction position"):
            wallet.check_spendable(tx, vout, inclusion=replace(block, leaf_count=2), **order)
        for changes, message in (({"value": 1}, "differs from the certified"),
                                 ({"scriptPubKey": {"hex": ""}}, "differs from the certified"),
                                 ({"bestblock": "ff" * 32}, "chain snapshot"),
                                 ({"confirmations": 0}, "chain snapshot")):
            current = coin | changes
            with self.subTest(changes=changes), self.assertRaisesRegex(CertifiedWalletError, message):
                wallet.check_spendable(tx, vout, **order)

        current = None
        self.assertEqual(wallet.check_creation(tx, vout), payment.creation)
        with self.assertRaisesRegex(CertifiedWalletError, "spent, conflicted or unavailable"):
            wallet.check_spendable(tx, vout, **order)


class AlignedWalletTests(CertifiedWalletFixture):
    align_output_count = True

    def test_confirmed_payment_padding_is_independent_of_eligibility_and_repayment(self):
        from continuity_statement import ParentReceipt
        from parent_prefix import align_output_count

        tx = self.split
        aligned = align_output_count(tx, 0)
        shortest = aligned.inputs[0].script[len(tx.inputs[0].script):]
        other = push(bytes(75)) if shortest != push(bytes(75)) else push(bytes(76))
        for pad in (b"", shortest, other, push(bytes(255)), b"\x4c\x00", b"\x4c\x01\x00",
                    b"\x4d\x02\x00" + bytes(2), b"\x4e\xff\x00\x00\x00" + bytes(255)):
            parent = tx.with_script(0, tx.inputs[0].script + pad)
            node = FixtureNode((*self.transactions[:9], (10, parent)))
            wallet = replace(self.wallet, bsv_rpc=node, locate=node.locations.get)
            creation = wallet.check_creation(parent, 0)
            self.assertEqual((creation.txid_wire, creation.state.quantity), (parent.txid_wire(), 640))
            next_receipt = ParentReceipt((creation.proof_digest,))
            funder = self.funders[2]
            spend = Transaction((Input(funder.txid_wire(), 0), Input(parent.txid_wire(), 0)),
                                (self.verifier.mint_policy.token_output(200, self.owner),
                                 self.verifier.mint_policy.token_output(440, self.owner), next_receipt.output()))
            self.assertEqual(self.verifier.validate(spend, funder, (parent,), (self.funders[1],))[0], next_receipt)

        for invalid in (push(b"\x01"), push(bytes(256)), push(b"") * 2, asm("OP_NOP"),
                        b"\x4c", b"\x4d\x00", b"\x4e\x01\x00\x00", b"\x4c\x02\x00",
                        b"\x4d\x01\x00\x01", b"\x4e\x00\x00\x00\x00\x00"):
            parent = tx.with_script(0, tx.inputs[0].script + invalid)
            self.node.include(16, parent)
            with self.assertRaisesRegex(CertifiedWalletError, "does not attest"):
                self.wallet.check_creation(parent, 0)
        # Even a legal pad cannot conceal a change to the actual transaction material.
        changed = tx.with_script(0, tx.inputs[0].script[:-2] + b"\xfa\x51" + shortest)
        self.node.include(16, changed)
        with self.assertRaisesRegex(CertifiedWalletError, "does not attest"):
            self.wallet.check_creation(changed, 0)
