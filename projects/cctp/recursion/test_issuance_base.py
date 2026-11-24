"""Exact and normalized first-mint ancestry on canonical transaction bytes."""

from dataclasses import replace
from importlib.util import find_spec
import unittest

from issuance_base import check_first_mint, first_mint_base_script, runtime_first_mint_base_script, runtime_mint_state_script
from mint import MintPolicy, ROOT_OFFSET, authorize_mint, authorize_pause, prepare_mint
from mint_events import EMPTY_ROOT, MintEvents
from operational_token import TokenPolicy
from shared.evaluate import evaluate, ScriptError
from shared.script import asm, number, push
from shared.transaction import Input, Output, Transaction, hash256
from statement import AssetDescriptor
import test_certified_mint as certified_fixture
from test_mint import ATTESTOR, OTHER, OWNER, event, public, sign


class IssuanceBaseTests(unittest.TestCase):
    def setUp(self):
        self.funder = Transaction((Input(b"f" * 32, 0),), (
            Output(200_000, asm("OP_1")), Output(200_000, asm("OP_DROP OP_1")),
            Output(200_000, asm("OP_1")), Output(200_000, asm("OP_1")),
        ))
        spend = lambda vout: Input(self.funder.txid_wire(), vout)
        self.anchor, self.sponsor, self.alternate_anchor, self.test_funding = (spend(i) for i in range(4))
        self.asset = AssetDescriptor(1, self.anchor.outpoint(), 6, 7, b"a" * 32, b"p" * 32)
        self.tokens = TokenPolicy((b"BSV/CCTP/test verifier identity",), public(OTHER))
        self.mint_policy = MintPolicy(self.asset, 84532, b"r" * 20, public(ATTESTOR), self.tokens.lock)
        self.genesis = self.genesis_with()
        self.mint = self.mint_from(self.genesis)
        self.static = first_mint_base_script(self.mint_policy, self.tokens)
        self.runtime = runtime_first_mint_base_script(self.mint_policy, self.tokens.freeze_key)

    def genesis_with(self, *, anchor=None, root=EMPTY_ROOT, extra_input=False):
        first = self.anchor if anchor is None else anchor
        inputs = (first, self.alternate_anchor) if extra_input else (first,)
        return Transaction(inputs, (Output(1000, self.mint_policy.state_lock(root)), Output(1, asm("OP_1"))))

    def mint_from(self, genesis, events=None, *, sponsor_script=None, change=None):
        # Large actual scriptSig is valid because the sponsor lock consumes
        # that element with OP_DROP. This covers the 0xfe CompactSize case.
        script = push(bytes(66_000)) if sponsor_script is None else sponsor_script
        sponsor = replace(self.sponsor, script=script)
        deposit = event(self.mint_policy, 1, 640)
        plan = prepare_mint(self.mint_policy, genesis, MintEvents() if events is None else events,
                            deposit, sponsor, change=change)
        return authorize_mint(plan, lambda _: deposit, sign)

    @staticmethod
    def verifier_lock(fragment, mint_raw):
        # Stand-in for the invoking verifier's authenticated input txid and
        # vout. Pin the expected hash and check the exact bytes passed onward.
        return (asm("OP_2 OP_PICK OP_HASH256") + push(hash256(mint_raw))
                + asm("OP_EQUALVERIFY") + fragment + asm("OP_1"))

    def test_complete_static_and_normalized_inputs(self):
        self.assertGreater(len(self.mint.inputs[0].script), 520)
        self.assertGreater(len(self.mint.inputs[1].script), 65535)
        token = check_first_mint(self.mint_policy, self.tokens, self.mint, 1, self.genesis)
        self.assertEqual((token.quantity, token.owner), (640, public(OWNER)))
        owned = self.mint.serialize()
        raw_genesis = self.genesis.serialize()
        guard, = self.tokens.verifier_hashes()
        for fragment, fields in (
            (self.static, push(owned) + number(1) + push(raw_genesis)),
            (self.runtime, push(owned) + push(raw_genesis) + push(guard)),
        ):
            lock = self.verifier_lock(fragment, owned)
            self.assertEqual(evaluate(fields + lock), ([b"\x01"], []))
            saved = push(b"enclosing verifier frame") + asm("OP_TOALTSTACK")
            self.assertEqual(evaluate(saved + fields + lock), ([b"\x01"], [b"enclosing verifier frame"]))
            if find_spec("tx_engine"):
                from shared.chain_gang import validate_at_heights

                def check(transaction, parents):
                    validate_at_heights(transaction, parents, spend_height=100, activation_height=2,
                                        utxo_heights=(3,) * len(parents))

                check(self.genesis, (self.funder,))
                check(self.mint, (self.genesis, self.funder))
                funding = Transaction((self.test_funding,), (Output(10_000, lock),))
                check(funding, (self.funder,))
                payment = Transaction((Input(funding.txid_wire(), 0, fields),), (Output(1000, asm("OP_1")),))
                check(payment, (funding,))

    def test_rejects_foreign_anchor_wrong_state_and_wrong_guard(self):
        guard, = self.tokens.verifier_hashes()
        foreign = self.genesis_with(anchor=self.alternate_anchor)
        copied_mint = self.mint_from(foreign)
        nonempty = MintEvents(frozenset({b"b" * 32}))
        nonempty_genesis = self.genesis_with(root=nonempty.root)
        nonempty_mint = self.mint_from(nonempty_genesis, nonempty)
        different_verifier = TokenPolicy((b"other verifier",), self.tokens.freeze_key)
        different_guard, = different_verifier.verifier_hashes()
        token = self.tokens.parse(self.mint.outputs[1].script)
        altered = replace(self.mint, outputs=(
            self.mint.outputs[0], replace(self.mint.outputs[1], script=different_verifier.lock(token)),
            *self.mint.outputs[2:],
        ))
        for mint, genesis, accepted_guard in (
            (copied_mint, foreign, guard),
            (nonempty_mint, nonempty_genesis, guard),
            (self.mint, self.genesis, bytes(32)),
            (self.mint, foreign, guard),
            (altered, self.genesis, different_guard),
        ):
            raw = mint.serialize()
            witness = push(raw) + push(genesis.serialize()) + push(accepted_guard)
            with self.subTest(txid=mint.txid()), self.assertRaises(ScriptError):
                evaluate(witness + self.verifier_lock(self.runtime, raw))

    def test_rejects_wrong_vout_and_noncanonical_complete_serialization(self):
        raw, genesis = self.mint.serialize(), self.genesis.serialize()
        malformed_genesis = genesis[:4] + b"\xfd\x01\x00" + genesis[5:]
        dependent = replace(self.mint, inputs=(
            replace(self.mint.inputs[0], txid=hash256(malformed_genesis)), self.mint.inputs[1],
        ))
        variants = (
            (raw, 0, genesis),
            (raw, 2, genesis),
            (raw + b"x", 1, genesis),
            (raw[:4] + b"\xfd\x02\x00" + raw[5:], 1, genesis),
            # Noncanonical 0xff for the actual first input script's short length.
            (raw[:41] + b"\xff" + len(self.mint.inputs[0].script).to_bytes(8, "little") + raw[44:], 1, genesis),
            (dependent.serialize(), 1, malformed_genesis),
        )
        for minted, vout, raw_genesis in variants:
            with self.subTest(vout=vout, bytes=len(minted)), self.assertRaises(ScriptError):
                witness = push(minted) + number(vout) + push(raw_genesis)
                evaluate(witness + self.verifier_lock(self.static, minted))

    def test_accepts_bounded_extra_genesis_inputs_and_mint_sponsor_change(self):
        genesis = self.genesis_with(extra_input=True)
        change = Output(900, bytes.fromhex("76a914" + "41" * 20 + "88ac"))
        mint = self.mint_from(genesis, change=change)
        raw = mint.serialize()
        guard, = self.tokens.verifier_hashes()
        witness = push(raw) + push(genesis.serialize()) + push(guard)
        self.assertEqual(evaluate(witness + self.verifier_lock(self.runtime, raw)), ([b"\x01"], []))


class CertifiedStateScriptTests(unittest.TestCase):
    def setUp(self):
        self.fixture = certified_fixture.CertifiedMintTests()
        self.fixture.setUp()
        self.policy = replace(self.fixture.policy, pause_authority=self.fixture.freeze)
        self.genesis = self.fixture.genesis_for(self.policy)
        self.guard, = self.fixture.tokens.verifier_hashes()
        self.genesis_script = runtime_mint_state_script(self.policy, self.fixture.freeze, genesis_only=True)
        self.continuing_script = runtime_mint_state_script(self.policy, self.fixture.freeze, genesis_only=False)

    @staticmethod
    def material(transaction, fragment, guard):
        # Stand-in for authentication by the invoking verifier's input relation.
        lock = (asm("OP_OVER OP_HASH256") + push(transaction.txid_wire()) + asm("OP_EQUALVERIFY")
                + fragment + asm("OP_1"))
        witness = push(transaction.serialize()) + push(guard)
        return lock, witness

    def script_result(self, transaction, fragment, guard=None):
        lock, witness = self.material(transaction, fragment, self.guard if guard is None else guard)
        return evaluate(witness + lock)

    def test_genesis_and_confirmed_certified_mint_state(self):
        self.assertEqual(self.script_result(self.genesis, self.genesis_script), ([b"\x01"], []))
        plan = self.fixture.plan_for(self.policy, self.genesis, MintEvents(), self.fixture.verifier_parent,
                                     self.fixture.deposit, self.fixture.receipt)
        minted = self.fixture.authorize(plan)
        self.assertEqual(self.script_result(minted, self.continuing_script), ([b"\x01"], []))
        self.fixture.check_inputs(minted, (self.genesis, self.fixture.verifier_parent))
        with self.assertRaises(ScriptError):
            self.script_result(minted, self.genesis_script)
        lock, witness = self.material(minted, self.continuing_script, self.guard)
        self.assertEqual(evaluate(push(b"enclosing frame") + asm("OP_TOALTSTACK") + witness + lock),
                         ([b"\x01"], [b"enclosing frame"]))
        funding = Transaction((self.fixture.input_at(self.fixture.coin_parent, 3),), (Output(10_000, lock),))
        payment = Transaction((Input(funding.txid_wire(), 0, witness),), (Output(1000, asm("OP_1")),))
        self.fixture.check_inputs(payment, (funding,))

    def test_state_root_and_pause_fields_are_the_only_mutable_body(self):
        admin = lambda digest: sign(digest, OTHER)
        paused = authorize_pause(self.policy, self.genesis, MintEvents(),
                                 self.fixture.input_at(self.fixture.coin_parent, 4), admin, paused=True)
        self.assertEqual(self.script_result(paused, self.continuing_script), ([b"\x01"], []))
        self.fixture.check_inputs(paused, (self.genesis, self.fixture.coin_parent))
        state_output = self.genesis.outputs[0]
        rootful = replace(self.genesis, outputs=(replace(
            state_output, script=self.policy.state_lock(MintEvents(frozenset({b"x" * 32})).root),
        ),))
        with self.assertRaises(ScriptError):
            self.script_result(rootful, self.genesis_script)
        self.assertEqual(self.script_result(rootful, self.continuing_script), ([b"\x01"], []))

        pause_offset = ROOT_OFFSET - 3 + 32 + len(asm("OP_NIP"))
        script = state_output.script
        for rogue in (
            script[:pause_offset] + asm("OP_2") + script[pause_offset + 1:],
            script[:-1] + asm("OP_1"),
            script.replace(self.guard, b"f" * 32, 1),
        ):
            forged = replace(self.genesis, outputs=(replace(state_output, script=rogue),))
            with self.subTest(changed_byte=next(i for i, v in enumerate(rogue) if v != script[i])):
                with self.assertRaises(ScriptError):
                    self.script_result(forged, self.continuing_script)

    def test_wrong_anchor_wrong_guard_and_legacy_state(self):
        alien_anchor = replace(self.genesis, inputs=(self.fixture.input_at(self.fixture.coin_parent, 2),))
        legacy = self.fixture.genesis_for(replace(self.policy, certified_verifier_hash=None))
        for state, fragment, guard in (
            (alien_anchor, self.genesis_script, self.guard),
            (self.genesis, self.genesis_script, b"f" * 32),
            (legacy, self.genesis_script, self.guard),
            (legacy, self.continuing_script, self.guard),
        ):
            with self.subTest(txid=state.txid()), self.assertRaises(ScriptError):
                self.script_result(state, fragment, guard)
