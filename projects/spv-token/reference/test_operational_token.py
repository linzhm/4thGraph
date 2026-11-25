"""Complete-input checks for token policy and administrative covenants."""
from dataclasses import replace
from hashlib import sha256
from importlib.util import find_spec
import unittest

from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_der_canonize

from operational_token import TokenPolicy, freeze_witness, ordinary_witness
from shared.script import asm
from shared.transaction import Input, Output, Transaction
from transaction_relation import TokenState


def fixture_signer(secret):
    key = SigningKey.from_secret_exponent(secret, curve=SECP256k1)

    def sign(digest):
        return key.sign_digest_deterministic(digest, hashfunc=sha256,
                                             sigencode=sigencode_der_canonize)

    return key.verifying_key.to_string("compressed"), sign


def parent_for(output, tag):
    return Transaction((Input(bytes([tag]) * 32, 0),), (output,))


def spends(*parents):
    return tuple(Input(parent.txid_wire(), 0) for parent in parents)


@unittest.skipUnless(find_spec("tx_engine"), "requires pinned chain-gang")
class OperationalTokenTests(unittest.TestCase):
    def setUp(self):
        # Public fixture keys and substitute verifier locks for guard isolation.
        owner, self.sign_owner = fixture_signer(11)
        freeze_key, self.sign_admin = fixture_signer(12)
        self.locks = (asm("OP_1"), asm("OP_2"))
        self.policy = TokenPolicy(self.locks, freeze_key)
        self.states = (TokenState(bytes(32), 640, owner), TokenState(bytes(32), 384, owner))
        self.parents = tuple(parent_for(Output(1500, self.policy.lock(state)), i)
                             for i, state in enumerate(self.states, 1))
        self.fee_parent = parent_for(Output(3000, asm("OP_1")), 3)

    def check(self, tx, parents):
        from shared.chain_gang import validate_at_heights

        validate_at_heights(tx, parents, spend_height=100, activation_height=2,
                            utxo_heights=(3,) * len(parents))

    def admin_tx(self, parents, states):
        return Transaction(spends(*parents, self.fee_parent),
                           tuple(Output(1500, self.policy.lock(state)) for state in states))

    def admin_signed(self, tx, parents, signer=None):
        for i, parent in enumerate(parents):
            tx = tx.with_script(i, freeze_witness(tx, i, parent, self.policy,
                                                   signer or self.sign_admin))
        return tx

    def test_freeze_and_unfreeze_two_real_inputs(self):
        frozen_states = tuple(replace(state, frozen=True) for state in self.states)
        parents = (*self.parents, self.fee_parent)
        freeze = self.admin_signed(self.admin_tx(self.parents, frozen_states), self.parents)
        self.check(freeze, parents)
        unfreeze = Transaction((Input(freeze.txid_wire(), 0), Input(freeze.txid_wire(), 1),
                                Input(self.fee_parent.txid_wire(), 0)),
                               self.admin_tx(self.parents, self.states).outputs)
        unfreeze = self.admin_signed(unfreeze, (freeze, freeze))
        self.check(unfreeze, (freeze, freeze, self.fee_parent))

    def test_wrong_key_altered_state_and_unpaired_successor_fail(self):
        frozen = tuple(replace(state, frozen=True) for state in self.states)
        tx = self.admin_tx(self.parents, frozen)
        parents = (*self.parents, self.fee_parent)
        other_owner, _ = fixture_signer(13)
        variants = (
            self.admin_signed(tx, self.parents, self.sign_owner),
            self.admin_signed(self.admin_tx(self.parents, (replace(frozen[0], quantity=641), frozen[1])),
                              self.parents),
            self.admin_signed(self.admin_tx(self.parents, (replace(frozen[0], owner=other_owner), frozen[1])),
                              self.parents),
            self.admin_signed(replace(tx, outputs=tx.outputs[:1]), self.parents),
            self.admin_signed(replace(tx, outputs=tx.outputs[::-1]), self.parents),
            self.admin_signed(replace(tx, outputs=(replace(tx.outputs[0], value=1499), tx.outputs[1])),
                              self.parents),
        )
        for index, rejected in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.check(rejected, parents)

    def test_active_lock_accepts_two_exact_verifiers_and_rejects_replacement(self):
        token = self.parents[0]
        successor = token.outputs[0]
        for index, lock in enumerate(self.locks):
            verifier = parent_for(Output(3000, lock), index + 20)
            tx = Transaction(spends(verifier, token), (successor,))
            witness = ordinary_witness(tx, 1, token, self.policy, verifier, self.sign_owner)
            self.check(tx.with_script(1, witness), (verifier, token))
        rogue = parent_for(Output(3000, asm("OP_3")), 22)
        tx = Transaction(spends(rogue, token), (successor,))
        # Build the witness from raw data to bypass the host policy preflight.
        from shared.script import push
        from shared.transaction import hash256, preimage_all

        preimage = preimage_all(tx, 1, successor.value, successor.script)
        witness = (push(self.sign_owner(hash256(preimage)) + b"\x41") + push(rogue.serialize())
                   + push(b"".join(item.outpoint() for item in tx.inputs)) + push(preimage) + asm("OP_0"))
        with self.assertRaises(ValueError):
            self.check(tx.with_script(1, witness), (rogue, token))

    def test_frozen_rejects_owner_spend_even_with_approved_verifier(self):
        from shared.script import push
        from shared.transaction import hash256, preimage_all

        token = parent_for(Output(1500, self.policy.lock(replace(self.states[0], frozen=True))), 5)
        verifier = parent_for(Output(3000, self.locks[0]), 6)
        tx = Transaction(spends(verifier, token), (self.parents[0].outputs[0],))
        output = token.outputs[0]
        preimage = preimage_all(tx, 1, output.value, output.script)
        witness = (push(self.sign_owner(hash256(preimage)) + b"\x41")
                   + push(verifier.serialize()) + push(b"".join(item.outpoint() for item in tx.inputs))
                   + push(preimage) + asm("OP_0"))
        with self.assertRaises(ValueError):
            self.check(tx.with_script(1, witness), (verifier, token))
