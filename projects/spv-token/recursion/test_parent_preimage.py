from dataclasses import replace
from importlib.util import find_spec
import unittest

from shared.evaluate import evaluate, ScriptError
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, hash256, preimage_all
from statement import Slot, TRANSFER_DOMAIN, encode_slots
from transfer import COMPACT_SCRIPTCODE

from parent_preimage import predecessor_preimage, predecessor_statement_digest, verifier_funding_script_hash


class PredecessorPreimageTests(unittest.TestCase):
    def test_reconstructs_preimage_from_actual_parent_bytes(self):
        verifier_lock = b'\x51' * 900
        funding = Transaction((Input(hash256(b'funding'), 0, b'\x51' * 22),), (Output(3, verifier_lock),))
        parent = Transaction((Input(funding.txid_wire(), 0, b'\x51' * 66_000, sequence=11),
                              Input(hash256(b'input'), 1, b'\x51' * 260, sequence=17)),
                             (Output(1, b'\x51'), Output(2, b'\x52' * 271)),
                             version=1, locktime=9)
        value = preimage_all(parent, 0, 3, COMPACT_SCRIPTCODE)
        relation = predecessor_preimage(verifier_funding_script_hash(verifier_lock))

        def lock_for(raw):
            return (asm("OP_OVER OP_HASH256") + push(hash256(raw)) + asm("OP_EQUALVERIFY")
                    + relation + push(value) + asm("OP_EQUAL"))

        unsigned = push(parent.serialize()) + push(funding.serialize())
        lock = lock_for(parent.serialize())
        self.assertEqual(evaluate(unsigned + lock), ([b'\x01'], []))
        asset_id, leaf_key_id = bytes(32), b'\x42' * 32
        slots = encode_slots((Slot(1, 1024),), 2, 1) + encode_slots((Slot(0, 640), Slot(1, 384)), 2, 0)
        digest = hash256(TRANSFER_DOMAIN + asset_id + leaf_key_id + hash256(value) + slots)
        digest_relation = predecessor_statement_digest(asset_id, leaf_key_id, verifier_funding_script_hash(verifier_lock))
        self.assertEqual(evaluate(push(slots) + unsigned + digest_relation), ([digest], []))
        other_order = replace(parent, outputs=parent.outputs[::-1]).serialize()
        self.assertEqual(evaluate(push(other_order) + push(funding.serialize()) + lock_for(other_order)), ([b""], []))
        wrong_funding = replace(funding, outputs=(Output(4, verifier_lock),))
        with self.assertRaises(ScriptError):
            evaluate(push(parent.serialize()) + push(wrong_funding.serialize()) + lock)
        wrong_lock_funding = replace(funding, outputs=(Output(3, verifier_lock + b'\x51'),))
        wrong_lock_parent = replace(parent, inputs=(replace(parent.inputs[0], txid=wrong_lock_funding.txid_wire()),
                                                   parent.inputs[1])).serialize()
        with self.assertRaises(ScriptError):
            evaluate(push(wrong_lock_parent) + push(wrong_lock_funding.serialize()) + lock_for(wrong_lock_parent))
        bad_position = replace(parent, inputs=(replace(parent.inputs[0], vout=1), parent.inputs[1])).serialize()
        with self.assertRaises(ScriptError):
            evaluate(push(bad_position) + push(funding.serialize()) + lock_for(bad_position))
        # The first output's one-byte script length replaced by a noncanonical
        # CompactSize encoding. Give that exact raw parent its own hash check.
        raw = parent.serialize()
        offset = 4 + 1 + sum(len(item.serialize()) for item in parent.inputs) + 1 + 8
        bad_size = raw[:offset] + b'\xfd\x01\x00' + raw[offset + 1:]
        with self.assertRaises(ScriptError):
            evaluate(push(bad_size) + push(funding.serialize()) + lock_for(bad_size))
        if find_spec("tx_engine") is not None:
            from shared.chain_gang import validate_at_heights

            fund = Transaction((Input(hash256(b"preimage check"), 0),), (Output(2, lock),))
            spend = Transaction((Input(fund.txid_wire(), 0, unsigned),), (Output(1, b'\x51'),))
            validate_at_heights(spend, (fund,), spend_height=100, activation_height=2, utxo_heights=(3,))
