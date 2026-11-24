from dataclasses import replace
from functools import lru_cache
import unittest

from capacity_relation import WideProfile, select_wide_token_output_script, wide_group_stream
from continuity_statement import ParentReceipt
from mimo_verifier import _compact_size, _split
from operational_token import TokenPolicy
from shared.evaluate import ScriptError, evaluate
from shared.script import asm, encode_num, push
from shared.transaction import Input, Output, Transaction, blob, hash256, preimage_all
from transaction_relation import TokenState
from transfer import COMPACT_SCRIPTCODE

ASSET = b"a" * 32
FREEZE = b"\x02" + b"f" * 32
OWNER = b"\x03" + b"o" * 32
POLICY = TokenPolicy((b"verifier",), FREEZE, certified_admin=True, shared_ordinary_guard=True)
GUARD, = POLICY.verifier_hashes()
SUPPORT = Transaction((Input(b"s" * 32, 9),), (Output(1, b"support"),))
CANDIDATE_FUNDING = Transaction((Input(b"v" * 32, 7),), (Output(389, b"verifier"),))
RECEIPT = ParentReceipt((b"d" * 32,)).output()
PROOF_PREFIX = b"untouched witness below relation"

# This fixture parses the actual input boundaries before extracting the output
# vector. The capacity verifier supplies its own ancestry digest callback.
SKIP_INPUT = (
    asm("OP_DUP OP_0NOTEQUAL OP_IF OP_SWAP") + _split(36) + asm("OP_NIP")
    + _compact_size() + asm("OP_SPLIT OP_NIP OP_4 OP_SPLIT OP_NIP OP_SWAP OP_1SUB OP_ENDIF")
)
PARENT_OUTPUTS = (
    asm("OP_4 OP_SPLIT OP_NIP") + _compact_size() + asm("OP_DUP 1 5 OP_WITHIN OP_VERIFY")
    + SKIP_INPUT * 4 + asm("OP_0 OP_NUMEQUALVERIFY") + _compact_size()
    + asm("OP_SWAP OP_SIZE OP_4 OP_SUB OP_SPLIT OP_DROP")
)
TEST_DIGEST = asm("OP_CAT OP_CAT OP_HASH256")


def token(quantity, *, owner=OWNER, policy=POLICY, frozen=False):
    return Output(2, policy.lock(TokenState(ASSET, quantity, owner, frozen)))


def creation(outputs, *, identity=1):
    return Transaction((Input(b"p" * 32, identity, push(b"x" * 260)),), (*outputs, RECEIPT))


def payment(inputs, outputs):
    return Transaction(
        (Input(CANDIDATE_FUNDING.txid_wire(), 0), Input(b"c" * 32, 0), *inputs),
        (*outputs, RECEIPT),
    )


def material(tx):
    return (
        b"".join(output.serialize() for output in tx.outputs),
        b"".join(txin.outpoint() for txin in tx.inputs),
        preimage_all(tx, 0, CANDIDATE_FUNDING.outputs[0].value, COMPACT_SCRIPTCODE),
    )


@lru_cache
def relation(n, m):
    return WideProfile(n, m).relation(ASSET, FREEZE, parent_outputs=PARENT_OUTPUTS, parent_digest=TEST_DIGEST)


def evaluate_relation(code, tx, pairs, *, stream=None, outputs=None, prevouts=None, preimage=None, guard=GUARD):
    contents = tuple(default if changed is None else changed
                     for default, changed in zip(material(tx), (outputs, prevouts, preimage), strict=True))
    groups = wide_group_stream(tx, pairs) if stream is None else stream
    return evaluate(code, [PROOF_PREFIX, groups, *contents, guard])


class CapacityRelationTests(unittest.TestCase):
    def assert_accepts(self, tx, parents):
        pairs = tuple((SUPPORT, parent) for parent in parents)
        expected = b"".join(hash256(parent.serialize() + SUPPORT.serialize() + GUARD) for parent in parents)
        self.assertEqual(evaluate_relation(relation(len(tx.inputs) - 2, len(tx.outputs) - 1), tx, pairs),
                         ([PROOF_PREFIX, expected, RECEIPT.serialize(), material(tx)[2]], []))

    def test_complete_counts_and_reused_parent(self):
        for n, m in ((1, 1), (1, 64), (64, 64), (1, 256), (256, 256)):
            with self.subTest(n=n, m=m):
                parent = creation((token(512),) * n)
                tx = payment(tuple(Input(parent.txid_wire(), i) for i in range(n)),
                             (token(1),) * (m - 1) + (token(512 * n - m + 1),))
                self.assertEqual(wide_group_stream(tx, ((SUPPORT, parent),)),
                                 blob(SUPPORT.serialize()) + blob(parent.serialize()))
                self.assert_accepts(tx, (parent,))

    def test_wide_counts_with_one_actual_transaction_per_input(self):
        for count in (64, 256):
            with self.subTest(count=count):
                parents = [
                    (creation((token(3),), identity=identity), identity)
                    for identity in range(count)
                ]
                parents.sort(key=lambda entry: int.from_bytes(entry[0].txid_wire(), "little"))
                tx = payment(tuple(Input(parent.txid_wire(), 0) for parent, _ in parents), (token(3),) * count)
                pairs = tuple((replace(SUPPORT, locktime=identity), parent) for parent, identity in parents)
                expected = b"".join(hash256(parent.serialize() + support.serialize() + GUARD)
                                    for support, parent in pairs)
                actual = evaluate_relation(relation(count, count), tx, pairs)
                self.assertEqual(actual, ([PROOF_PREFIX, expected, RECEIPT.serialize(), material(tx)[2]], []))

    def test_distinct_parents_and_actual_vouts_in_narrow_and_wide_parents(self):
        parents = [
            (creation((Output(290, push(b"arbitrary")), token(27))), (1,)),
            (creation((token(5),) * 256, identity=2), (0, 255)),
            (creation((token(3), token(13), token(17)), identity=3), (1, 2)),
        ]
        parents.sort(key=lambda entry: int.from_bytes(entry[0].txid_wire(), "little"))
        tx = payment(tuple(Input(parent.txid_wire(), index) for parent, vouts in parents for index in vouts),
                     (token(67, owner=FREEZE),))
        pairs = tuple((SUPPORT, parent) for parent, _ in reversed(parents))
        self.assertEqual(
            wide_group_stream(tx, pairs),
            b"".join(blob(SUPPORT.serialize()) + blob(parent.serialize()) for parent, _ in parents),
        )
        self.assert_accepts(tx, tuple(parent for parent, _ in parents))

    def test_rejects_duplicate_reverse_and_reappearing_outpoints(self):
        first = creation((token(7), token(7)))
        second = creation((token(7),), identity=2)
        first, second = sorted((first, second), key=lambda item: int.from_bytes(item.txid_wire(), "little"))
        # A hash-order violation rejects even if both group hashes and amounts
        # would otherwise match the complete candidate transaction.
        stream = blob(SUPPORT.serialize()) + blob(second.serialize()) + blob(SUPPORT.serialize()) + blob(first.serialize())
        tx = payment((Input(second.txid_wire(), 0), Input(first.txid_wire(), 0)), (token(14),))
        with self.assertRaisesRegex(ValueError, "strictly increasing"):
            wide_group_stream(tx, ((SUPPORT, first), (SUPPORT, second)))
        with self.assertRaises(ScriptError):
            evaluate_relation(relation(2, 1), tx, (), stream=stream)
        tx = payment((Input(first.txid_wire(), 0), Input(second.txid_wire(), 0), Input(first.txid_wire(), 0)), (token(21),))
        reverse_stream = blob(SUPPORT.serialize()) + blob(first.serialize()) + blob(SUPPORT.serialize()) + blob(second.serialize())
        with self.assertRaises(ScriptError):
            evaluate_relation(relation(3, 1), tx, (), stream=reverse_stream)

        parent = creation((token(7), token(7)))
        for vouts in ((0, 0), (1, 0)):
            tx = payment(tuple(Input(parent.txid_wire(), index) for index in vouts), (token(14),))
            with self.subTest(vouts=vouts), self.assertRaises(ScriptError):
                evaluate_relation(relation(2, 1), tx, (), stream=blob(SUPPORT.serialize()) + blob(parent.serialize()))

    def test_rejects_missing_and_extra_material_and_altered_committed_bytes(self):
        parent = creation((token(10),))
        tx = payment((Input(parent.txid_wire(), 0),), (token(10),))
        pairs = ((SUPPORT, parent),)
        stream = wide_group_stream(tx, pairs)
        outputs, prevouts, preimage = material(tx)
        variants = (
            {"stream": b""},
            {"stream": stream + stream},
            {"stream": b"\xfd" + len(SUPPORT.serialize()).to_bytes(2, "little") + stream[1:]},
            {"stream": blob(SUPPORT.serialize()) + blob(replace(parent, locktime=1).serialize())},
            {"outputs": outputs + b"\x01"},
            {"prevouts": prevouts[:-1] + b"\x01"},
            {"preimage": preimage[:-4] + b"\x43\x00\x00\x00"},
            {"preimage": preimage[:68] + bytes(36) + preimage[104:]},
            {"guard": b"z" * 32},
        )
        for overrides in variants:
            with self.subTest(field=tuple(overrides)), self.assertRaises(ScriptError):
                evaluate_relation(relation(1, 1), tx, pairs, **overrides)
        for bad_pairs in ((), pairs * 2, (*pairs, (SUPPORT, replace(parent, locktime=1)))):
            with self.subTest(pair_count=len(bad_pairs)), self.assertRaises(ValueError):
                wide_group_stream(tx, bad_pairs)

    def test_rejects_fabricated_slots_and_shifted_wide_output_boundaries(self):
        parent = creation((Output(2, b"\x51"), token(15)))
        for vout in (0, 2, 3):
            tx = payment((Input(parent.txid_wire(), vout),), (token(15),))
            with self.subTest(vout=vout), self.assertRaises(ScriptError):
                evaluate_relation(relation(1, 1), tx, ((SUPPORT, parent),))

        real = token(15)
        shifted = creation((Output(real.value, real.script + b"\x51"),
                            Output(real.value, real.script[:-1]), real, real))
        unshifted = creation((real,) * 4)
        self.assertEqual(len(shifted.serialize()), len(unshifted.serialize()))
        tx = payment((Input(shifted.txid_wire(), 2),), (real,))
        with self.assertRaises(ScriptError):
            evaluate_relation(relation(1, 1), tx, ((SUPPORT, shifted),))
        tx = payment((Input(unshifted.txid_wire(), 4),), (real,))
        with self.assertRaises(ScriptError):
            evaluate_relation(relation(1, 1), tx, ((SUPPORT, unshifted),))

    def test_standalone_wide_selection_checks_all_prior_positions(self):
        output = token(1)
        last = token(29, owner=FREEZE)
        carrier_size = len(output.script)
        receipt = RECEIPT.serialize()
        script = select_wide_token_output_script(carrier_size, len(receipt))

        def selected(index, count, raw):
            return evaluate(script, [PROOF_PREFIX, encode_num(index), encode_num(count), raw])

        one_carrier = last.serialize() + receipt
        self.assertEqual(selected(0, 2, one_carrier), ([PROOF_PREFIX, last.script], []))
        all_carriers = output.serialize() * 255 + last.serialize() + receipt
        self.assertEqual(selected(255, 257, all_carriers), ([PROOF_PREFIX, last.script], []))
        shifted = (
            replace(output, script=output.script + b"\x51").serialize()
            + replace(output, script=output.script[:-1]).serialize()
            + output.serialize() * 253 + last.serialize() + receipt
        )
        self.assertEqual(len(shifted), len(all_carriers))
        for vout, count, raw in (
            (-1, 257, all_carriers), (256, 257, all_carriers), (255, 257, shifted),
            (255, 257, all_carriers[:-1]), (0, 1, one_carrier),
        ):
            with self.subTest(vout=vout, count=count, size=len(raw)), self.assertRaises(ScriptError):
                selected(vout, count, raw)

    def test_rejects_foreign_guard_frozen_quantity_mismatch_extra_token_and_overflow(self):
        parent = creation((token(15),))
        vin = (Input(parent.txid_wire(), 0),)
        foreign = TokenPolicy((b"wrong verifier",), FREEZE, certified_admin=True, shared_ordinary_guard=True)
        variants = (
            (token(15, policy=foreign),), (token(15, frozen=True),), (token(14),), (token(16),),
            (token(14), token(1)),
        )
        for outputs in variants:
            tx = payment(vin, outputs)
            with self.subTest(outputs=outputs), self.assertRaises(ScriptError):
                evaluate_relation(relation(1, 1), tx, ((SUPPORT, parent),))
        outputs = (token(2**64 - 1), token(1))
        overflowing = creation(outputs)
        tx = payment(tuple(Input(overflowing.txid_wire(), i) for i in range(2)), outputs)
        with self.assertRaises(ScriptError):
            evaluate_relation(relation(2, 2), tx, ((SUPPORT, overflowing),))


if __name__ == "__main__":
    unittest.main()
