"""Declared finite domain for P-256 payment input acceptance."""
from dataclasses import replace
from itertools import product
from math import prod
import unittest

from tx_engine import Script, Tx, TxIn

from signature import authorization, current_input_unlock
from test_payment import TRUE, check, child, fixture_signature, locking_script, parent, signer

VERSIONS = (1, 2)
OUTPUT_LAYOUTS = ("paired", "unpaired")
SIGHASH_TYPES = (0x41, 0x42, 0x43, 0x61, 0x62, 0x63, 0xc1, 0xc2, 0xc3, 0xe1, 0xe2, 0xe3)
CONTEXTS = (("genesis", False, 1), ("chronicle-old", True, 1), ("chronicle-new", True, 3))
WITNESS_CASES = (
    "unchanged", "other outpoint", "other sequence", "current sequence",
    "output zero", "same-index output", "wrong P-256 key", "wrong signing amount", "locktime",
)


def expected_payment(layout, mode, mutation):
    """Reference decision from the field commitments in the payment specification."""
    base = mode & 0x1f
    anyone_can_pay = bool(mode & 0x80)
    uses_otda_digest = bool(mode & 0x20) and (layout == "paired" or base != 3)
    return {
        "unchanged": True,
        "other outpoint": anyone_can_pay,
        "other sequence": anyone_can_pay or base != 1,
        "current sequence": False,
        "output zero": base != 1,
        "same-index output": base == 2,
        "wrong P-256 key": False,
        "wrong signing amount": uses_otda_digest,
        "locktime": False,
    }[mutation]


class PaymentAcceptanceTests(unittest.TestCase):
    def test_complete_input_acceptance_domain(self):
        self.check_complete_input_acceptance_domain(compiled_curve=False)

    def test_compiled_curve_complete_input_acceptance_domain(self):
        self.check_complete_input_acceptance_domain(compiled_curve=True)

    def test_scheduled_curve_complete_input_acceptance_domain(self):
        self.check_complete_input_acceptance_domain(compiled_curve="scheduled")

    def check_complete_input_acceptance_domain(self, *, compiled_curve):
        owner_key, owner_public, owner_hash = signer(7)
        wrong_key, _, _ = signer(19)
        funding = parent(locking_script(owner_hash, compiled_curve=compiled_curve), 1000, "33")
        sponsor = parent(TRUE, 400, "22")
        replacement = parent(TRUE, 400, "44")
        dimensions = (VERSIONS, OUTPUT_LAYOUTS, SIGHASH_TYPES, CONTEXTS, WITNESS_CASES)
        expected_size = 1296
        self.assertTrue(all(len(set(dimension)) == len(dimension) for dimension in dimensions))
        self.assertEqual(prod(map(len, dimensions)), expected_size)
        seen = set()
        accepted = dict.fromkeys((context[0] for context in CONTEXTS), 0)
        for version, layout, mode in product(*dimensions[:3]):
            amounts = [400, 600] if layout == "paired" else [900]
            unsigned = child([sponsor, funding], amounts)
            unsigned = Tx(version, unsigned.tx_ins, unsigned.tx_outs, 0)
            auth = authorization(unsigned, 1, 1000, mode)
            self.assertEqual(auth.companion, layout == "unpaired" and mode in (0x63, 0xe3))
            witness = current_input_unlock(auth, owner_public, fixture_signature(owner_key, auth.digest()))
            for mutation in WITNESS_CASES:
                previous = [sponsor, funding]
                ins = [TxIn(sponsor.id(), 0, unsigned.tx_ins[0].script_sig),
                       TxIn(funding.id(), 0, witness)]
                values = amounts.copy()
                locktime = 0
                if mutation == "other outpoint":
                    previous[0] = replacement
                    ins[0] = TxIn(replacement.id(), 0, ins[0].script_sig)
                elif mutation == "other sequence":
                    ins[0] = TxIn(sponsor.id(), 0, ins[0].script_sig, 0xfffffffe)
                elif mutation == "current sequence":
                    ins[1] = TxIn(funding.id(), 0, witness, 0xfffffffe)
                elif mutation == "output zero":
                    values[0] -= 1
                elif mutation == "same-index output":
                    if layout == "paired":
                        values[1] -= 1
                    else:
                        values.append(1)
                elif mutation == "wrong P-256 key":
                    wrong = current_input_unlock(auth, owner_public, fixture_signature(wrong_key, auth.digest()))
                    ins[1] = TxIn(funding.id(), 0, wrong)
                elif mutation == "wrong signing amount":
                    wrong_auth = authorization(unsigned, 1, 1001, mode)
                    wrong = current_input_unlock(
                        wrong_auth, owner_public, fixture_signature(owner_key, wrong_auth.digest()),
                    )
                    ins[1] = TxIn(funding.id(), 0, wrong)
                elif mutation == "locktime":
                    locktime = 1
                tx = Tx(version, ins, child(previous, values).tx_outs, locktime)
                expected = expected_payment(layout, mode, mutation)
                for context in CONTEXTS:
                    label, chronicle, height = context
                    with self.subTest(version=version, layout=layout, mode=hex(mode), context=label,
                                      mutation=mutation):
                        row = (version, layout, mode, context, mutation)
                        self.assertTrue(all(value in axis for value, axis in zip(row, dimensions, strict=True)))
                        self.assertNotIn(row, seen)
                        seen.add(row)
                        verdict = expected and (chronicle or not mode & 0x20)
                        check(tx, previous, 1, verdict, chronicle=chronicle, funding_height=height)
                        accepted[label] += verdict
                        if label == "chronicle-new":
                            if verdict:
                                tx.validate(previous)
                            else:
                                with self.assertRaises((ValueError, RuntimeError)):
                                    tx.validate(previous)
        self.assertEqual(len(seen), expected_size)
        self.assertEqual(accepted, {"genesis": 80, "chronicle-old": 180, "chronicle-new": 180})

    def test_rejects_nonconforming_witnesses_in_each_path(self):
        for compiled_curve in (False, True, "scheduled"):
            with self.subTest(compiled_curve=compiled_curve):
                self.check_nonconforming_witnesses(compiled_curve=compiled_curve)

    def check_nonconforming_witnesses(self, *, compiled_curve):
        owner_key, owner_public, owner_hash = signer(7)
        other_key, other_public, _ = signer(19)
        previous = [parent(TRUE, 400, "22"), parent(locking_script(owner_hash, compiled_curve=compiled_curve), 1000, "33")]
        paths = ((0x41, [400, 600]), (0x61, [400, 600]), (0x63, [900]), (0xe3, [900]))
        for mode, amounts in paths:
            unsigned = child(previous, amounts)
            auth = authorization(unsigned, 1, 1000, mode)
            ordinary = current_input_unlock(auth, owner_public, fixture_signature(owner_key, auth.digest()))
            raw = ordinary.raw_serialize()
            self.assertEqual(raw[-34], 32)
            wrong_type = replace(auth, preimage=auth.preimage[:-3] + b"\x01\x00\x00")
            wrong_type_witness = current_input_unlock(
                wrong_type, owner_public, fixture_signature(owner_key, wrong_type.digest()),
            )
            wrong_owner = current_input_unlock(auth, other_public, fixture_signature(other_key, auth.digest()))
            malformed = {
                "extra stack item": b"\x51" + raw,
                "bad inverse": raw[:-2] + bytes([raw[-2] ^ 1]) + raw[-1:],
                "flipped selector": raw[:-1] + (b"\x00" if auth.companion else b"\x51"),
                "non-boolean selector": raw[:-1] + b"\x52",
                "nonzero higher type bytes": wrong_type_witness.raw_serialize(),
                "valid signature with a different owner": wrong_owner.raw_serialize(),
            }
            check(child(previous, amounts, {1: ordinary}), previous, 1)
            for label, data in malformed.items():
                with self.subTest(mode=hex(mode), defect=label):
                    witness = Script()
                    witness.append_data(data)
                    tx = child(previous, amounts, {1: witness})
                    check(tx, previous, 1, False)
                    with self.assertRaises((ValueError, RuntimeError)):
                        tx.validate(previous)
