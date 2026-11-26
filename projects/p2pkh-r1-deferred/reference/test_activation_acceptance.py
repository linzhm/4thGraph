"""Declared finite domain for activation of hash-only and full-key Deferred outputs."""
from dataclasses import replace
from itertools import product
from math import prod
import unittest

from deferred import activation_preimages, activate_input, funding_output, target_output
from fixed_templates import TEMPLATE_VERSIONS
from fourthgraph.bsv.script import asm, push
from fourthgraph.bsv.transaction import Input, Output, Transaction
from test_deferred import engine_tx, fixture_key
from test_payment import check
from test_payment_acceptance import CONTEXTS, SIGHASH_TYPES, VERSIONS

FUNDING_LAYOUTS = ("owner hash", "legacy full key")
ACTIVATION_CASES = (
    "unchanged", "fresh wrong target amount", "fresh wrong target script", "missing target output",
    "changed sponsor output", "changed activation sequence", "fresh wrong binding amount", "extra witness item",
    "fresh wrong target version",
)


def fresh_witness(tx, mode, amount):
    """Build witnesses below the wallet's canonical-recognition and target preflight."""
    binding, auxiliary = activation_preimages(tx, 1, amount, mode)
    return (push(auxiliary) if auxiliary else b"") + push(binding)


class ActivationAcceptanceTests(unittest.TestCase):
    def test_complete_input_activation_domain(self):
        for target_r1_version in TEMPLATE_VERSIONS:
            with self.subTest(target_r1_version=target_r1_version):
                self.check_complete_input_activation_domain(target_r1_version)

    def check_complete_input_activation_domain(self, target_r1_version):
        _, public_key = fixture_key(1)
        _, different_key = fixture_key(2)
        true_script = asm("OP_1")
        target = target_output(120_000, public_key, target_r1_version=target_r1_version)
        wrong_recipient = target_output(120_000, different_key, target_r1_version=target_r1_version)
        (other_version,) = (version for version in TEMPLATE_VERSIONS if version != target_r1_version)
        other_target = target_output(120_000, public_key, target_r1_version=other_version)
        current = funding_output(120_000, public_key, target_r1_version=target_r1_version)
        funding_locks = (current, replace(current, script=push(public_key) + current.script[21:]))
        dimensions = (FUNDING_LAYOUTS, VERSIONS, SIGHASH_TYPES, CONTEXTS, ACTIVATION_CASES)
        expected_size = 1296
        self.assertTrue(all(len(set(dimension)) == len(dimension) for dimension in dimensions))
        self.assertEqual(prod(map(len, dimensions)), expected_size)
        seen = set()
        accepted = dict.fromkeys((context[0] for context in CONTEXTS), 0)
        for layout, version, mode in product(*dimensions[:3]):
            funding_lock = funding_locks[FUNDING_LAYOUTS.index(layout)]
            funding = Transaction((Input(bytes.fromhex("f0" * 32), 0),),
                                  (Output(10_000, true_script), funding_lock))
            previous = engine_tx(funding)
            inputs = tuple(Input(funding.txid_wire(), index) for index in range(2))
            sponsor_output = Output(8000, true_script)
            unsigned = Transaction(inputs, (sponsor_output, target), version=version)
            base = activate_input(unsigned, 1, funding.serialize(), sighash=mode)
            for mutation in ACTIVATION_CASES:
                tx = base
                if mutation == "fresh wrong target amount":
                    tx = replace(unsigned, outputs=(sponsor_output, replace(target, value=target.value - 1)))
                    tx = tx.with_script(1, fresh_witness(tx, mode, funding_lock.value))
                elif mutation == "fresh wrong target script":
                    tx = replace(unsigned, outputs=(sponsor_output, wrong_recipient))
                    tx = tx.with_script(1, fresh_witness(tx, mode, funding_lock.value))
                elif mutation == "fresh wrong target version":
                    tx = replace(unsigned, outputs=(sponsor_output, other_target))
                    with self.assertRaisesRegex(ValueError, 'activation output'):
                        activate_input(tx, 1, funding.serialize(), sighash=mode)
                    tx = tx.with_script(1, fresh_witness(tx, mode, funding_lock.value))
                elif mutation == "missing target output":
                    tx = replace(base, outputs=(sponsor_output,))
                elif mutation == "changed sponsor output":
                    tx = replace(base, outputs=(replace(sponsor_output, value=sponsor_output.value - 1), target))
                elif mutation == "changed activation sequence":
                    tx = replace(base, inputs=(base.inputs[0], replace(base.inputs[1], sequence=0xfffffffe)))
                elif mutation == "fresh wrong binding amount":
                    tx = base.with_script(1, fresh_witness(unsigned, mode, funding_lock.value - 1))
                elif mutation == "extra witness item":
                    tx = base.with_script(1, true_script + base.inputs[1].script)
                spend = engine_tx(tx)
                # The lock always commits to the exact target. The selected ALL
                # mode also commits to the other output.
                expected = mutation == "unchanged" or (mutation == "changed sponsor output" and mode & 31 != 1)
                for context in CONTEXTS:
                    label, chronicle, height = context
                    with self.subTest(layout=layout, version=version, mode=hex(mode), context=label,
                                      mutation=mutation):
                        row = (layout, version, mode, context, mutation)
                        self.assertTrue(all(value in axis for value, axis in zip(row, dimensions, strict=True)))
                        self.assertNotIn(row, seen)
                        seen.add(row)
                        verdict = expected and (chronicle or not mode & 0x20)
                        check(spend, [previous, previous], 1, verdict, chronicle=chronicle, funding_height=height)
                        accepted[label] += verdict
                        if label == "chronicle-new":
                            if verdict:
                                spend.validate([previous])
                            else:
                                with self.assertRaises((ValueError, RuntimeError)):
                                    spend.validate([previous])
        self.assertEqual(len(seen), expected_size)
        self.assertEqual(accepted, {"genesis": 40, "chronicle-old": 80, "chronicle-new": 80})
