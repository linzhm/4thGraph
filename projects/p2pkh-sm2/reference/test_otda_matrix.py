"""Complete-transaction coverage for the newest P2PKH-SM2 locking template."""
import argparse
from dataclasses import dataclass, replace
from pathlib import Path
import json
import os
import unittest
from unittest.mock import Mock, patch

from assemble import SIGNED_WINDOW_TEMPLATE_VERSION, TEMPLATE_PROFILES, TEMPLATE_VERSIONS
from fourthgraph.benchmark.cases import allocations, native_coin, seed
from fourthgraph.benchmark.validation import ACTIVATION_HEIGHT, SPEND_HEIGHT, UTXO_HEIGHT
from fourthgraph.benchmark.validation import Node, chain_metadata, chain_verdict
from fourthgraph.bsv.differential import require_chain_gang_pin
from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.transaction import Input, Output, Transaction
from p2pkh_sm2 import authorization, locking_script_from_owner_hash, locking_script_from_public_key, sign_input
from sm2 import USER_ID, encode_public, fixture_sign, mul

LATEST_VERSION = TEMPLATE_VERSIONS[-1]
INPUT_VALUE = 10_000
FEE = 100
require_chain_gang_pin(Path(__file__).with_name('requirements.txt'))


@dataclass(frozen=True)
class Case:
    name: str
    flags: tuple[int, ...]
    output_count: int
    reconstructed: tuple[int, ...]
    native_inputs: tuple[int, ...] = ()
    native_outputs: tuple[int, ...] = ()
    similar_output: int | None = None
    version: int = 2
    chronicle_active: bool = True
    compress_otda: bool | None = None
    same_parent: bool = False


def construction_cases():
    shapes = ((1, 1), (1, 2), (2, 1), (2, 2), (3, 2), (2, 3), (4, 4), (6, 2), (1, 8))
    for inputs, outputs in shapes:
        for mode, flag in (("all", 0x61), ("acp-all", 0xe1)):
            yield Case(f"{mode}-{inputs}x{outputs}", (flag,) * inputs, outputs, tuple(range(inputs)))
    yield from (
        Case("bip143-all", (0x41, 0xc1), 2, ()),
        Case("bip143-none", (0x42, 0xc2), 2, ()),
        Case("bip143-single", (0x43, 0xc3), 2, ()),
        Case("otda-none", (0x62, 0xe2), 2, ()),
        Case("otda-single", (0x63, 0xe3), 2, (0, 1)),
        Case("otda-unpaired-single", (0x63, 0xe3), 1, (0,)),
        Case("mixed-sighashes", (0x41, 0xe1, 0x63, 0xe3), 3, (1, 2)),
        Case("shared-funding-transaction", (0x61, 0xe1, 0x61), 2, (0, 1, 2), same_parent=True),
        Case("native-fee-input-and-output", (0x61, 0x41, 0xe1), 3, (0, 2),
             native_inputs=(1,), native_outputs=(1,)),
        Case("native-only-destinations", (0x61, 0xe1), 2, (), native_outputs=(0, 1)),
        Case("same-length-non-template", (0x61,), 1, (), similar_output=0),
        Case("same-length-output-beside-template", (0xe1,), 2, (0,), similar_output=0),
        Case("explicit-literal", (0x61, 0xe1), 2, (), compress_otda=False),
        Case("transaction-version-one", (0x61, 0xe1), 2, (), version=1),
        Case("pre-chronicle-bip143", (0x41, 0xc1), 2, (), version=1, chronicle_active=False),
        Case("compactsize-output-count", (0x61,), 253, (0,), native_outputs=tuple(range(1, 253))),
    )


def fixture(case, template_version):
    """Build balanced, deterministic synthetic transactions using public test keys."""
    native = native_coin(f"sm2-matrix/{case.name}/native", INPUT_VALUE)
    scalars = range(17, 17 + len(case.flags))
    keys = tuple(encode_public(mul(scalar)) for scalar in scalars)
    locks = tuple(native.output.script if index in case.native_inputs else
                  locking_script_from_public_key(key, version=template_version) for index, key in enumerate(keys))
    funding = tuple(Output(INPUT_VALUE, lock) for lock in locks)
    if case.same_parent:
        parent = Transaction((Input(seed(case.name), 0),), (Output(1, b'\x51'), *funding))
        parents = (parent,) * len(locks)
        vouts = range(1, len(locks) + 1)
    else:
        parents = tuple(Transaction((Input(seed(f"{case.name}/{index}"), 0),), (output,))
                        for index, output in enumerate(funding))
        vouts = (0,) * len(locks)
    inputs = tuple(Input(parent.txid_wire(), vout, sequence=10 + index)
                   for index, (parent, vout) in enumerate(zip(parents, vouts, strict=True)))
    outputs = []
    amounts = allocations(len(inputs) * INPUT_VALUE - FEE, case.output_count)
    for index, value in enumerate(amounts):
        owner = seed(f"{case.name}/destination/{index}")[:20]
        lock = (native.output.script if index in case.native_outputs else
                locking_script_from_owner_hash(owner, version=template_version))
        if index == case.similar_output:
            lock = bytes([lock[0] ^ 1]) + lock[1:]
        outputs.append(Output(value, lock))
    tx = Transaction(inputs, tuple(outputs), version=case.version, locktime=42)
    return tx, parents, keys, scalars, native


class LatestTemplateMatrixTests(unittest.TestCase):
    template_version = LATEST_VERSION

    @classmethod
    def setUpClass(cls):
        cls.node = Node(os.environ['REGTEST_URL'], os.environ['REGTEST_COOKIE'])

    def sign_variants(self, case, tx, parents, keys, scalars, native):
        compact, literal = tx, tx
        for index, (parent, key, scalar, flag) in enumerate(zip(parents, keys, scalars, case.flags, strict=True)):
            if index in case.native_inputs:
                signed = native.unlock(tx, index, parent, flag, None)
                witness = signed.inputs[index].script
                compact, literal = compact.with_script(index, witness), literal.with_script(index, witness)
                continue
            auth = authorization(tx, index, INPUT_VALUE, flag, chronicle_active=case.chronicle_active)
            signature = fixture_sign(scalar, auth.message, 71 + index)

            def signer(message, user_id):
                self.assertEqual((message, user_id), (auth.message, USER_ID))
                return signature

            args = (index, parent.serialize(), key, signer, flag)
            compact = sign_input(compact, *args, chronicle_active=case.chronicle_active,
                                 compress_otda=case.compress_otda)
            literal = sign_input(literal, *args, chronicle_active=case.chronicle_active, compress_otda=False)
            after, before = compact.inputs[index].script, literal.inputs[index].script
            self.assertEqual(evaluate(after), ([auth.preimage, key, signature], []))
            if index in case.reconstructed:
                self.assertLess(len(after), len(before))
            else:
                self.assertEqual(after, before)
        return compact, literal

    def test_transaction_construction_matrix(self):
        self.results = []
        with patch('p2pkh_sm2._combine_otda_programs', create=True,
                   side_effect=AssertionError('unexpected mixed SM2 constructor')):
            for case in construction_cases():
                with self.subTest(case=case.name):
                    tx, parents, keys, scalars, native = fixture(case, self.template_version)
                    compact, literal = self.sign_variants(case, tx, parents, keys, scalars, native)
                    spend_height = SPEND_HEIGHT if case.chronicle_active else ACTIVATION_HEIGHT - 1
                    utxo_height = UTXO_HEIGHT if case.chronicle_active else spend_height
                    self.assertEqual(sum(parent.outputs[txin.vout].value
                                         for parent, txin in zip(parents, tx.inputs, strict=True)) -
                                     sum(output.value for output in tx.outputs), FEE)
                    for signed in (compact, literal):
                        self.assertEqual(Transaction.parse(signed.serialize()), signed)
                        self.assertEqual(replace(signed, inputs=tuple(replace(item, script=b'')
                                                                      for item in signed.inputs)), tx)
                        self.assertTrue(chain_verdict(signed, parents))
                        self.assertEqual(self.node.verdicts(signed, parents, spend_height=spend_height,
                                                            utxo_heights=(utxo_height,) * len(parents)),
                                         [True] * len(parents))
                    self.results.append({
                        'case': case.name,
                        'shape': [len(tx.inputs), len(tx.outputs)],
                        'transaction_version': tx.version,
                        'chronicle_spend': case.chronicle_active,
                        'sighashes': [f'{flag:02x}' for flag in case.flags],
                        'native_inputs': list(case.native_inputs),
                        'native_output_count': len(case.native_outputs),
                        'non_matching_output': case.similar_output,
                        'same_funding_transaction': case.same_parent,
                        'reconstructed_inputs': list(case.reconstructed),
                        'shared_constructor_inputs': [],
                        'auto_bytes': len(compact.serialize()),
                        'literal_bytes': len(literal.serialize()),
                        'auto_txid': compact.txid(),
                        'literal_txid': literal.txid(),
                        'auto_unlock_bytes': [len(item.script) for item in compact.inputs],
                        'literal_unlock_bytes': [len(item.script) for item in literal.inputs],
                    })

    def test_latest_otda_activation_and_output_commitments(self):
        case = Case('binding-and-activation', (0x61, 0xe1), 2, (0, 1))
        tx, parents, keys, scalars, native = fixture(case, self.template_version)
        signer = Mock(side_effect=AssertionError('signer called before activation'))
        with self.assertRaisesRegex(ValueError, 'disabled'):
            sign_input(tx, 0, parents[0].serialize(), keys[0], signer, 0x61, chronicle_active=False)
        signer.assert_not_called()

        compact, _ = self.sign_variants(case, tx, parents, keys, scalars, native)
        self.assertTrue(chain_verdict(compact, parents))
        self.assertEqual(self.node.verdicts(compact, parents), [True, True])
        self.assertEqual(self.node.verdicts(compact, parents, spend_height=1, utxo_heights=(1, 1)), [False, False])
        self.assertEqual(self.node.verdicts(compact, parents, utxo_heights=(1, 3)), [True, True])
        for label, altered in (
            ('amount', replace(compact, outputs=(replace(compact.outputs[0], value=1), compact.outputs[1]))),
            ('order', replace(compact, outputs=compact.outputs[::-1])),
            ('locktime', replace(compact, locktime=compact.locktime + 1)),
        ):
            with self.subTest(mutation=label):
                self.assertFalse(chain_verdict(altered, parents))
                self.assertEqual(self.node.verdicts(altered, parents), [False, False])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, help='write the verified construction matrix as JSON')
    parser.add_argument('--template', type=int, choices=(SIGNED_WINDOW_TEMPLATE_VERSION, LATEST_VERSION),
                        default=LATEST_VERSION, help='locking template for the entire matrix')
    args = parser.parse_args()
    matrix = LatestTemplateMatrixTests('test_transaction_construction_matrix')
    binding = LatestTemplateMatrixTests('test_latest_otda_activation_and_output_commitments')
    matrix.template_version = binding.template_version = args.template
    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([matrix, binding]))
    if result.wasSuccessful() and args.report:
        evidence = {
            'sm2_locking_template': TEMPLATE_PROFILES[args.template],
            'bsv_node_version': '1.2.3',
            'chain_gang_commit': chain_metadata()['commit'],
            'validation': 'Peerless regtest script replay with supplied prevouts',
            'positive_cases': matrix.results,
            'controls_passed': ['pre-activation signing rejected', 'pre-activation OTDA witness rejected by node',
                                'post-activation mixed-age prevouts accepted by node',
                                'two engines reject altered output amount, output order and locktime'],
        }
        args.report.write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    raise SystemExit(not result.wasSuccessful())
