import json
from dataclasses import replace
from pathlib import Path
import unittest

from committed_verifier import load_artifact
from fixtures import fixture
from mimo_verifier import MimoProfile
from operational_token import TokenPolicy
from recursive_mimo import RecursiveMimo, SplitLeaf
from shared.evaluate import ScriptError, evaluate
from shared.pushtx import PUBLIC
from shared.script import encode_num, push
from shared.transaction import Input, Output, Transaction, hash256, preimage_all
from statement import AssetDescriptor
from transaction_relation import TokenState
from transfer import COMPACT_SCRIPTCODE


class RecursiveTransactionStatementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        asset = AssetDescriptor(1, b"a" * 36, 6, 7, b"r" * 32, b"p" * 32)
        outer_key, relation, _, _ = load_artifact(json.loads(
            (Path(__file__).parent / "testdata/bsb22-proof.json").read_text()
        ))
        leaf = SplitLeaf(fixture()[0], MimoProfile(1, 2, 2, PUBLIC))
        family = RecursiveMimo(leaf, outer_key, relation)
        leaf_lock, child_lock = leaf.profile.lock(asset, leaf.key), family.lock(asset)
        policy = TokenPolicy((leaf_lock, child_lock), PUBLIC)

        def output(quantity):
            return Output(1_000, policy.lock(TokenState(asset.asset_id(), quantity, PUBLIC)))

        def funding(tag, lock, amount):
            return Transaction((Input(hash256(tag), 0),), (Output(amount, lock),))

        funders = (funding(b"left", leaf_lock, 100_000), funding(b"right", leaf_lock, 110_000))
        # Dummy unlocking scripts exercise CompactSize above 65535.
        parents = tuple(Transaction(
            (Input(parent.txid_wire(), 0, push(bytes(66_000)), sequence=3 + i),
             Input(hash256(bytes([i])), 1, b"\x51", sequence=5 + i)),
            (output(a), output(b)), locktime=i + 80,
        ) for i, (parent, (a, b)) in enumerate(zip(funders, ((640, 384), (700, 324)), strict=True)))
        verifier = funding(b"child", child_lock, 470_000)
        tx = Transaction((Input(verifier.txid_wire(), 0), Input(parents[0].txid_wire(), 0),
                          Input(parents[1].txid_wire(), 1)), (output(700), output(264)))

        cls.asset, cls.family, cls.policy = asset, family, policy
        cls.funders, cls.parents, cls.verifier, cls.tx = funders, parents, verifier, tx
        cls.output = staticmethod(output)
        cls.relation = family.statement_script(asset)

    def execute_relation(self, tx=None, parents=None, funders=None):
        material = self.family.transaction_material(
            tx or self.tx, self.verifier, parents or self.parents, funders or self.funders,
        )
        return evaluate(material + self.relation)

    def test_leaf_digest_reconstructed_from_actual_output_and_funding(self):
        for parent, funding in zip(self.parents, self.funders, strict=True):
            statement = self.family.leaf.statement(self.asset, self.policy, parent, funding)
            script = push(parent.serialize()) + push(funding.serialize()) + self.family.leaf.statement_script(self.asset)
            self.assertEqual(evaluate(script), ([hash256(statement)], []))

    def test_authenticates_child_and_predecessor_statements(self):
        child, parents = self.family.statements(
            self.asset, self.policy, self.tx, self.verifier, self.parents, self.funders,
        )
        signals = self.family.signals(child, parents)
        preimage = preimage_all(self.tx, 0, self.verifier.outputs[0].value, COMPACT_SCRIPTCODE)
        self.assertEqual(self.execute_relation(), (list(map(encode_num, signals)), [hash256(preimage)]))
        with self.assertRaises(ScriptError):
            self.execute_relation(parents=self.parents[::-1])
        with self.assertRaises(ScriptError):
            self.execute_relation(funders=self.funders[::-1])

    def test_rejects_inflation_even_with_recomputed_child_preimage(self):
        inflated = replace(self.tx, outputs=(self.output(700), self.output(265)))
        with self.assertRaises(ScriptError):
            self.execute_relation(tx=inflated)
        bad_vout = replace(self.tx, inputs=(*self.tx.inputs[:2], replace(self.tx.inputs[2], vout=2)))
        with self.assertRaises(ScriptError):
            self.execute_relation(tx=bad_vout)
