from dataclasses import replace
from itertools import combinations
import unittest

from inventory_multipath import multipath_script, selection_witness
from inventory_tree import inventory_root, membership_path, multi_path, open_multi_path, pair_digest, payment_digest
from run_inventory_multipath_regtest import example_leaves
from shared.evaluate import ScriptError, evaluate
from shared.script import asm, push


class InventoryTreeTests(unittest.TestCase):
    def setUp(self):
        self.leaves = example_leaves(4, b"\x02" + bytes(32))
        self.root = inventory_root(self.leaves)

    def test_subset_roots_match_script_and_host(self):
        for count in range(1, 5):
            lock = multipath_script(4, count) + push(self.root) + asm("OP_EQUALVERIFY")
            for positions in combinations(range(4), count):
                digests = tuple(self.leaves[i].digest() for i in positions)
                siblings = multi_path(self.leaves, positions)
                self.assertEqual(self.root, open_multi_path(4, positions, digests, siblings))
                witness = selection_witness(self.leaves, positions)
                self.assertEqual(evaluate(witness + lock), ([], []))
                with self.assertRaises(ScriptError):
                    evaluate(witness[:-1] + bytes([witness[-1] ^ 1]) + lock)
                if siblings:
                    with self.assertRaises(ValueError):
                        open_multi_path(4, positions, digests, siblings[:-1])
                with self.assertRaises(ValueError):
                    open_multi_path(4, positions, digests, (*siblings, None))

    def test_exact_positions_and_single_paths(self):
        for i, leaf in enumerate(self.leaves):
            digest = leaf.digest()
            for level, sibling in enumerate(membership_path(self.leaves, i)):
                digest = pair_digest(sibling, digest) if (i >> level) & 1 else pair_digest(digest, sibling)
            self.assertEqual(self.root, digest)
        for invalid in ((0, 0), (2, 0), (1, 4), ()):
            with self.assertRaises(ValueError):
                multi_path(self.leaves, invalid)
        with self.assertRaises(ValueError):
            inventory_root([self.leaves[0]] * 4)

    def test_scope_outpoint_and_all_state_fields_affect_commitments(self):
        leaf = self.leaves[0]
        for field in (dict(quantity=9), dict(sats=999), dict(owner=b"\x03" + bytes(32)), dict(frozen=True)):
            self.assertNotEqual(leaf.digest(), replace(leaf, state=replace(leaf.state, **field)).digest())
        self.assertNotEqual(leaf.digest(), replace(leaf, scope=bytes(32)).digest())
        self.assertNotEqual(leaf.digest(), replace(leaf, outpoint=bytes(36)).digest())
        points = [self.leaves[i].outpoint for i in (0, 2)]
        outputs = [leaf.state, self.leaves[3].state]
        digest = payment_digest(leaf.scope, self.root, points, outputs)
        self.assertNotEqual(digest, payment_digest(leaf.scope, self.root, points[::-1], outputs))
        self.assertNotEqual(digest, payment_digest(leaf.scope, self.root, points, outputs[::-1]))
