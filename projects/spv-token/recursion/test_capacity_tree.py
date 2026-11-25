from hashlib import sha256
import unittest

from capacity_tree import CAPACITY_TREE_DOMAIN, capacity_plan, capacity_receipt, capacity_receipt_script
from continuity_statement import ParentReceipt
from shared.evaluate import ScriptError, evaluate
from shared.script import asm, push


ASSET = b"a" * 32
KEY = b"k" * 32


def parent_digests(count):
    return tuple(sha256(i.to_bytes(2, "big")).digest() for i in range(count))


def hash256(data):
    return sha256(sha256(data).digest()).digest()


def node_digest(height, left, right):
    context = hash256(b"BSV/CCTP/capacity-tree/v1\x00" + bytes([height]) + left + right)
    return hash256(b"BSV/CCTP/continuity/v1\x00" + ASSET + KEY + context + b"\x02" + left + right)


class CapacityTreeTests(unittest.TestCase):
    def test_script_matches_host_at_each_capacity(self):
        for capacity, counts in (
            (1, (1,)), (2, (1, 2)), (4, (1, 2, 3, 4)),
            (64, (1, 2, 17, 63, 64)), (256, (1, 2, 65, 127, 255, 256)),
        ):
            script = capacity_receipt_script(ASSET, KEY, capacity)
            for count in counts:
                with self.subTest(capacity=capacity, count=count):
                    parents = parent_digests(count)
                    expected = capacity_receipt(ASSET, KEY, capacity, parents).payload()
                    self.assertEqual(len(expected), 65)
                    stack = [b"caller stack", b"caller altstack", b"".join(parents)]
                    prefix = asm("OP_SWAP OP_TOALTSTACK")
                    self.assertEqual(evaluate(prefix + script, stack),
                                     ([b"caller stack", expected], [b"caller altstack"]))

    def test_wire_height_order_and_last_digest_padding(self):
        a, b, c = parent_digests(3)
        ab, cc = node_digest(1, a, b), node_digest(1, c, c)
        expected = ParentReceipt((node_digest(2, ab, cc), node_digest(2, cc, cc)))
        script = capacity_receipt_script(ASSET, KEY, 8)
        parents = (a, b, c)
        self.assertEqual(capacity_receipt(ASSET, KEY, 8, parents), expected)
        selected_receipt = push(expected.payload()) + asm("OP_EQUALVERIFY")
        self.assertEqual(evaluate(script + selected_receipt, [a + b + c]), ([], []))

        wrong_height = script.replace(push(CAPACITY_TREE_DOMAIN + b"\x02"),
                                      push(CAPACITY_TREE_DOMAIN + b"\x03"))
        for mutated_script, packed in ((wrong_height, a + b + c), (script, b + a + c),
                                       (script, a + c), (script, a + b + c + b)):
            with self.assertRaises(ScriptError):
                evaluate(mutated_script + selected_receipt, [packed])

    def test_proving_plan_reuses_padding_and_keeps_child_order(self):
        a, b, c = parent_digests(3)
        plan = capacity_plan(ASSET, KEY, 8, (a, b, c))
        ab, cc = node_digest(1, a, b), node_digest(1, c, c)
        self.assertEqual(tuple(step.receipt.parents for step in plan.steps),
                         ((a, b), (c, c), (ab, cc), (cc, cc)))
        seen = []

        def prove(context, children):
            seen.append((context, children))
            return ParentReceipt(children).digest(ASSET, KEY, context)

        self.assertEqual(plan.prove((a, b, c), prove), plan.receipt.parents)
        self.assertEqual(seen, [(step.context, step.receipt.parents) for step in plan.steps])
        for capacity, parents in ((256, (a,)), (2, (a, b))):
            direct = capacity_plan(ASSET, KEY, capacity, parents)
            self.assertEqual(direct.steps, ())
            self.assertEqual(direct.prove(parents, lambda *_: self.fail("unexpected proof")), parents)
        with self.assertRaises(ValueError):
            plan.prove((a, b), prove)

    def test_rejects_invalid_capacity_parameters_and_packed_lengths(self):
        for capacity in (0, 3, 257, 512, True):
            with self.assertRaises(ValueError):
                capacity_receipt_script(ASSET, KEY, capacity)
            with self.assertRaises(ValueError):
                capacity_receipt(ASSET, KEY, capacity, parent_digests(1))
        for asset, key in ((b"", KEY), (ASSET, b"")):
            with self.assertRaises(ValueError):
                capacity_receipt_script(asset, key, 2)
            with self.assertRaises(ValueError):
                capacity_receipt(asset, key, 2, parent_digests(1))
        for parents in ((), (b"\x01",), parent_digests(3)):
            with self.assertRaises(ValueError):
                capacity_receipt(ASSET, KEY, 2, parents)

        script = capacity_receipt_script(ASSET, KEY, 2)
        for size in (0, 31, 33, 65, 96):
            with self.assertRaises(ScriptError):
                evaluate(script, [bytes(size)])
