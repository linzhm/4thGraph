import unittest

from inventory_origin import direct_origin_script, origin_statement
from shared.evaluate import ScriptError, evaluate
from shared.script import push
from shared.transaction import hash256


class DirectOriginTests(unittest.TestCase):
    def test_canonical_four_and_independent_rejections(self):
        approved = [hash256(bytes([i])) for i in range(4)]
        source = origin_statement(approved)
        raw = b"".join(approved)
        lock = direct_origin_script(source.anchor)

        def run(material, root):
            return evaluate(push(material) + push(root) + lock)

        self.assertEqual(run(raw, source.root), ([b"\x01"], []))
        self.assertEqual(run(raw, origin_statement(approved, (2, 3, 1, 0)).root), ([b""], []))
        for invalid in (raw + b"\x00", raw[:-1], raw[32:]+raw[:32]):
            with self.assertRaises(ScriptError):
                run(invalid, source.root)
        with self.assertRaises(ValueError):
            origin_statement(approved, (0, 2, 2, 3))
