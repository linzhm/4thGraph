import unittest

from tx_engine import Context, Script


class AssemblyTests(unittest.TestCase):
    def test_runtime(self):
        program = Script.parse_string("OP_2 OP_3 OP_ADD OP_5 OP_NUMEQUAL")
        self.assertTrue(Context(program).evaluate())


if __name__ == "__main__":
    unittest.main()
