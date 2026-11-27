"""Arithmetic differential checks for the opt-in P-256 compiler."""

from itertools import product
from random import Random
import unittest

from assemble import assemble
from curve_compiler import ADD, ADD_INPUTS, B3, DOUBLE, DOUBLE_INPUTS, FIELD, curve_blocks, intermediate_bits
from p2pkh_r1 import locking_script_from_owner_hash, recognize
from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.bsv.script import decode_num, encode_num
from signature import GROUP_ORDER_R1
from test_payment import signer


class CurveCompilerTests(unittest.TestCase):
    def test_projective_formulas_match_the_literal_blocks_in_the_field(self):
        rng = Random(256)
        edges = (0, 1, -1, FIELD - 1, 1 - FIELD)
        for name, arity, assignments, inputs, expected_bound in (
            ('ADD_POINTS', 6, ADD, ADD_INPUTS, 1529),
            ('DOUBLE_POINT', 3, DOUBLE, DOUBLE_INPUTS, 1547),
        ):
            literal = assemble(bytes(20), entry=name)
            scheduled = curve_blocks(signed_residues=False)[name]
            compiled = curve_blocks()[name]
            self.assertLess(len(compiled), len(scheduled))
            self.assertLess(len(scheduled), len(literal))
            self.assertEqual(intermediate_bits(inputs, assignments), expected_bound)
            vectors = [tuple([a, b] * arity)[:arity] for a, b in product(edges, repeat=2)]
            vectors.extend(tuple(rng.randrange(1 - FIELD, FIELD) for _ in range(arity))
                           for _ in range(200))
            for coordinates in vectors:
                with self.subTest(kernel=name, coordinates=coordinates):
                    # Keep an unrelated value between the cached constants and point.
                    prefix = tuple(map(encode_num, (FIELD, B3, 847)))
                    start = [*prefix, *(encode_num(value) for value in coordinates)]
                    original, _ = evaluate(literal, start)
                    for kernel in (scheduled, compiled):
                        stack, alternate = evaluate(kernel, start)
                        self.assertEqual(tuple(stack[:3]), prefix)
                        self.assertEqual(alternate, [])
                        self.assertEqual(len(stack), 6)
                        self.assertEqual([decode_num(value) % FIELD for value in stack[3:]],
                                         [decode_num(value) % FIELD for value in original[3:]])
                        self.assertTrue(all(abs(decode_num(value)) < FIELD for value in stack[3:]))

    def test_endpoint_handles_x_plus_order_and_infinity(self):
        # For e=0 and r=s=x(G')-n, the verification point is exactly G'.
        # Construct G' with n < x(G') < p to exercise the rare second candidate.
        n = GROUP_ORDER_R1
        b = (B3 * pow(3, -1, FIELD)) % FIELD
        for x in range(n + 1, n + 128):
            rhs = (x**3 - 3*x + b) % FIELD
            y = pow(rhs, (FIELD + 1) // 4, FIELD)
            if y * y % FIELD == rhs:
                break
        else:
            self.fail('no second-candidate point')
        r = x - n
        high_x = (FIELD, r, r, x, y, 0, pow(r, -1, n))
        _, public, _ = signer(1)
        gx = int.from_bytes(public[1:33], 'big')
        gy = int.from_bytes(public[33:], 'big')
        infinity = (FIELD, 1, 1, gx, FIELD - gy, 1, 1)
        for compiled_curve in (False, True):
            kernel = assemble(bytes(20), compiled_curve=compiled_curve, entry='VERIFY_R1_POINT')
            self.assertEqual(evaluate(kernel, [encode_num(value) for value in high_x]), ([], []))
            with self.assertRaises(ScriptError):
                evaluate(kernel, [encode_num(value) for value in infinity])

    def test_owner_slot_and_full_template_recognition(self):
        owner = bytes(range(20))
        canonical = locking_script_from_owner_hash(owner, compiled_curve=False)
        compiled = locking_script_from_owner_hash(owner, compiled_curve=True)
        self.assertEqual(len(canonical), 59582)
        self.assertEqual(len(compiled), 47510)
        self.assertEqual(compiled, assemble(owner, compiled_curve=True))
        self.assertEqual(recognize(compiled), owner)
        self.assertEqual(recognize(canonical), owner)
        for offset in (0, 207, 228, len(compiled) - 1):
            modified = bytearray(compiled)
            modified[offset] ^= 1
            self.assertIsNone(recognize(bytes(modified)))


if __name__ == '__main__':
    unittest.main()
