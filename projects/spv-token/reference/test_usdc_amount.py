import unittest

from usdc_amount import format_usdc, parse_usdc


class UsdcAmountTests(unittest.TestCase):
    def test_protocol_sample_and_uint64_boundary(self):
        for text, quantity, canonical in (
            ("0", 0, "0.000000"),
            ("0.001024", 1024, "0.001024"),
            ("0.000640", 640, "0.000640"),
            ("0.000384", 384, "0.000384"),
            ("1.2", 1_200_000, "1.200000"),
            ("1024", 1_024_000_000, "1024.000000"),
            ("18446744073709.551615", 2**64 - 1, "18446744073709.551615"),
        ):
            with self.subTest(text=text):
                self.assertEqual(parse_usdc(text), quantity)
                self.assertEqual(format_usdc(quantity), canonical)
                self.assertEqual(parse_usdc(canonical), quantity)

    def test_rejects_rounding_nondecimal_inputs_and_overflow(self):
        for text in (None, 1.0, "01", "-1", "+1", "1.", ".1", "1e-6", " 1", "1,000",
                     "１", "0.0000001", "1.0000000", "18446744073709.551616"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_usdc(text)
        for quantity in (True, 1.0, -1, 2**64):
            with self.subTest(quantity=quantity), self.assertRaises(ValueError):
                format_usdc(quantity)
