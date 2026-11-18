"""Run the inherited transaction acceptance suite with each window selected."""
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
import test_handwritten


class Joint2Tests(test_handwritten.PaymentTests):
    lock_version = 3


class Split4Tests(test_handwritten.PaymentTests):
    lock_version = 4


class GeneratorTableTests(unittest.TestCase):
    def test_public_multiples(self):
        values = {}
        for line in Path(__file__).with_name("window-4.asm").read_text().splitlines():
            if line.startswith("number "):
                _, name, value = line.split()
                values[name] = int(value, 16)
        for scalar in range(2, 16):
            point = ec.derive_private_key(scalar, ec.SECP256R1()).public_key().public_numbers()
            self.assertEqual(values[f"GX{scalar}"], point.x)
            self.assertEqual(values[f"GY{scalar}"], point.y)
