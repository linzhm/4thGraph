from dataclasses import replace
import unittest

from continuity_statement import COMMITTED_OUTPUT_SIZE, CommittedParentReceipt, ParentReceipt


class CommittedParentReceiptTests(unittest.TestCase):
    def test_width_order_and_round_trip(self):
        parents = tuple(bytes([n]) * 32 for n in range(1, 5))
        for count in range(5):
            receipt = CommittedParentReceipt.from_parents(parents[:count])
            txout = receipt.output()
            self.assertEqual(len(txout.serialize()), 77)
            self.assertEqual(len(txout.serialize()), COMMITTED_OUTPUT_SIZE)
            self.assertEqual(CommittedParentReceipt.parse(txout), receipt)
        whole = CommittedParentReceipt.from_parents(parents)
        self.assertEqual(whole.commitment.hex(),
                         "4ee24c0fd4d567e3f0884fd5cfed6e97a17577a1fdc1a39eadf860691d5c391f")
        self.assertNotEqual(whole, CommittedParentReceipt.from_parents(parents[::-1]))

    def test_rejects_alternate_receipt_encodings(self):
        receipt = CommittedParentReceipt.from_parents(()).output()
        for invalid in (
            ParentReceipt(()).output(),
            replace(receipt, value=1),
            replace(receipt, script=receipt.script + b"\0"),
            replace(receipt, script=receipt.script[:-33] + b"\x05" + receipt.script[-32:]),
            replace(receipt, script=receipt.script[:-1] + bytes([receipt.script[-1] ^ 1])),
        ):
            with self.assertRaises(ValueError):
                CommittedParentReceipt.parse(invalid)
        with self.assertRaises(ValueError):
            CommittedParentReceipt.from_parents((bytes(32),) * 5)
