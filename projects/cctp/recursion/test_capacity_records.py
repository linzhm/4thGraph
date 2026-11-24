from importlib.util import find_spec
from random import Random
import unittest

from capacity_records import MAX_SEGMENTS, capacity_record_script, decode_capacity_record, encode_capacity_record
from shared.evaluate import ScriptError, evaluate
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, compact, hash256


class CapacityRecordTests(unittest.TestCase):
    def setUp(self):
        self.dictionary = (b"repeated universal lock", b"shared witness bytes")
        self.script = capacity_record_script()

    def assert_expands(self, raw, record, dictionary=None):
        if dictionary is None:
            dictionary = self.dictionary
        self.assertEqual(raw, decode_capacity_record(record, dictionary))
        lower, alt = b"previous item", b"caller altstack"
        script = push(alt) + asm("OP_TOALTSTACK") + self.script
        self.assertEqual(evaluate(script, stack=[lower, record, *dictionary]), ([lower, raw], [alt]))

    def test_mixed_order_shortens_real_transaction_bytes(self):
        lock, witness = self.dictionary
        tx = Transaction((Input(hash256(b"funding"), 0, witness),), (Output(1, lock), Output(2, lock)))
        raw = tx.serialize()
        record = encode_capacity_record(raw, self.dictionary)
        self.assertLess(len(record), len(raw))
        self.assert_expands(raw, record)

        check = self.script + asm("OP_HASH256") + push(tx.txid_wire()) + asm("OP_EQUAL")
        wrong_lock = bytes(len(lock))
        self.assertEqual(evaluate(check, stack=[record, *self.dictionary]), ([b"\x01"], []))
        self.assertEqual(evaluate(check, stack=[record, wrong_lock, witness]), ([b""], []))
        if find_spec("tx_engine") is not None:
            from shared.chain_gang import validate_at_heights

            fund = Transaction((Input(hash256(b"capacity record check"), 0),), (Output(2, check),))
            witness_script = b"".join(map(push, (record, *self.dictionary)))
            spend = Transaction((Input(fund.txid_wire(), 0, witness_script),), (Output(1, b"\x51"),))
            validate_at_heights(spend, (fund,), spend_height=100, activation_height=2, utxo_heights=(3,))

    def test_deterministic_match_selection_and_fallback(self):
        dictionary = (b"abcd", b"abcde")
        raw = b"xabcdeabcdy"
        record = encode_capacity_record(raw, dictionary)
        self.assertEqual(record, b"\x04\x00\x01x\x02\x01\x00\x01y")
        self.assert_expands(raw, record, dictionary)

        for dictionary, raw, record in (
            ((b"abc", b"abc"), b"abcabc", b"\x02\x01\x01"),
            ((b"abc", b"bcdefgh"), b"abcdefgh", b"\x02\x01\x00\x05defgh"),
            ((b"a", b""), b"zaz", b"\x01\x00\x03zaz"),
            ((b"", b"abc"), b"abc", b"\x01\x02"),
            ((b"", b""), b"", b"\x01\x00\x00"),
        ):
            with self.subTest(dictionary=dictionary, raw=raw):
                self.assertEqual(encode_capacity_record(raw, dictionary), record)
                self.assert_expands(raw, record, dictionary)

        lock = self.dictionary[0]
        last = lock * MAX_SEGMENTS
        self.assertEqual(encode_capacity_record(last, self.dictionary), bytes([MAX_SEGMENTS]) + b"\x01" * MAX_SEGMENTS)
        self.assert_expands(last, encode_capacity_record(last, self.dictionary))
        for raw in (last + lock, last + b"literal" + lock, last + b"literal"):
            record = encode_capacity_record(raw, self.dictionary)
            self.assertEqual(record, b"\x01\x00" + compact(len(raw)) + raw)
            self.assert_expands(raw, record)

    def test_canonical_literal_widths_and_random_roundtrips(self):
        for size in (0, 252, 253, 65535, 65536):
            with self.subTest(size=size):
                raw = b"\x92" * size
                record = encode_capacity_record(raw, self.dictionary)
                self.assertEqual(record, b"\x01\x00" + compact(size) + raw)
                self.assert_expands(raw, record)

        random = Random(0)
        for _ in range(60):
            dictionary = (random.randbytes(random.randrange(2, 40)), random.randbytes(random.randrange(2, 40)))
            parts = (*dictionary, random.randbytes(17), b"")
            raw = b"".join(random.choice(parts) for _ in range(random.randrange(32)))
            self.assert_expands(raw, encode_capacity_record(raw, dictionary), dictionary)

    def test_rejects_malformed_wire_in_host_and_script(self):
        records = (
            b"", b"\x00", b"\x11", b"\x80", b"\xff",
            b"\x01", b"\x01\x03", b"\x01\x80", b"\x01\x00",
            b"\x01\x00\x02a", b"\x01\x00\xfd\xfd", b"\x01\x00\xfe\x00\x00\x01",
            b"\x01\x00\xfd\x01\x00a", b"\x01\x00\xfe\xfd\x00\x00\x00" + b"a" * 253,
            b"\x01\x00\xff" + b"\x00" * 8, b"\x01\x00\xfe\xff\xff\xff\xff",
            b"\x01\x01\x02", b"\x01\x00\x01ab", b"\x02\x01", b"\x02\x00\x01a",
        )
        for record in records:
            with self.subTest(record=record), self.assertRaises(ValueError):
                decode_capacity_record(record, self.dictionary)
            with self.subTest(record=record), self.assertRaises(ScriptError):
                evaluate(self.script, stack=[record, *self.dictionary])

        for record, dictionary in ((b"\x01\x01", (b"", b"abc")), (b"\x01\x02", (b"abc", b""))):
            with self.subTest(record=record), self.assertRaises(ValueError):
                decode_capacity_record(record, dictionary)
            with self.subTest(record=record), self.assertRaises(ScriptError):
                evaluate(self.script, stack=[record, *dictionary])


if __name__ == "__main__":
    unittest.main()
