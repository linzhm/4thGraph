from dataclasses import replace
from hashlib import sha256
import json
import lzma
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from parent_prefix import (
    BLOCK_BYTES, align_output_count, checkpoint_record, output_offsets, parent_prefix,
    sha256_checkpoint, sha256_continue,
)
from projects.groth16.reference.transfer import COMPACT_SCRIPTCODE
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, compact, hash256, preimage_all, preimage_otda


class ParentPrefixTests(unittest.TestCase):
    def test_align_output_count_uses_the_shortest_zero_push_at_the_selected_vin(self):
        # (script sizes, vin, shortest payload, CompactSize width before/after).
        cases = (
            ((175, 57), 0, 0, (1, 1)),     # OP_0 is sufficient.
            ((175, 58), 0, 63, (1, 1)),    # Aligned already, but still add one item.
            ((252, 12), 0, 30, (1, 3)),
            ((12, 65_535), 1, 25, (3, 5)),
            ((238, 44), 0, 139, (1, 3)),   # Both CompactSize and PUSHDATA1 skip a candidate alignment.
        )
        for sizes, vin, payload_size, widths in cases:
            with self.subTest(sizes=sizes, vin=vin):
                tx = Transaction(tuple(Input(bytes([i]) * 32, i, bytes([0x51]) * size, sequence=5 + i)
                                       for i, size in enumerate(sizes)), (Output(1_000, b"\x51"),), locktime=42)
                old = tx.inputs[vin].script
                aligned = align_output_count(tx, vin)
                expected = tx.with_script(vin, old + push(bytes(payload_size)))
                self.assertEqual(aligned, expected)
                self.assertEqual((len(compact(len(old))), len(compact(len(aligned.inputs[vin].script)))), widths)
                new_count, _ = output_offsets(aligned.serialize())
                self.assertEqual(new_count % BLOCK_BYTES, 0)
                for n in range(payload_size):
                    shorter = tx.with_script(vin, old + push(bytes(n)))
                    self.assertNotEqual(output_offsets(shorter.serialize())[0] % BLOCK_BYTES, 0)

    def test_aligned_archived_payments_keep_sighash_preimages_and_equal_suffix_lengths(self):
        path = Path(__file__).resolve().parents[1] / "fixtures/v3-secure-receipt-regtest.json.xz"
        with lzma.open(path, "rt") as stream:
            archive = json.load(stream)
        for label, payload_size in (("alice-to-bob", 21), ("bob-to-carol", 41)):
            with self.subTest(label=label):
                txid = archive["summary"]["transactions"][label]["txid"]
                ledger = archive["transactions"]
                raw = bytes.fromhex(ledger[txid])
                tx = Transaction.parse(raw)
                self.assertEqual(tx.txid(), txid)
                vin = len(tx.inputs) - 1
                aligned = align_output_count(tx, vin)
                self.assertNotEqual(aligned.txid(), txid)
                self.assertEqual(aligned, tx.with_script(vin, tx.inputs[vin].script + push(bytes(payload_size))))
                count, _ = output_offsets(raw)
                padded = aligned.serialize()
                padded_count, _ = output_offsets(padded)
                self.assertEqual(padded_count % BLOCK_BYTES, 0)
                self.assertEqual(padded[padded_count:], raw[count:])
                self.assertEqual(len(padded) - padded_count, 4_876)
                for i, item in enumerate(tx.inputs):
                    previous = Transaction.parse(bytes.fromhex(ledger[item.txid[::-1].hex()]))
                    spent = previous.outputs[item.vout]
                    code = COMPACT_SCRIPTCODE if i == 0 else spent.script
                    self.assertEqual(preimage_all(tx, i, spent.value, code), preimage_all(aligned, i, spent.value, code))
                    self.assertEqual(preimage_otda(tx, i, code, 0x61), preimage_otda(aligned, i, code, 0x61))

    def test_cli_generates_the_same_verified_record_from_hex_and_binary(self):
        tx = Transaction(
            (Input(b"p" * 32, 0, push(bytes(range(256))), sequence=9),),
            (Output(1000, asm("OP_1")), Output(2000, asm("OP_1"))),
        )
        raw = tx.serialize()
        record = checkpoint_record(raw)
        self.assertEqual(record["txid"], tx.txid())
        self.assertEqual(record["processed_bytes"], 256)
        self.assertEqual(record["output_count_offset"], 307)
        self.assertEqual(record["output_offsets"], [308, 318])
        self.assertEqual(bytes.fromhex(record["suffix"]), raw[256:])
        self.assertEqual(record["hash_outputs"], hash256(b"".join(x.serialize() for x in tx.outputs)).hex())
        command = [sys.executable, "-m", "recursion.parent_prefix"]
        root = Path(__file__).resolve().parents[3]
        with TemporaryDirectory() as directory:
            src = Path(directory) / "parent.hex"
            dest = Path(directory) / "checkpoint.json"
            src.write_text(raw.hex() + "\n")
            subprocess.run([*command, str(src), "--out", str(dest)], cwd=root, check=True)
            self.assertEqual(json.loads(dest.read_text()), record)
        result = subprocess.run([*command, "-", "--input-format", "raw"], input=raw,
                                capture_output=True, cwd=root, check=True)
        self.assertEqual(json.loads(result.stdout), record)

    def test_checkpoint_and_continuation_match_hashlib_at_padding_edges(self):
        raw = bytes(range(256)) + b"\xa5" * 80
        for length in (0, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 335, 336):
            for offset in range(0, length + 1, BLOCK_BYTES):
                with self.subTest(length=length, offset=offset):
                    state = sha256_checkpoint(raw[:offset])
                    self.assertEqual(sha256_continue(state, offset, raw[offset:length]), sha256(raw[:length]).digest())

        state = sha256_checkpoint(raw[:64])
        self.assertNotEqual(state, sha256(raw[:64]).digest())
        self.assertNotEqual(sha256_continue(state, 64, raw[64:]), sha256_continue(state, 128, raw[64:]))
        with self.assertRaises(ValueError):
            sha256_checkpoint(raw[:63])
        for candidate_state, count in ((state[:-1], 64), (state, -64), (state, 65), (state, True), (state, 1 << 61)):
            with self.subTest(count=count), self.assertRaises(ValueError):
                sha256_continue(candidate_state, count, raw[64:])

    def test_output_positions_use_canonical_wire_lengths(self):
        tx = Transaction((Input(bytes(32), 0, b"x" * 253), Input(bytes(32), 1, b"y" * 65_536)),
                         tuple(Output(i, b"z" * 253 if i == 2 else b"") for i in range(253)), locktime=1 << 24)
        raw = tx.serialize()
        count_offset = 4 + len(compact(len(tx.inputs))) + sum(len(item.serialize()) for item in tx.inputs)
        count, positions = output_offsets(raw)
        self.assertEqual(count, count_offset)
        self.assertEqual(positions[0], count_offset + 3)
        outputs = (*positions[1:], len(raw) - 4)
        for output, start, end in zip(tx.outputs, positions, outputs, strict=True):
            self.assertEqual(raw[start:end], output.serialize())

    def test_malformed_transaction_cannot_supply_output_boundary(self):
        tx = Transaction((Input(bytes(32), 1, b"x"),), (Output(1, b"y"),))
        raw = tx.serialize()
        count, (vout,) = output_offsets(raw)
        excess_value = (2_100_000_000_000_001).to_bytes(8, "little")
        invalid = (
            raw[:4] + b"\x00" + raw[5:],
            raw[:4] + b"\xfd\x01\x00" + raw[5:],
            raw[:41] + b"\xfd\x01\x00" + raw[42:],
            raw[:41] + b"\xfe\xff\xff\xff\xff" + raw[42:],
            raw[:count] + b"\x00" + raw[count + 1:],
            raw[:count] + b"\xfd\x01\x00" + raw[count + 1:],
            raw[:vout] + excess_value + raw[vout + 8:],
            raw[:vout + 8] + b"\xfd\x01\x00" + raw[vout + 9:],
            raw[:-5], raw[:-5] + raw[-4:], raw + b"\0",
        )
        for malformed in invalid:
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                output_offsets(malformed)

    def test_reference_uses_the_unpadded_state_of_an_archived_v3_parent(self):
        path = Path(__file__).resolve().parents[1] / "fixtures/v3-certified-cross-chain-regtest.json.xz"
        with lzma.open(path, "rt") as stream:
            archive = json.load(stream)
        name = "mint-1024"
        raw = bytes.fromhex(archive["transactions"][name])
        recorded = archive["summary"]["transactions"][name]["txid"]
        del archive
        tx = Transaction.parse(raw)
        count, starts = output_offsets(raw)
        self.assertEqual(raw[count:], compact(len(tx.outputs)) + b"".join(o.serialize() for o in tx.outputs) + raw[-4:])
        self.assertEqual(raw[starts[1]:starts[2]], tx.outputs[1].serialize())

        disclosure = parent_prefix(raw)
        self.assertEqual(disclosure.output_count_offset, count)
        self.assertEqual(disclosure.processed_bytes % BLOCK_BYTES, 0)
        self.assertLess(count - disclosure.processed_bytes, BLOCK_BYTES)
        self.assertEqual(disclosure.continued_txid_wire(), hash256(raw))
        self.assertEqual(disclosure.continued_txid_wire()[::-1].hex(), recorded)
        self.assertEqual(replace(disclosure, output_count_offset=count + 1).continued_txid_wire()[::-1].hex(), recorded)
        self.assertNotEqual(replace(disclosure, state=bytes(32)).continued_txid_wire()[::-1].hex(), recorded)
        self.assertNotEqual(replace(disclosure, suffix=disclosure.suffix[:-1] + b"\x01").continued_txid_wire()[::-1].hex(), recorded)


if __name__ == "__main__":
    unittest.main()
