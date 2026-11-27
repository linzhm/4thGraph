"""Check constructor legality, byte equality and reproducible selection."""
import json
import subprocess
import sys
import unittest
from dataclasses import replace
from hashlib import sha256
from random import Random

from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.otda_reconstruction import Reconstruction, push_repeated_bytes
from fourthgraph.bsv.spend_authorization import prepare_authorization
from fourthgraph.bsv.transaction import Input, Output, Transaction, hash256
from fourthgraph.compiler.preimage import compile_preimage
from fourthgraph.workflow.preimage_constructor import build


CODE = bytes.fromhex("68ac")


class PreimageConstructorTests(unittest.TestCase):
    def setUp(self):
        shared = Random(340).randbytes(1_000)
        self.patterns = tuple(Reconstruction(push_repeated_bytes(prefix) + push_repeated_bytes(suffix),
                                             (prefix, suffix), (20,))
                              for prefix, suffix in ((b"first", b"left" + shared),
                                                     (b"second", b"right" + shared)))
        outputs = tuple(Output(400, prefix + bytes((i,)) * 20 + suffix)
                        for i, (prefix, suffix) in enumerate(p.fixed_parts for p in self.patterns))
        self.parent = Transaction((Input(bytes(32), 1),), (Output(1_000, CODE),))
        self.tx = Transaction((Input(self.parent.txid_wire(), 0),), outputs)

    def auth(self, tx, flag):
        return prepare_authorization(tx, 0, 1_000, flag, ordinary_code=CODE, companion_code=b"\x51")

    def test_selects_byte_exact_shared_template_with_serialized_cost(self):
        auth = self.auth(self.tx, 0x61)
        plan = compile_preimage(self.tx, 0, auth, self.patterns, chronicle_active=True, witness_tail_bytes=163)
        self.assertEqual(plan.selected, "mixed/shared")
        self.assertEqual(evaluate(plan.program, [b"caller"]), ([b"caller", auth.preimage], []))
        picked = next(row for row in plan.candidates if row["name"] == plan.selected)
        other = next(row for row in plan.candidates if row["name"] == "mixed/repeated")
        self.assertLess(picked["input_field_bytes"], other["input_field_bytes"])
        self.assertEqual(picked["sha256"], sha256(plan.program).hexdigest())

    def test_neither_family_nor_era_changes_during_selection(self):
        for tx, flag, active in ((self.tx, 0x41, True), (self.tx, 0x62, True),
                                 (replace(self.tx, version=1), 0x61, True), (self.tx, 0x61, False)):
            with self.subTest(version=tx.version, flag=flag, active=active):
                auth = self.auth(tx, flag)
                plan = compile_preimage(tx, 0, auth, self.patterns, chronicle_active=active)
                self.assertEqual(plan.selected, "literal")
                self.assertEqual(evaluate(plan.program), ([auth.preimage], []))
                self.assertFalse(plan.candidates[1]["eligible"])

    def test_wrong_template_program_is_excluded(self):
        bad_pattern = replace(self.patterns[0], program=b"\x00\x00")
        auth = self.auth(self.tx, 0x63)
        plan = compile_preimage(self.tx, 0, auth, (bad_pattern,), chronicle_active=True)
        rejected = next(row for row in plan.candidates if row["name"] == "template-0/repeated")
        self.assertFalse(rejected["eligible"])
        self.assertIn("complete preimage", rejected["reason"])
        self.assertEqual(evaluate(plan.program), ([auth.preimage], []))

    def test_payload_limit_excludes_large_copy(self):
        tx = replace(self.tx, outputs=(Output(800, bytes(range(32)) * 33),))
        auth = self.auth(tx, 0x61)
        limit = len(auth.preimage)
        best = compile_preimage(tx, 0, auth, chronicle_active=True)
        bounded = compile_preimage(tx, 0, auth, chronicle_active=True, max_payload_bytes=limit)
        self.assertEqual(best.selected, "repeat-preimage")
        self.assertEqual(bounded.selected, "literal")
        self.assertIn("payload limit", bounded.candidates[1]["reason"])
        with self.assertRaisesRegex(ValueError, "no preimage encoding"):
            compile_preimage(tx, 0, auth, chronicle_active=True, max_payload_bytes=limit - 1)

    def test_cli_uses_the_approved_parent_and_full_signing_digest(self):
        request = {"parent_hex": self.parent.serialize().hex(), "transaction_hex": self.tx.serialize().hex(),
                   "input_index": 0, "sighash": 0x61, "script_code_hex": CODE.hex(), "chronicle_active": True,
                   "witness_tail_bytes": 163}
        result = build(request)
        cli = subprocess.run((sys.executable, "-m", "fourthgraph.workflow.protocol", "preimage-constructor", "-"),
                             input=json.dumps(request), capture_output=True, text=True, check=True)
        self.assertEqual(result, json.loads(cli.stdout))
        preimage = self.auth(self.tx, 0x61).preimage
        self.assertEqual(result["signing_digest_sha256d"], hash256(preimage).hex())
        self.assertEqual(evaluate(bytes.fromhex(result["program_hex"])), ([preimage], []))
        other = replace(self.parent, locktime=1)
        with self.assertRaisesRegex(ValueError, "spend the supplied parent"):
            build(dict(request, parent_hex=other.serialize().hex()))
