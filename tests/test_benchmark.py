"""Verification controls for benchmark inventory and serialization."""
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fourthgraph.benchmark.run import collect, summarize
from fourthgraph.benchmark.cases import MODES, Leg, Template
from fourthgraph.benchmark.validation import AcceptanceResult, measure_leg, stack_profile
from fourthgraph.bsv.transaction import Input, Output, Transaction


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.template = Template(lambda *_: None)
        self.name = "demo/template"
        self.scenarios = {}
        for mode in MODES:
            base = f"{self.name}/{mode:02x}/"
            for shape, size in (("2x2", 10), ("3x2", 12), ("2x3", 16)):
                self.scenarios[base + "batch/" + shape] = {"payment": {"transaction_bytes": size}}
            legs = {"funding": {"transaction_bytes": 1}, "exit": {"transaction_bytes": 3}}
            self.scenarios[base + "direct-exit"] = legs
            self.scenarios[base + "turnover"] = dict(legs, turnover={"transaction_bytes": 10})

    def test_marginals_and_lifecycle_combine_serialized_transactions(self):
        row = summarize(self.template, self.name, self.scenarios)["41"]
        self.assertEqual((row["extra_input_bytes"], row["extra_output_bytes"]), (2, 6))
        self.assertEqual(row["lifecycle_total_bytes"], {"direct-exit": 4, "turnover": 14})

    def test_missing_case_and_phase_fail_inventory(self):
        with self.assertRaisesRegex(ValueError, "missing"):
            summarize(self.template, self.name, dict(list(self.scenarios.items())[1:]))
        self.scenarios[f"{self.name}/41/direct-exit"].pop("exit")
        with self.assertRaisesRegex(ValueError, "incomplete"):
            summarize(self.template, self.name, self.scenarios)

    @patch("fourthgraph.benchmark.run.measure_leg", return_value={})
    def test_duplicate_case_is_rejected(self, _measure):
        row = ("fixture", {"payment": None})
        with patch("fourthgraph.benchmark.run.workloads", return_value=[row, row]):
            with self.assertRaisesRegex(ValueError, "duplicate cost scenario"):
                collect(self.template, self.name, Path("."), None, 0, False)

    def test_recorder_detects_duplicate_subtests(self):
        record = AcceptanceResult(StringIO(), False, 0)
        case = SimpleNamespace(id=lambda: "a.valid.subtest")
        record.record(case, "pass")
        record.record(case, "pass")
        self.assertEqual(record.duplicates, {"a.valid.subtest"})

    def test_failed_verdict_or_roundtrip_is_rejected(self):
        parent = Transaction((Input(bytes(32), 0),), (Output(500, b"\x51"),))
        tx = Transaction((Input(parent.txid_wire(), 0),), (Output(400, b"\x51"),))
        leg = Leg(tx, (parent,), (0x41,))
        with patch("fourthgraph.benchmark.validation.chain_verdict", return_value=False):
            with self.assertRaisesRegex(ValueError, "failed verification"):
                measure_leg(leg, None)
        with patch.object(Transaction, "parse", return_value=parent):
            with self.assertRaisesRegex(ValueError, "round-trip"):
                measure_leg(leg, None)

    def test_stack_measurement_includes_altstack(self):
        # Push 1, move it to the alt stack, and restore it.
        measured = stack_profile(b"\x6b\x6c", b"\x51")
        self.assertEqual(measured["main_items"], 1)
        self.assertEqual(measured["alt_items"], 1)
        self.assertEqual(measured["combined_payload_bytes"], 1)
