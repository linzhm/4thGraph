"""Check the Forth reference arithmetic and both complete baseline lock entries."""

from dataclasses import replace
from hashlib import sha256
from importlib.metadata import PackageNotFoundError
import os
from pathlib import Path
import unittest

from ecdsa import NIST256p, ellipticcurve

from compile_r1 import (COUNTER_ENTRY, ENTRY_SOURCES, MAX_AUTO_CANDIDATES, MAX_AUTO_ROUNDS, PAYMENT_ENTRY,
                        baseline_plans, compile_auto, compile_source, emit_lock, select_baseline_plan)
from curve_compiler import B3, FIELD
from signature import SpendAuthorization, authorization, current_input_unlock
from test_payment import fixture_signature, signer

from fourthgraph.benchmark.cases import seed
from fourthgraph.benchmark.validation import CONTEXT_PIN, Node, chain_metadata, chain_verdict
from fourthgraph.bsv.chain_gang import engine_transaction
from fourthgraph.bsv.differential import require_chain_gang_pin
from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.bsv.script import asm, decode_num, encode_num, push
from fourthgraph.bsv.transaction import Input, Output, Transaction, preimage_forkid
from fourthgraph.compiler.script_builder import ScriptBuilder


def builder(entry, owner=bytes(20)):
    source = ENTRY_SOURCES[entry]
    return compile_source(source.read_bytes(), owner, source_path=source)


def parent(script, label, value=10_000):
    return Transaction((Input(seed(label), 0),), (Output(value, script),))


def sign(tx, index, auth, key, public):
    signature = fixture_signature(key, auth.digest())
    witness = current_input_unlock(auth, public, signature)
    return tx.with_script(index, witness.raw_serialize())


class BaselineTests(unittest.TestCase):
    def test_scalar_multiplication(self):
        script = builder(PAYMENT_ENTRY).emit("r1-baseline-scalar-multiply", b"")
        point = 7 * NIST256p.generator
        for scalar in (0, 1, 2, 3, 1000, 1 << 255, NIST256p.order - 1):
            with self.subTest(scalar=scalar):
                stack = tuple(map(encode_num, (FIELD, B3, scalar, point.x(), point.y(), 1)))
                main, alt = evaluate(script, stack)
                p, b3, x, y, z = map(decode_num, main)
                self.assertEqual((p, b3, alt), (FIELD, B3, []))
                expected = scalar * point
                if expected == ellipticcurve.INFINITY:
                    self.assertEqual((x % FIELD, z % FIELD), (0, 0))
                    self.assertNotEqual(y % FIELD, 0)
                else:
                    self.assertNotEqual(z % FIELD, 0)
                    self.assertEqual((x - expected.x() * z) % FIELD, 0)
                    self.assertEqual((y - expected.y() * z) % FIELD, 0)
        main, alt = evaluate(script, tuple(map(encode_num, (FIELD, B3, 17, 0, 1, 0))))
        _, _, x, y, z = map(decode_num, main)
        self.assertEqual((x % FIELD, z % FIELD, alt), (0, 0, []))
        self.assertNotEqual(y % FIELD, 0)

    def test_pels_fragment_accepts_another_rule_and_canonical_script_lengths(self):
        # Embed the PELS fragment independently of R1. This checks the output
        # assertion only. Full transaction binding is exercised below.
        source = """
        REQUIRE pels-successor.fth
        : test-rule ( script -- script )
            57 bsv-num op-sub op-8 op-num2bin
            op-swap op-bin2num op-2 op-add op-5 op-num2bin op-swap
        ;
        : test-output ( script -- script )
            bsv-empty test-rule pels-assert-successor op-1
        ;
        """
        path = ENTRY_SOURCES[COUNTER_ENTRY].with_name("pels-fragment-test.fth")
        script = ScriptBuilder(source, source_path=path).emit("test-output", b"")
        for size in (160, 246, 253, 32_768, 65_535, 65_536):
            with self.subTest(script_code_bytes=size):
                code = asm("OP_NOP") * size
                previous = parent(b"", "reusable-pels")
                successor = Output(9_943, push((12).to_bytes(5, "little")) + asm("OP_CODESEPARATOR") + code)
                unsigned = Transaction((Input(previous.txid_wire(), 0),), (successor,))
                preimage = preimage_forkid(unsigned, 0, 10_000, code, 0x41)
                self.assertEqual(evaluate(script, [(10).to_bytes(5, "little"), preimage]), ([b"\x01"], []))
                wrong = replace(unsigned, outputs=(replace(successor, value=9_942),))
                wrong_preimage = preimage_forkid(wrong, 0, 10_000, code, 0x41)
                with self.assertRaises(ScriptError):
                    evaluate(script, [(10).to_bytes(5, "little"), wrong_preimage])

    def test_counter_state_is_fixed_width_and_in_range(self):
        compiled = builder(COUNTER_ENTRY)
        body = compiled.emit("r1-counter-body", b"")
        for state in (0, 1, 2**32 - 1):
            self.assertEqual(emit_lock(compiled, COUNTER_ENTRY, state),
                             push(state.to_bytes(5, "little")) + asm("OP_CODESEPARATOR") + body)
        for state in (None, -1, 2**32):
            with self.assertRaisesRegex(ValueError, "unsigned 32-bit"):
                emit_lock(compiled, COUNTER_ENTRY, state)


class BaselineAutoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_path = ENTRY_SOURCES[PAYMENT_ENTRY]
        cls.source = cls.source_path.read_bytes()
        cls.key, cls.public, cls.owner = signer(7)
        cls.raw, cls.optimized, cls.candidates, cls.region = baseline_plans(
            cls.source, cls.owner, rounds=MAX_AUTO_ROUNDS)

    def test_automatic_selection_preserves_the_payment_boundaries(self):
        self.assertEqual(self.region["status"], "matched")
        self.assertEqual((len(self.candidates["baseline"]), len(self.candidates["formula"])), (415058, 139333))
        self.assertEqual(self.candidates["baseline"], emit_lock(self.raw, PAYMENT_ENTRY))
        self.assertEqual(self.candidates["formula"], emit_lock(self.optimized, PAYMENT_ENTRY))
        first_round = self.region["search"]["rounds"][0]
        self.assertEqual(len(first_round["candidates"]), 6)
        self.assertEqual(first_round["best"], "split-5x4-affine-g-ifdup")
        before = self.optimized.emit("r1-prepare-scalars", self.optimized.emit("r1-prepare-lock", b""))
        after = self.optimized.emit("r1-bind-transaction", self.optimized.emit("r1-baseline-check-x", b""))
        for name, span in self.region["fragments"].items():
            with self.subTest(plan=name):
                script = self.candidates[name]
                start, end = span["offset"], span["offset"] + span["bytes"]
                self.assertEqual(script[:start], before)
                self.assertEqual(script[end:], after)
                self.assertEqual(sha256(script[start:end]).hexdigest(), span["sha256"])

    def test_rounds_expand_without_repeats_and_respect_the_candidate_budget(self):
        search = self.region["search"]
        rounds = search["rounds"]
        names = [name for row in rounds for name in row["candidates"]]
        self.assertGreater(len(rounds), 1)
        self.assertEqual(search["stop"], "candidate_budget")
        self.assertEqual(len(names), MAX_AUTO_CANDIDATES)
        self.assertEqual(names, list(self.candidates))
        seen = {}
        for row in rounds:
            seen.update((name, self.candidates[name]) for name in row["candidates"])
            best = select_baseline_plan(seen)
            self.assertEqual((row["best"], row["best_lock_bytes"]), (best, len(seen[best])))

    def test_distinct_source_uses_the_existing_formula_path(self):
        _, script, report = compile_auto(self.source + b"\n( local revision )\n", self.owner, rounds=4)
        self.assertEqual(report["window_region"]["status"], "ineligible")
        self.assertEqual(report["window_region"]["search"]["stop"], "ineligible")
        self.assertEqual(list(report["candidates"]), ["baseline", "formula"])
        self.assertEqual(report["selected"], "formula")
        self.assertEqual(script, self.candidates["formula"])

    def test_complete_spends_under_chain_gang(self):
        try:
            engine = chain_metadata()
        except PackageNotFoundError:
            self.skipTest("requires pinned chain-gang")
        if engine["commit"] != CONTEXT_PIN:
            self.skipTest("requires pinned chain-gang")
        for name, script in self.candidates.items():
            previous = parent(script, "baseline-payment")
            unsigned = Transaction((Input(previous.txid_wire(), 0),), (Output(9_000, asm("OP_1")),))
            for flag in (0x41, 0x61, 0x63):
                with self.subTest(plan=name, flag=flag):
                    auth = authorization(engine_transaction(unsigned), 0, 10_000, flag)
                    tx = sign(unsigned, 0, auth, self.key, self.public)
                    self.assertTrue(chain_verdict(tx, (previous,)))
                    self.assertFalse(chain_verdict(replace(tx, locktime=1), (previous,)))


@unittest.skipUnless(os.environ.get("REGTEST_COOKIE"), "requires the isolated regtest launcher")
class BaselineSpendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        require_chain_gang_pin(Path(__file__).resolve().parents[3] / "tools/requirements-chronicle.txt")
        cls.node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
        cls.key, cls.public, cls.owner = signer(7)

    def verdict(self, tx, parents, expected):
        self.assertEqual(self.node.verdicts(tx, parents, timeout_us=100_000), expected)
        self.assertEqual(chain_verdict(tx, parents), all(expected))

    def test_payment_and_unpaired_single(self):
        lock = emit_lock(builder(PAYMENT_ENTRY, self.owner), PAYMENT_ENTRY)
        previous = parent(lock, "baseline-payment")
        unsigned = Transaction((Input(previous.txid_wire(), 0),), (Output(9_000, asm("OP_1")),))
        for flag in (0x41, 0x61):
            with self.subTest(flag=flag):
                auth = authorization(engine_transaction(unsigned), 0, 10_000, flag)
                tx = sign(unsigned, 0, auth, self.key, self.public)
                self.verdict(tx, (previous,), [True])
                self.verdict(replace(tx, locktime=1), (previous,), [False])
        sponsor = parent(asm("OP_1"), "baseline-sponsor")
        unsigned = replace(unsigned, inputs=(Input(sponsor.txid_wire(), 0), *unsigned.inputs))
        auth = authorization(engine_transaction(unsigned), 1, 10_000, 0x63)
        self.assertTrue(auth.companion)
        tx = sign(unsigned, 1, auth, self.key, self.public)
        self.verdict(tx, (sponsor, previous), [True, True])
        self.verdict(replace(tx, locktime=1), (sponsor, previous), [True, False])

    def test_counter_and_freshly_signed_invalid_successors(self):
        compiled = builder(COUNTER_ENTRY, self.owner)
        code = compiled.emit("r1-counter-body", b"")
        previous = parent(emit_lock(compiled, COUNTER_ENTRY, 0), "baseline-counter")

        def next_output(value, state):
            return Output(value, emit_lock(compiled, COUNTER_ENTRY, state))

        def authorize(outputs):
            unsigned = Transaction((Input(previous.txid_wire(), 0),), outputs)
            preimage = preimage_forkid(unsigned, 0, previous.outputs[0].value, code, 0x41)
            return sign(unsigned, 0, SpendAuthorization(0x41, preimage, False), self.key, self.public)

        first = authorize((next_output(9_000, 1),))
        self.verdict(first, (previous,), [True])
        previous = first
        second = next_output(8_000, 2)
        self.verdict(authorize((second,)), (previous,), [True])
        invalid_outputs = {
            "state": (next_output(8_000, 3),),
            "value": (replace(second, value=7_999),),
            "code": (replace(second, script=second.script + asm("OP_NOP")),),
            "extra output": (second, Output(1, asm("OP_1"))),
        }
        for name, outputs in invalid_outputs.items():
            with self.subTest(invalid=name):
                self.verdict(authorize(outputs), (previous,), [False])
