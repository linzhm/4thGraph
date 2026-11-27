"""Check the independent Forth libraries and the composed reference lock."""

from dataclasses import replace
from hashlib import sha256
import os
from pathlib import Path
import unittest

from ecdsa import NIST256p, ellipticcurve

from compile_r1 import ENTRY_SOURCES, PELS_ENTRY, compile_source, describe_pels_blocks, emit_lock
from pels_r1 import prepare_authorization
from test_payment import fixture_signature, signer

from fourthgraph.benchmark.cases import seed
from fourthgraph.benchmark.validation import Node, chain_verdict
from fourthgraph.bsv.differential import require_chain_gang_pin
from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.bsv.script import asm, decode_num, encode_num, push
from fourthgraph.bsv.transaction import Input, Output, Transaction, hash256, preimage_forkid
from fourthgraph.compiler.script_builder import ScriptBuilder

HERE = Path(__file__).resolve().parent
CURVE = NIST256p.curve
GENERATOR = NIST256p.generator


def point_values(point):
    return (0, 0, 0) if point == ellipticcurve.INFINITY else (point.x(), point.y(), 1)


def funding(lock, label):
    return Transaction((Input(seed(label), 0),), (Output(10_000, lock),))


def unsigned_spend(parent, output):
    return Transaction((Input(parent.txid_wire(), 0),), (output,))


class PreparedAuthorizationTests(unittest.TestCase):
    def test_prepare_authorization_requires_one_successor_output(self):
        lock = push(bytes(5)) + asm("OP_CODESEPARATOR OP_1")
        parent = funding(lock, "pels-output-count")
        successor = Output(9_000, lock)
        tx = unsigned_spend(parent, successor)
        expected = hash256(preimage_forkid(tx, 0, parent.outputs[0].value, lock[7:], 0x41))
        self.assertEqual(prepare_authorization(tx, parent).digest, expected)

        for outputs in ((), (successor, Output(0, asm("OP_0 OP_RETURN")))):
            with self.subTest(output_count=len(outputs)), self.assertRaisesRegex(ValueError, "one successor output"):
                prepare_authorization(replace(tx, outputs=outputs), parent)


class R1MathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = ScriptBuilder.from_file(HERE / "r1-math-verify.fth")

    def run_word(self, entry, *values):
        script = self.builder.emit(entry, b"")
        main, alt = evaluate(script, list(map(encode_num, values)))
        self.assertEqual(alt, [])
        return tuple(map(decode_num, main))

    def test_inverse_and_affine_point_branches(self):
        for modulus in (CURVE.p(), NIST256p.order):
            for value in (1, 2, 98273472, modulus - 1):
                with self.subTest(modulus=modulus, value=value):
                    self.assertEqual(self.run_word("r1-inverse", modulus, value), (pow(value, -1, modulus),))
        field = CURVE.p(), CURVE.b()
        for left, right in ((0, 1), (1, 0), (1, 1), (1, NIST256p.order - 1), (2, 3)):
            with self.subTest(left=left, right=right):
                a, b = left * GENERATOR, right * GENERATOR
                self.assertEqual(self.run_word("r1-point-add", *field, *point_values(a), *point_values(b)),
                                 (*field, *point_values(a + b)))

    def test_independent_verifier_computes_inverse_and_checks_inputs(self):
        key, _, _ = signer(7)
        Q = 7 * GENERATOR
        digest = sha256(b"synthetic affine R1 math reference").digest()
        signature = fixture_signature(key, digest)
        r, s = (int.from_bytes(scalar, "big") for scalar in (signature[:32], signature[32:]))
        e = int.from_bytes(digest, "big")
        self.assertEqual(self.run_word("r1-verify", Q.x(), Q.y(), r, s, e), (1,))
        for x, y, first, second in ((0, 0, r, s), (CURVE.p(), Q.y(), r, s), (Q.x(), Q.y(), 0, s),
                                    (Q.x(), Q.y(), r, NIST256p.order)):
            with self.subTest(x=x, y=y, r=first, s=second), self.assertRaises(ScriptError):
                self.run_word("r1-verify", x, y, first, second, e)

    def test_artifact_reports_exact_word_boundaries(self):
        source = ENTRY_SOURCES[PELS_ENTRY]
        owner = bytes(20)
        compiler = compile_source(source.read_bytes(), owner, source_path=source)
        lock = emit_lock(compiler, PELS_ENTRY, 0)
        blocks = describe_pels_blocks(compiler, owner, 0, lock)
        self.assertEqual([block["word"] for block in blocks], ["r1-pels-state", "pels-verify", "r1-verify-owner"])
        self.assertEqual(sum(block["bytes"] for block in blocks), len(lock))
        for block in blocks:
            start = block["offset"]
            self.assertEqual(sha256(lock[start:start + block["bytes"]]).hexdigest(), block["sha256"])


@unittest.skipUnless(os.environ.get("REGTEST_COOKIE"), "requires the isolated regtest launcher")
class ComposedSpendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        require_chain_gang_pin(HERE.parents[2] / "tools/requirements-chronicle.txt")
        cls.node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])

    def verdict(self, tx, parent, expected):
        self.assertEqual(chain_verdict(tx, (parent,)), expected)
        self.assertEqual(self.node.verdicts(tx, (parent,), timeout_us=30_000), [expected])

    def test_standalone_pels_with_a_separate_rule(self):
        source = """
        REQUIRE pels-verify.fth
        : twice-and-pay ( script -- script )
            500 bsv-num op-sub op-8 op-num2bin
            op-swap op-bin2num op-2 op-add op-5 op-num2bin op-swap
        ;
        : pels-only ( script bytes -- script )
            bsv-push op-codeseparator bsv-empty twice-and-pay pels-verify op-drop op-1
        ;
        """
        builder = ScriptBuilder(source, source_path=HERE / "pels-only-test.fth")
        previous = funding(builder.emit("pels-only", b"", bytes(5)), "pels-only")
        for next_state in (2, 1):
            output = Output(9_500, builder.emit("pels-only", b"", next_state.to_bytes(5, "little")))
            tx = unsigned_spend(previous, output)
            authorization = prepare_authorization(tx, previous)
            unlock = push(authorization.tail) + push(authorization.head)
            self.verdict(tx.with_script(0, unlock), previous, next_state == 2)

    def test_counter_authorization_and_independent_rejections(self):
        key, public, owner = signer(7)
        source = ENTRY_SOURCES[PELS_ENTRY]
        compiler = compile_source(source.read_bytes(), owner, source_path=source)
        previous = funding(emit_lock(compiler, PELS_ENTRY, 0), "pels-r1-composition")

        def spend(parent, state, value, *, wrong_signature=False):
            tx = unsigned_spend(parent, Output(value, emit_lock(compiler, PELS_ENTRY, state)))
            auth = prepare_authorization(tx, parent)
            previous_output = parent.outputs[0]
            expected_digest = hash256(preimage_forkid(tx, 0, previous_output.value, previous_output.script[7:], 0x41))
            self.assertEqual(auth.digest, expected_digest)
            digest = sha256(auth.digest).digest() if wrong_signature else auth.digest
            unlock = auth.unlocking_script(public, fixture_signature(key, digest))
            return tx.with_script(0, unlock)

        first = spend(previous, 1, 9_000)
        self.verdict(first, previous, True)
        self.verdict(spend(first, 2, 8_000), first, True)
        # Freshly sign a different successor, then use a valid successor with a wrong R1 signature.
        self.verdict(spend(first, 3, 8_000), first, False)
        self.verdict(spend(first, 2, 8_000, wrong_signature=True), first, False)
