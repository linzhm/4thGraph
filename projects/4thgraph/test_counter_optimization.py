from dataclasses import replace
from hashlib import sha256
import unittest

from compiler import ParentOutput, SourceCompiler
from examples.pels_counter import FULL_PREIMAGE, LINKED, RECONSTRUCTED, REUSED, SOURCE, TRANSITION, counter_builds
from forkid_lowering import ALL, pack_context, reconstructed_context, repeated_fragment
from pels_constraints import FeeConstraint, PelsSource, WitnessAmount
from shared.evaluate import ScriptError, evaluate
from shared.pushtx import N, PUBLIC, R, binding_der, fixed_key_checksig
from shared.script import asm, encode_num
from shared.transaction import Input, Output, Transaction, preimage_forkid


class CounterOptimizationTests(unittest.TestCase):
    def test_counter_candidates_preserve_the_previous_locks(self):
        advance = SourceCompiler(SOURCE.read_text()).words["advance"]
        _, candidates = counter_builds(advance)
        self.assertEqual(len(candidates), 12)
        previous = {
            ("baseline", FULL_PREIMAGE): "8b757966d492adfadb003bd7e5d0766fa44261d5034da10fed85befd31367917",
            ("baseline", RECONSTRUCTED): "c6e0d8ce9650a0684d2840daecdb56a3b19845ef01f0e38a4e9266da070f8b07",
            ("compact", FULL_PREIMAGE): "804d9eb559ba4aab63311cf6261d056abc8c3ca376d440ddae458ff6917c10b8",
            ("compact", RECONSTRUCTED): "69cd1a834142cab357a0d6bcaec3802380b3d51cc78d05324e9b04fa538f6e73",
            ("compact-reuse-r", LINKED): "2fa1b1f552284b9252f8114a678ddf163d164ae40bef55665f9b42296c159899",
        }
        digests = {(build.authentication, build.witness): sha256(build.root.script).hexdigest()
                   for build in candidates}
        self.assertEqual(len(set(digests.values())), len(candidates))
        self.assertEqual({layout: digests[layout] for layout in previous}, previous)
        best = min(candidates, key=lambda candidate: candidate.describe()["path_bytes"])
        self.assertEqual((best.authentication, best.witness), ("compact-reuse-r", REUSED))

    def test_reconstruction_requires_single_input_forkid_all_and_exact_output(self):
        output_hash = asm("OP_HASH256")
        extra_input = replace(TRANSITION, inputs=(*TRANSITION.inputs, ParentOutput("sponsor", 0)))
        extra_output = replace(TRANSITION, outputs=(*TRANSITION.outputs, "change"))
        self.assertIsNotNone(reconstructed_context(TRANSITION, ALL, output_hash))
        self.assertIsNone(reconstructed_context(extra_input, ALL, output_hash))
        self.assertIsNone(reconstructed_context(extra_output, ALL, output_hash))
        self.assertIsNone(reconstructed_context(TRANSITION, 0x43, output_hash))
        self.assertIsNone(reconstructed_context(TRANSITION, ALL, b""))

    def test_packed_context_rejects_a_two_input_preimage(self):
        tx = Transaction((Input(b"\x01" * 32, 0), Input(b"\x02" * 32, 0)), (Output(1, b""),))
        preimage = preimage_forkid(tx, 0, 2, b"", ALL)
        with self.assertRaisesRegex(ValueError, "single input"):
            pack_context(preimage)

    def test_linked_context_omits_compact_size_at_the_width_boundary(self):
        tx = Transaction((Input(b"\x01" * 32, 0),), (Output(1, b""),))
        for size, header_width, other_size in ((252, 1, 253), (253, 3, 252)):
            with self.subTest(size=size):
                preimage = preimage_forkid(tx, 0, 2, b"\x61" * size, ALL)
                self.assertEqual(len(pack_context(preimage)) - len(pack_context(preimage, script_size=size)),
                                 header_width)
                with self.assertRaisesRegex(ValueError, "scriptCode size"):
                    pack_context(preimage, script_size=other_size)

    def test_reused_fragment_reconstructs_script_code_in_its_original_position(self):
        tx = Transaction((Input(b"\x01" * 32, 0),), (Output(1, b""),))
        repeated = b"\x51\x7f" * 62
        parts = (b"\x61" * 23, repeated, b"\x75", repeated, b"\xac")
        code = b"".join(parts)
        reuse = repeated_fragment(parts)
        preimage = preimage_forkid(tx, 0, 2, code, ALL)
        full = pack_context(preimage, script_size=len(code))
        compact = pack_context(preimage, script_size=len(code), reuse=reuse)
        self.assertEqual(len(full) - len(compact), len(repeated))
        self.assertEqual(evaluate(reuse.decoder(), [full[:1], compact]), ([full[:1], full], []))

        changed = code[:reuse.repeated] + b"\0" + code[reuse.repeated + 1:]
        with self.assertRaisesRegex(ValueError, "same emitted fragment"):
            pack_context(preimage_forkid(tx, 0, 2, changed, ALL), script_size=len(code), reuse=reuse)

    def test_compact_der_preserves_signed_length_boundaries_and_zero_rejection(self):
        original, compact = binding_der(), binding_der(compact=True)
        self.assertLess(len(compact), len(original))
        for s in (1, 127, 128, 255, 256, N // 2, N - 1):
            digest = ((s - R) % N).to_bytes(32, "big")
            with self.subTest(s=s):
                self.assertEqual(evaluate(compact, [digest]), evaluate(original, [digest]))
        digest = ((N - R) % N).to_bytes(32, "big")
        for script in (original, compact):
            with self.assertRaises(ScriptError):
                evaluate(script, [digest])

    def test_shared_r_emits_the_same_signature_and_public_key(self):
        script = fixed_key_checksig(ALL, compact=True, reuse_r=True)
        for s in (1, 128, 256, N // 2, N - 1):
            digest = ((s - R) % N).to_bytes(32, "big")
            der, _ = evaluate(binding_der(compact=True), [digest])
            signature = der[0] + bytes([ALL])
            with self.subTest(s=s):
                result = evaluate(script, [digest], lambda sig, key: sig == signature and key == PUBLIC)
                self.assertEqual(result, ([b"\x01"], []))

    def test_fee_declaration_only_uses_witness_for_an_interval(self):
        source = PelsSource("pels-fee: 1000 2000 ;\n" + SOURCE.read_text())
        self.assertEqual(source.amount_rule, FeeConstraint(1000, 2000))
        self.assertTrue(source.amount_rule.takes_witness)
        self.assertFalse(PelsSource("pels-fee: 1000 1000 ;").amount_rule.takes_witness)
        with self.assertRaisesRegex(ValueError, "line 1.*ordered fee bounds"):
            PelsSource("pels-fee: 2000 1000 ;")

    def test_bounded_fee_assertion_consumes_and_checks_the_claim(self):
        rule = FeeConstraint(1000, 2000)
        state, code, amount = b"\x07", b"\x61", 10_000
        operands = [state, code, amount.to_bytes(8, "little")]
        for fee in (1000, 2000):
            result, alt = evaluate(rule.lower_amount(), [encode_num(fee), *operands])
            self.assertEqual(result, [state, code, (amount - fee).to_bytes(8, "little")])
            self.assertEqual(alt, [])
        for fee in (999, 2001):
            with self.assertRaises(ScriptError):
                evaluate(rule.lower_amount(), [encode_num(fee), *operands])

    def test_witness_amount_leaves_fee_to_transaction_construction(self):
        rule = PelsSource("pels-amount: witness ;").amount_rule
        self.assertIsInstance(rule, WitnessAmount)
        old_amount = 10_000
        state, code = b"\x07", b"\x61"
        for next_amount in (10_000, 9_219, 6_150, 0):
            claimed = next_amount.to_bytes(8, "little")
            stack = [claimed, state, code, old_amount.to_bytes(8, "little")]
            self.assertEqual(evaluate(rule.lower_amount(), stack), ([state, code, claimed], []))
        with self.assertRaises(ScriptError):
            evaluate(rule.lower_amount(), [b"\0" * 7, state, code, old_amount.to_bytes(8, "little")])


if __name__ == "__main__":
    unittest.main()
