"""Check the Forth build against the original verifier and its typed ABI."""

from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import unittest

from fourthgraph.verification.bls12381.verifier import (
    FIELD_BYTES, HOST, Q, R, Curve, Dynamic, ScriptVerifier, bind_public_output, input_sources, public_output,
    public_packet,
)
from fourthgraph.verification.bls12381.build import ArithmeticPlan, ForthVerifier, SOURCE, layout_candidates, select_layout
from fourthgraph.compiler.source import CompileError
from fourthgraph.workflow.protocol import artifact_digest
from fourthgraph.replay.bls12381_verifier import SOURCES, fixture
from fourthgraph.bsv.chain_gang import validate_at_heights
from fourthgraph.bsv.script import asm, push
from fourthgraph.bsv.transaction import blob, preimage_all
from fourthgraph.stdlib import GROTH16_ENTRY, LEGACY_GROTH16_ENTRY, capabilities
from .test_backend import check_spend, g1_json, g2_json, spend_fixture


HIGH_LEVEL = (Path(__file__).resolve().parents[2]
              / "projects/groth16-verifier/experiments/high-level/verifier.fth")


class ForthVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key, cls.cases = fixture()
        cls.source = SOURCE.read_bytes()

    def test_compact_and_baseline_fixed_hybrid_and_dynamic(self):
        verifier = ForthVerifier(self.key, self.source)
        original = ScriptVerifier(self.key)
        signals, proof = self.cases[0]
        for sources in (signals, SOURCES[:3] + signals[3:], SOURCES):
            with self.subTest(sources=sources):
                suffix = asm("OP_VERIFY OP_1")
                baseline = verifier.compile(sources, compact=False)
                self.assertEqual(baseline, original.compile(sources, compact=False) + suffix)
                lock = verifier.compile(sources)
                self.assertLess(len(lock), len(original.compile(sources) + suffix))
                witness = original.witness(signals, proof, sources=sources)
                self.assertEqual(verifier.witness(signals, proof, sources=sources), witness)
                for script in (baseline, lock):
                    check_spend(*spend_fixture(script, witness))
                artifact = verifier.artifact(sources, None, lock)
                self.assertEqual(artifact["source_sha256"], sha256(self.source).hexdigest())
                self.assertEqual(artifact["artifact_sha256"], artifact_digest(artifact))
                self.assertEqual(artifact["forth_entry"], GROTH16_ENTRY)
                self.assertEqual(artifact["stack_schedule"], "compact")

    def test_legacy_source_and_module_share_the_asserting_verifier(self):
        current = ForthVerifier(self.key, b"REQUIRE groth16-bls12-381/verifier.fth")
        legacy_source = self.source.replace(GROTH16_ENTRY.encode(), LEGACY_GROTH16_ENTRY.encode())
        legacy = ForthVerifier(self.key, legacy_source)
        (signals, proof), (other_signals, other_proof) = self.cases
        lock = current.compile(signals)
        self.assertEqual(lock, legacy.compile(signals))
        artifact = current.artifact(signals, None, lock)
        interface = capabilities()["std/groth16-bls12-381"]
        self.assertEqual(artifact["entry_interface"], interface["interfaces"][GROTH16_ENTRY])
        self.assertEqual(artifact["verification_key_sha256"], sha256(self.key.encode()).hexdigest())
        self.assertEqual(artifact["entry_interface_sha256"], interface["interface_sha256"])
        imports = {library["name"]: library for library in artifact["libraries"]}
        self.assertEqual(set(imports), {"std/bsv", "std/groth16-bls12-381"})
        self.assertEqual(imports["std/groth16-bls12-381"]["interface_sha256"], interface["interface_sha256"])

        continuation = lock + asm("OP_DROP OP_1")
        parent, spend = spend_fixture(continuation, current.witness(signals, proof))
        check_spend(parent, spend)
        parent, spend = spend_fixture(continuation, current.witness(other_signals, other_proof))
        with self.assertRaises((RuntimeError, ValueError)):
            check_spend(parent, spend)

    def test_reordered_source_changes_lowering(self):
        original = b"bls12-381-check-public-inputs\n    swap bls12-381-check-g1-points"
        reordered = b"swap bls12-381-check-g1-points\n    swap bls12-381-check-public-inputs swap"
        verifier = ForthVerifier(self.key, self.source.replace(original, reordered))
        baseline = ForthVerifier(self.key, self.source)
        self.assertNotEqual(verifier.compile(SOURCES), baseline.compile(SOURCES))

    def test_reports_missing_stage_at_pairing_preparation(self):
        invalid = self.source.replace(b"swap bls12-381-check-g1-points", b"swap")
        with self.assertRaisesRegex(CompileError, r"line 5, column 3: body leaves .*groth16-checked-g1"):
            ForthVerifier(self.key, invalid)

    def test_modular_forth_reuses_the_same_script_and_can_pair_g1_doublings(self):
        modular = HIGH_LEVEL.parents[2] / "forth/verifier.fth"
        plan = ArithmeticPlan(residue_association="accumulator-frobenius-first",
                              msm="signed-radix4", msm_table="deferred-doubling-slopes",
                              miller_reductions="split-chord-residue", miller_kernel="direct-normalized")
        old = ForthVerifier(self.key, HIGH_LEVEL.read_bytes(), source_path=HIGH_LEVEL, entry="verify-proof",
                            witness_layout="affine-inline", plan=plan)
        new = ForthVerifier(self.key, modular.read_bytes(), source_path=modular, entry="verify-proof",
                            witness_layout="affine-inline", plan=plan)
        lock = new.compile(SOURCES)
        self.assertEqual(lock, old.compile(SOURCES))
        self.assertEqual({library.name for library in new.libraries},
                         {"miller.fth", "public-inputs.fth", "residue.fth", "std/bsv"})
        paired = ForthVerifier(self.key, modular.read_bytes(), source_path=modular, entry="verify-proof",
                               witness_layout="affine-inline", plan=replace(plan, g1_reductions="paired-doubles"))
        compact = paired.compile(SOURCES)
        self.assertLess(len(compact), len(lock))
        for signals, proof in self.cases:
            check_spend(*spend_fixture(compact, paired.witness(signals, proof, sources=SOURCES)))

    def test_high_level_requires_the_complete_miller_plan(self):
        source = HIGH_LEVEL.read_bytes()
        for before, after in ((b"16 0 DO", b"15 0 DO"), (b"16 0 DO", b"17 0 DO")):
            with self.subTest(loop=after):
                invalid = ForthVerifier(self.key, source.replace(before, after), entry="verify-proof")
                with self.assertRaisesRegex(ValueError, "round plan must match the BLS12-381 seed"):
                    invalid.compile(self.cases[0][0])

    def test_high_level_requires_both_residue_checks(self):
        source = HIGH_LEVEL.read_bytes()
        for word in (b"bls12-381-require-fp6", b"bls12-381-require-nonzero"):
            with self.subTest(word=word):
                with self.assertRaises(CompileError):
                    ForthVerifier(self.key, source.replace(word, b""), entry="verify-proof")
        with self.assertRaisesRegex(CompileError, "requires an explicit BLS12-381 residue product"):
            ForthVerifier(self.key, self.source, plan=ArithmeticPlan(residue_association="right"))

    def test_split_g1_checks_require_a_and_c(self):
        source = HIGH_LEVEL.read_bytes().replace(b"bls12-381-check-g1-c-then-a", b"bls12-381-check-g1-points")
        source = source.replace(b"swap bls12-381-check-g1-points",
                                b"swap bls12-381-check-g1-a bls12-381-check-g1-c")
        for word in (b"bls12-381-check-g1-a", b"bls12-381-check-g1-c"):
            with self.subTest(word=word), self.assertRaises(CompileError):
                ForthVerifier(self.key, source.replace(word, b""), entry="verify-proof")
        ForthVerifier(self.key, source, entry="verify-proof")

    def test_reports_unsupported_words(self):
        invalid = self.source.replace(b"swap bls12", b"1 drop swap bls12")
        with self.assertRaisesRegex(CompileError, r"line 8, column 5: '1' cannot compile"):
            ForthVerifier(self.key, invalid)

    def test_bounds_expanded_verifier_helpers(self):
        helper = b"bsv-effect: h0 -- ;\n: h0 ;\n"
        helper += "".join(f"bsv-effect: h{i} -- ;\n: h{i} h{i - 1} h{i - 1} ;\n"
                          for i in range(1, 20)).encode()
        source = helper + self.source.replace(b"    bls12-381-read-witness", b"    h19 bls12-381-read-witness")
        with self.assertRaisesRegex(CompileError, f"{GROTH16_ENTRY}.*expansion budget before lowering"):
            ForthVerifier(self.key, source)

    def test_affine_msm_infinity_doubling_and_scalar_range(self):
        original = ScriptVerifier(self.key)
        p, q = original.key.alpha, original.key.beta
        curve = Curve(HOST)
        metadata = {"protocol": "groth16", "curve": "bls12381"}
        key = {
            **metadata, "nPublic": 2, "IC": list(map(g1_json, (p, curve.negate(p), p))),
            "vk_alpha_1": g1_json(p), "vk_beta_2": g2_json(q), "vk_gamma_2": g2_json(q),
            "vk_delta_2": g2_json(q),
        }
        sources = Dynamic(), Dynamic(2)
        unsigned = ForthVerifier(json.dumps(key), self.source, witness_layout="affine-witness")
        signed = ForthVerifier(json.dumps(key), self.source, witness_layout="affine-witness",
                               plan=ArithmeticPlan(msm="signed-radix4"))
        derived = ForthVerifier(json.dumps(key), self.source, witness_layout="affine-witness",
                                plan=ArithmeticPlan(msm="signed-radix4", msm_table="doubling-slopes"))
        deferred = ForthVerifier(json.dumps(key), self.source, witness_layout="affine-witness",
                                 plan=replace(derived.plan, msm_table="deferred-doubling-slopes"))
        for verifier in (unsigned, signed, derived, deferred):
            lock = verifier.compile(sources)
            for s, t in ((0, 0), (1, 0), (0, 1), (0, 3), (R - 1, 2)):
                with self.subTest(plan=verifier.plan, signals=(s, t)):
                    # VK_x=[1-s+t]P, and A=[3-s+t]P makes the test pairing exact.
                    proof = json.dumps({**metadata, "pi_a": g1_json(curve.mul_host(p, (3 - s + t) % R)),
                                        "pi_b": g2_json(q), "pi_c": g1_json(p)})
                    witness = verifier.witness((s, t), proof, sources=sources)
                    parent, spend = spend_fixture(lock, witness)
                    check_spend(parent, spend)
                    if s == R - 1:
                        packet = push(public_packet(sources, (s, t)))
                        malformed = witness[:-len(packet)] + push(R.to_bytes(32, "little") + bytes([t]))
                        with self.assertRaises((RuntimeError, ValueError)):
                            check_spend(parent, spend.with_script(0, malformed))
                    if verifier is signed and t == 3:
                        old_witness = unsigned.witness((s, t), proof, sources=sources)
                        with self.assertRaises((RuntimeError, ValueError)):
                            check_spend(parent, spend.with_script(0, old_witness))
                    if verifier in (derived, deferred) and t == 3:
                        self.assertEqual(witness, signed.witness((s, t), proof, sources=sources))

    def test_affine_layout_shares_public_packet_with_successor_check(self):
        verifier = ForthVerifier(self.key, self.source, witness_layout="affine-inline")
        signals, proof = self.cases[0]
        sources = SOURCES[:3] + signals[3:]
        lock = bind_public_output(verifier.compile(sources), sources, 1000)
        witness = verifier.witness(signals, proof, sources=sources)
        for i, (statement, _) in enumerate(self.cases):
            with self.subTest(statement=statement):
                output = public_output(1000, public_packet(sources, statement))
                parent, draft = spend_fixture(lock, b"", output)
                spend = draft.with_script(0, witness + push(preimage_all(draft, 0, 2000)))
                if i == 0:
                    check_spend(parent, spend)
                else:
                    with self.assertRaises((RuntimeError, ValueError)):
                        check_spend(parent, spend)

    def test_affine_explicit_maximum_rejects_an_otherwise_valid_spend(self):
        verifier = ForthVerifier(self.key, self.source, witness_layout="affine-witness")
        signals, proof = self.cases[0]
        # Both scripts use the same packet width and window count. The one-step
        # difference in their configured maxima is the reason this proof fails.
        for limit in (signals[2], signals[2] - 1):
            with self.subTest(limit=limit):
                source, = input_sources(json.dumps([{"max": limit}]))
                config = SOURCES[:2] + (source,) + SOURCES[3:]
                witness = verifier.witness(signals, proof, sources=SOURCES)
                parent, spend = spend_fixture(verifier.compile(config), witness)
                if limit == signals[2]:
                    check_spend(parent, spend)
                else:
                    with self.assertRaises((RuntimeError, ValueError)):
                        check_spend(parent, spend)

    def test_affine_compact_checks_trace_lines_and_residue(self):
        verifier = ForthVerifier(self.key, self.source, witness_layout="affine-witness",
                                 plan=ArithmeticPlan(msm="signed-radix4", msm_table="deferred-doubling-slopes",
                                                     miller_reductions="split-chord-residue",
                                                     miller_kernel="direct-normalized"))
        signals, proof = self.cases[0]
        lock = verifier.compile(SOURCES)
        artifact = verifier.artifact(SOURCES, None, lock)
        witness = verifier.witness(signals, proof, sources=SOURCES)
        parent, spend = spend_fixture(lock, witness)
        check_spend(parent, spend)

        line_size = artifact["pairing_line_packet_bytes"]
        slope_size = artifact["slope_packet_bytes"]
        line_push = len(push(bytes(line_size)))
        line_start = line_push - line_size
        slope_start = line_push + len(push(bytes(slope_size))) - slope_size
        residue_bytes = 12 * FIELD_BYTES
        public_push = len(push(public_packet(SOURCES, signals)))
        residue_start = len(witness) - public_push - residue_bytes
        # The first public scalar is zero, so its first window requires slope zero.
        self.assertEqual(witness[slope_start:slope_start + FIELD_BYTES], bytes(FIELD_BYTES))
        controls = (
            ("lines", line_start, bytes([witness[line_start] ^ 1])),
            ("slope", slope_start, (1).to_bytes(FIELD_BYTES, "little")),
            ("out-of-range slope", slope_start, Q.to_bytes(FIELD_BYTES, "little")),
            ("Miller slope", slope_start + artifact["msm_slope_count"] * FIELD_BYTES,
             bytes(FIELD_BYTES)),
            ("zero residue", residue_start, bytes(residue_bytes)),
        )
        for name, offset, replacement in controls:
            with self.subTest(name=name), self.assertRaises((RuntimeError, ValueError)):
                bad = witness[:offset] + replacement + witness[offset + len(replacement):]
                check_spend(parent, spend.with_script(0, bad))

    def test_objectives_report_serialized_cost_and_use_the_selected_witness(self):
        candidates = layout_candidates(self.key, self.source, SOURCES)
        for objective, layout in (("lock-bytes", "affine-witness"), ("path-bytes", "affine-inline"),
                                  ("witness-bytes", "projective")):
            with self.subTest(objective=objective):
                verifier, artifact = select_layout(candidates, objective)
                self.assertEqual(verifier.witness_layout, layout)
                self.assertEqual(artifact["witness_layout"], layout)
                self.assertEqual(artifact["artifact_sha256"], artifact_digest(artifact))
                rows = artifact["layout_selection"]["candidates"]
                cost = next(row for row in rows if row["witness_layout"] == layout)
                lock = bytes.fromhex(artifact["script_hex"])
                for signals, proof in self.cases:
                    witness = verifier.witness(signals, proof, sources=SOURCES)
                    self.assertEqual(cost["witness_bytes"], len(witness))
                    self.assertEqual(cost["path_bytes"], len(blob(lock)) + len(blob(witness)))
                    check_spend(*spend_fixture(lock, witness))

    def test_objective_only_considers_applicable_fixed_layout(self):
        signals, proof = self.cases[0]
        candidates = layout_candidates(self.key, self.source, signals)
        verifier, artifact = select_layout(candidates, "lock-bytes")
        self.assertEqual(artifact["witness_layout"], "projective")
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].cost["witness_bytes"],
                         len(verifier.witness(signals, proof, sources=signals)))

    def test_chronicle_shortens_the_lock_for_post_activation_outputs(self):
        genesis = ForthVerifier(self.key, self.source, witness_layout="affine-witness")
        chronicle = ForthVerifier(self.key, self.source, witness_layout="affine-witness", script_era="chronicle")
        genesis_lock, lock = genesis.compile(SOURCES), chronicle.compile(SOURCES)
        self.assertLess(len(lock), len(genesis_lock))
        artifact = chronicle.artifact(SOURCES, None, lock)
        self.assertEqual(artifact["minimum_utxo_era"], "chronicle")
        for signals, proof in self.cases:
            witness = chronicle.witness(signals, proof, sources=SOURCES)
            self.assertEqual(witness, genesis.witness(signals, proof, sources=SOURCES))
            parent, spend = spend_fixture(lock, witness)
            for version in (1, 2):
                with self.subTest(signals=signals, version=version):
                    tx = replace(spend, version=version)
                    check_spend(parent, tx)
                    with self.assertRaises((RuntimeError, ValueError)):
                        validate_at_heights(tx, (parent,), spend_height=4, activation_height=2, utxo_heights=(1,))
                    with self.assertRaises((RuntimeError, ValueError)):
                        validate_at_heights(tx, (parent,), spend_height=4, activation_height=1000, utxo_heights=(3,))


if __name__ == "__main__":
    unittest.main()
