"""Check the Forth build against the original verifier and its typed ABI."""

from dataclasses import replace
from hashlib import sha256
import json
import unittest

from fourthgraph.verification.bls12381.verifier import (
    HOST, R, Curve, Dynamic, ScriptVerifier, bind_public_output, input_sources, public_output, public_packet,
)
from fourthgraph.verification.bls12381.build import ForthVerifier, SOURCE, layout_candidates, select_layout
from fourthgraph.compiler.source import CompileError
from fourthgraph.workflow.protocol import artifact_digest
from fourthgraph.replay.bls12381_verifier import SOURCES, fixture
from fourthgraph.bsv.chain_gang import validate_at_heights
from fourthgraph.bsv.script import asm, push
from fourthgraph.bsv.transaction import blob, preimage_all
from fourthgraph.stdlib import GROTH16_ENTRY, LEGACY_GROTH16_ENTRY, capabilities
from .test_backend import check_spend, g1_json, g2_json, spend_fixture


class ForthVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key, cls.cases = fixture()
        cls.source = SOURCE.read_bytes()

    def test_matches_original_fixed_hybrid_and_dynamic(self):
        verifier = ForthVerifier(self.key, self.source)
        original = ScriptVerifier(self.key)
        signals, proof = self.cases[0]
        profiles = ((signals, True), (SOURCES[:3] + signals[3:], True), (SOURCES, True), (SOURCES, False))
        for sources, compact in profiles:
            with self.subTest(sources=sources, compact=compact):
                lock = verifier.compile(sources, compact=compact)
                self.assertEqual(lock, original.compile(sources, compact=compact) + asm("OP_VERIFY OP_1"))
                self.assertEqual(verifier.witness(signals, proof, sources=sources),
                                 original.witness(signals, proof, sources=sources))
                artifact = verifier.artifact(sources, None, lock, compact=compact)
                self.assertEqual(artifact["source_sha256"], sha256(self.source).hexdigest())
                self.assertEqual(artifact["artifact_sha256"], artifact_digest(artifact))
                self.assertEqual(artifact["forth_entry"], GROTH16_ENTRY)

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
        verifier = ForthVerifier(json.dumps(key), self.source, witness_layout="affine-witness")
        lock = verifier.compile(sources)
        cases = ((0, 0), (1, 0), (0, 1), (R - 1, 2))
        for s, t in cases:
            with self.subTest(signals=(s, t)):
                # VK_x=[1-s+t]P, and A=[3-s+t]P makes the test pairing exact.
                proof = {**metadata, "pi_a": g1_json(curve.mul_host(p, (3 - s + t) % R)),
                         "pi_b": g2_json(q), "pi_c": g1_json(p)}
                witnesses = verifier.witness((s, t), json.dumps(proof), sources=sources)
                parent, spend = spend_fixture(lock, witnesses)
                check_spend(parent, spend)
                if s == R - 1:
                    packet = push(public_packet(sources, (s, t)))
                    malformed = witnesses[:-len(packet)] + push(R.to_bytes(32, "little") + bytes([t]))
                    with self.assertRaises((RuntimeError, ValueError)):
                        check_spend(parent, spend.with_script(0, malformed))

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
