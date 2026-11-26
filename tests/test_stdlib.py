"""Import and funded composition regressions for the bundled library."""

from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from fourthgraph.verification.circuit_backend import compile_circuit
from fourthgraph.verification.circuit_tools import CircuitFixture
from fourthgraph.compiler.source import CompileError, SourceCompiler, evaluate, schedule
from fourthgraph.compiler.lowering import compile_word
from fourthgraph.verification.proof_contract import FIELD, ProofContract, VerificationKey
from fourthgraph.workflow.protocol import ROOT_VALUE, UTXO
from fourthgraph.replay.workflow import GATED_EXAMPLE, Replay, TestKeys
from fourthgraph.benchmark.validation import Node
from fourthgraph.bsv.evaluate import ScriptError, evaluate as evaluate_script
from fourthgraph.bsv.native_payments import p2pk_lock, p2pkh_lock
from fourthgraph.bsv.script import asm, encode_num, number, push
from fourthgraph.bsv.transaction import Input, Output, Transaction
from fourthgraph.stdlib import LIBRARIES, Library, capabilities
from fourthgraph.verification.plan import compile_solutions
from fourthgraph.compiler.wordsets import U32, Primitive

PROJECTS = Path(__file__).resolve().parents[1] / "projects"
COMPOSITION = (PROJECTS / "workflow-examples/library-composition.fth").read_text()
VERIFICATION_PATH = PROJECTS / "proof-counter/verify-state.fth"
VERIFICATION = VERIFICATION_PATH.read_bytes()
OWNER = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
COMPRESSED = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
NATIVE_LOCK = bytes.fromhex("76a914") + OWNER + bytes.fromhex("88ac")


class LibraryTests(unittest.TestCase):
    def test_named_p2pkh_preserves_native_lock_and_verification_order(self):
        source = LIBRARIES["std/native-p2pkh"].source.read_text()
        word = SourceCompiler(source, bindings={"owner-hash": OWNER}).words["p2pkh"]
        signature = b"test signature"
        checksig = Mock(side_effect=lambda sig, key: (sig, key) == (signature, COMPRESSED))
        self.assertEqual(evaluate(word, signature, COMPRESSED, checksig=checksig), (1,))
        self.assertEqual(evaluate(word, b"", COMPRESSED, checksig=checksig), (0,))
        for mode in ("baseline", "safe", "stack"):
            script = compile_word(word, mode).script
            self.assertEqual(script, NATIVE_LOCK)
            self.assertEqual(evaluate_script(script, [signature, COMPRESSED], checksig), ([b"\x01"], []))
            self.assertEqual(evaluate_script(script, [b"", COMPRESSED], checksig), ([b""], []))
            checksig.reset_mock()
            with self.assertRaisesRegex(ScriptError, "EQUALVERIFY"):
                evaluate_script(script, [signature, b"other key"], checksig)
            checksig.assert_not_called()
        with self.assertRaisesRegex(CompileError, "missing binding"):
            SourceCompiler(source)
        with self.assertRaisesRegex(CompileError, "requires exactly 20 bytes"):
            SourceCompiler(source, bindings={"owner-hash": OWNER[:-1]})
        with self.assertRaisesRegex(CompileError, "check-signature.*expected stack suffix"):
            SourceCompiler(source.replace("public-key dup", "public-key"), bindings={"owner-hash": OWNER})

    def test_lock_entries_cannot_be_inlined_or_used_as_workflow_gates(self):
        source = "REQUIRE BSV\nlock: positive ( value:u32 ) value u32>cell 0 > verify ;\n"
        frontend = SourceCompiler(source)
        word = frontend.words["positive"]
        self.assertEqual(evaluate(word, 0), (0,))
        self.assertEqual(evaluate_script(compile_word(word).script, [b""]), ([b""], []))
        for suffix in (": bypass ( u32 -- cell ) positive drop 1 ;",
                       "gate: approval state positive alice ;",
                       "lock: composed ( value:u32 ) value positive ;"):
            with self.subTest(suffix=suffix):
                with self.assertRaisesRegex(CompileError, "positive.*lock entry.*cannot be called"):
                    SourceCompiler(source + suffix)

    def test_named_lock_rewrites_only_a_single_use_branch_flag(self):
        frontend = SourceCompiler("""
REQUIRE BSV
lock: decide ( value:cell ) value 0 > IF 1 ELSE 0 THEN ;
lock: retain ( value:cell ) value 0 > dup IF 1 drop THEN ;
""")
        decide = frontend.words["decide"]
        retain = frontend.words["retain"]
        self.assertEqual(len(compile_word(decide).script), 9)
        for mode in ("safe", "stack"):
            compiled = compile_word(decide, mode)
            self.assertEqual(compiled.script, asm("OP_0 OP_GREATERTHAN OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF"))
            rewrite, = compiled.rewrites
            self.assertEqual((rewrite.rule, rewrite.script_bytes), ("comparison-feeds-if", (3, 1)))
            retained = compile_word(retain, mode)
            self.assertEqual(retained.rewrites, ())
            for value in (-1, 0, 1):
                self.assertEqual(evaluate_script(compiled.script, [encode_num(value)])[0],
                                 [encode_num(int(value > 0))])
                self.assertEqual(evaluate_script(retained.script, [encode_num(value)])[0],
                                 [encode_num(-int(value > 0))])

        custom = Primitive(("cell",), ("cell",), asm("OP_0NOTEQUAL OP_0 OP_SWAP OP_SUB"),
                           lambda value: (-int(value != 0),), "custom flag", comparison=True)
        frontend = SourceCompiler("""
: plain ( cell -- cell ) custom IF 1 ELSE 0 THEN ;
lock: named ( value:cell ) value custom IF 1 ELSE 0 THEN ;
""", vocabulary={"custom": custom})
        for entry in ("plain", "named"):
            for mode in ("safe", "stack"):
                with self.subTest(entry=entry, mode=mode):
                    compiled = compile_word(frontend.words[entry], mode)
                    self.assertEqual(compiled.rewrites, ())
                    for value in (0, 1):
                        self.assertEqual(evaluate_script(compiled.script, [encode_num(value)]),
                                         ([encode_num(value)], []))

    def test_named_lock_schedules_multi_result_words_and_unused_inputs(self):
        source = """
REQUIRE bsv
: halves ( bytes -- bytes bytes ) 1 OP_SPLIT ;
lock: match ( unused:bytes data:bytes )
    data halves bytes-hex 62 OP_EQUALVERIFY bytes-hex 61 OP_EQUAL ;
"""
        word = SourceCompiler(source).words["match"]
        self.assertEqual(evaluate(word, b"ignored", b"ab"), (1,))
        for mode in ("baseline", "safe", "stack"):
            self.assertEqual(evaluate_script(compile_word(word, mode).script, [b"ignored", b"ab"]), ([b"\x01"], []))
        with self.assertRaisesRegex(CompileError, "one cell"):
            SourceCompiler("lock: invalid ( data:bytes ) data ;")

    def test_named_lock_fuses_verify_only_when_its_flag_is_consumed(self):
        for predicate, fused in (("OP_EQUAL", "OP_EQUALVERIFY"), ("OP_CHECKSIG", "OP_CHECKSIGVERIFY")):
            with self.subTest(predicate=predicate):
                body = f"lock: verify-once ( a:bytes b:bytes ) a b {predicate} verify"
                word = SourceCompiler(f"REQUIRE bsv\n{body} ;").words["verify-once"]
                self.assertEqual(compile_word(word).script, asm(predicate))

                source = f"REQUIRE bsv\n{body} 1 ;"
                word = SourceCompiler(source).words["verify-once"]
                self.assertEqual(compile_word(word).script, asm(f"{fused} OP_1"))

                source = f"REQUIRE bsv\nlock: retain-flag ( a:bytes b:bytes ) a b {predicate} dup verify ;"
                word = SourceCompiler(source).words["retain-flag"]
                self.assertEqual(compile_word(word).script, asm(f"{predicate} OP_DUP OP_VERIFY"))

    def test_require_bsv_enables_typed_native_opcodes(self):
        source = ": hash ( bytes -- bytes ) OP_HASH160 ;"
        with self.assertRaisesRegex(CompileError, "OP_HASH160.*requires REQUIRE BSV"):
            SourceCompiler(source)
        frontend = SourceCompiler(f"REQUIRE BSV\nREQUIRE bsv\n{source}")
        self.assertEqual(compile_word(frontend.words["hash"]).script, b"\xa9")
        self.assertEqual(tuple(item.name for item in frontend.library_imports), ("std/bsv",))
        with self.assertRaisesRegex(CompileError, "OP_HASH160.*expected stack suffix"):
            SourceCompiler(f"REQUIRE bsv\n{source.replace('bytes --', 'cell --')}")

    def test_named_lock_uses_forth_branches_with_shared_stack_values(self):
        source = """
REQUIRE bsv
lock: match ( value:bytes switch:cell inner:cell )
    value switch IF
        inner IF bytes-hex aa ELSE bytes-hex bb THEN
    ELSE bytes-hex cc THEN
    OP_EQUAL verify ;
"""
        word = SourceCompiler(source).words["match"]
        for mode in ("baseline", "safe", "stack"):
            script = compile_word(word, mode).script
            for switch, inner, expected in ((0, 0, b"\xcc"), (1, 0, b"\xbb"), (-1, 1, b"\xaa")):
                for value in (expected, b"wrong"):
                    accepted = int(value == expected)
                    self.assertEqual(evaluate(word, value, switch, inner), (accepted,))
                    self.assertEqual(evaluate_script(script, [value, encode_num(switch), encode_num(inner)]),
                                     ([encode_num(accepted)], []))
        with self.assertRaisesRegex(CompileError, "equal stack types"):
            SourceCompiler(source.replace("bytes-hex cc", "0"))

    def test_composition_preserves_native_lock_bytes_and_wraps(self):
        frontend = SourceCompiler(COMPOSITION + "\nrequire stdlib/./u32.fth\n")
        self.assertEqual(tuple(item.name for item in frontend.library_imports), ("std/bsv", "std/p2pkh", "std/u32"))
        word = frontend.words["advance-and-pay"]
        self.assertEqual(evaluate(word, U32 - 1, OWNER), (0, NATIVE_LOCK))
        self.assertEqual(p2pkh_lock(OWNER), NATIVE_LOCK)
        self.assertEqual(p2pk_lock(COMPRESSED), b"\x21" + COMPRESSED + b"\xac")
        for mode in ("baseline", "safe", "stack"):
            script = compile_word(word, mode).script
            self.assertEqual(evaluate_script(script, [encode_num(U32 - 1), OWNER]), ([b"", NATIVE_LOCK], []))
        self.assertEqual(compile_word(word, "stack").describe()["rewrites"][0]["module"], "std/u32")
        with self.assertRaisesRegex(ValueError, "expected 20 bytes"):
            evaluate(word, 7, OWNER[:-1])

    def test_require_loads_relative_files_once_in_the_caller_dictionary(self):
        with TemporaryDirectory() as directory:
            parent = Path(directory) / "main.fth"
            (parent.parent / "modules").mkdir()
            helper = parent.parent / "modules" / "Helper.fth"
            helper.write_text("range: small cell 0 20 ;\n: get-helper ( -- cell ) base ;\n")
            wrapper = helper.with_name("wrapper.fth")
            wrapper.write_text("REQUIRE Helper.fth\n: use-helper ( -- cell ) get-helper ;\n")
            source = (
                ": base ( -- cell ) 7 ;\n"
                "require modules/wrapper.fth\n"
                "REQUIRE modules/./Helper.fth\n"
                ": base ( -- cell ) 9 ;\n"
                ": combined ( -- cell ) use-helper base + ;\n"
            )
            frontend = SourceCompiler(source, source_path=parent)
            self.assertEqual(evaluate(frontend.words["combined"]), (16,))
            self.assertEqual(tuple(item.name for item in frontend.library_imports),
                             ("modules/Helper.fth", "modules/wrapper.fth"))
            self.assertEqual(frontend.library_imports[0].sha256, sha256(helper.read_bytes()).hexdigest())
            self.assertIsNone(frontend.library_imports[0].interface_sha256)
            helper.write_text("REQUIRE wrapper.fth\n")
            with self.assertRaisesRegex(CompileError, r"modules/Helper.fth, line 1.*REQUIRE cycle"):
                SourceCompiler(source, source_path=parent)

    def test_require_diagnostics_and_registered_interfaces(self):
        with self.assertRaisesRegex(CompileError, "expected a filename"):
            SourceCompiler("REQUIRE\nstdlib/u32.fth")
        with self.assertRaisesRegex(CompileError, "could not resolve required file"):
            SourceCompiler("REQUIRE stdlib/unknown.fth")
        with self.assertRaisesRegex(CompileError, "requires the groth16-bls12-381 backend"):
            SourceCompiler("REQUIRE groth16-bls12-381/verifier.fth")
        with self.assertRaisesRegex(CompileError, "unknown Forth word 'bsv-use'"):
            SourceCompiler("bsv-use std/u32")
        with TemporaryDirectory() as directory:
            source = Path(directory) / "test.fth"
            source.write_text(": other ( u32 -- u32 ) ;\n")
            export = replace(LIBRARIES["std/u32"].exports[0], name="other", gives=("cell",))
            with patch.dict(LIBRARIES, {"std/test": Library(source, (export,))}):
                with self.assertRaisesRegex(CompileError, "std/test.*does not match its public stack effect"):
                    SourceCompiler(f"REQUIRE {source}")
        frontend = SourceCompiler("REQUIRE stdlib/u32.fth\n: u32-inc ( u32 -- u32 ) ;")
        self.assertEqual(evaluate(frontend.words["u32-inc"], 13), (13,))
        self.assertNotIn("u32-inc", frontend.imported_words)

    def test_public_interface_catalog_matches_loaded_forth(self):
        catalog = capabilities()
        for module, entry in (("std/bsv", "verify"), ("std/u32", "u32-inc"), ("std/p2pk", "p2pk-lock"),
                              ("std/p2pkh", "p2pkh-lock")):
            frontend = SourceCompiler(f"REQUIRE stdlib/{module.removeprefix('std/')}.fth")
            imports = {item.name: item for item in frontend.library_imports}
            self.assertEqual(set(imports), {"std/bsv", module})
            evidence = imports[module]
            self.assertEqual(evidence.interface_sha256, catalog[module]["interface_sha256"])
            self.assertEqual(set(frontend.imported_words), {"verify", entry})
            for name, descriptor in catalog[module]["interfaces"].items():
                word = frontend.words[name]
                self.assertEqual((word.takes, word.gives), (descriptor["takes"], descriptor["gives"]))
                self.assertEqual(descriptor["module"], module)
                self.assertTrue(descriptor["runtime_inputs"] and descriptor["backends"] and descriptor["failure"])
        payments = SourceCompiler("REQUIRE stdlib/p2pk.fth\nREQUIRE stdlib/p2pkh.fth\n")
        self.assertEqual(set(payments.imported_words), {"verify", "p2pk-lock", "p2pkh-lock"})
        groth = catalog["std/groth16-bls12-381"]["interfaces"]["groth16-bls12-381-verify"]
        self.assertEqual(groth["build_parameters"][0]["name"], "verification-key")
        self.assertEqual(groth["aliases"], ("groth16-verify",))

    def test_canonical_declaration_boundaries_keep_legacy_semantics(self):
        source = GATED_EXAMPLE.read_text()
        canonical = SourceCompiler(source + "recovery: 145\n review ; independent-submit: qualify ;").program()
        implicit = "\n".join(line.removesuffix(" ;") if line.startswith(
            ("work:", "join:", "split-authority:", "gate:")
        ) else line for line in source.splitlines())
        legacy = SourceCompiler(implicit + "\nrecovery: 145 review\nqualify independent-submit").program()
        self.assertEqual(canonical.recovery, legacy.recovery)
        self.assertEqual(schedule(canonical).templates, schedule(legacy).templates)
        self.assertEqual(compile_circuit(VERIFICATION, source_path=VERIFICATION_PATH), compile_circuit(VERIFICATION.replace(b"relation:", b"verify:"), source_path=VERIFICATION_PATH))
        for clause in ("independent-submit: qualify", "relation: u32-inc decide"):
            with self.subTest(clause=clause), self.assertRaisesRegex(CompileError, "expected ';'"):
                SourceCompiler("REQUIRE stdlib/verify.fth\n" + clause)
        with self.assertRaisesRegex(CompileError, "bsv- prefix is reserved"):
            SourceCompiler("bsv-effect: bsv-counter u32 -- u32 ;")
        with self.assertRaisesRegex(CompileError, "cannot be used inside a definition"):
            SourceCompiler("bsv-effect: foo -- ;\n: foo relation: ;")

    def test_p256_reuses_project_kernels_byte_for_byte(self):
        frontend = SourceCompiler("REQUIRE stdlib/p256.fth")
        expected = {
            "p256-add": "76d4ff0d4125590a058c3ad89c32634ae95e17feddd50d6fc49b16fed02344d9",
            "p256-double": "cc1ee9c2fe0526c3bc0a6c54d42f73b0600fb43300d2fbb774c6acabf7653d7e",
        }
        self.assertEqual({name: sha256(compile_word(frontend.words[name]).script).hexdigest() for name in expected},
                         expected)

    def test_verification_policy_filters_before_ranking(self):
        keys = TestKeys().public
        frontend = SourceCompiler(VERIFICATION.decode(), source_path=VERIFICATION_PATH)
        with TemporaryDirectory() as directory:
            candidate, report = compile_solutions(frontend, keys, 19, directory, target="both")
            self.assertEqual(report["selected"], "script")
            self.assertEqual(report["statement"]["entries"]["transition"]["module"], "counter.fth")
            self.assertIn("no matching external setup", report["candidates"]["groth16-bls12-381/projective"]["reason"])
            self.assertEqual(evaluate(candidate.contract.circuit.transition, 19), (20,))
            self.assertEqual(report["compilations"]["script"]["script_hex"], candidate.contract.root.script.hex())
            self.assertEqual(report["compilations"]["circuit"]["source"].encode(), compile_circuit(VERIFICATION, source_path=VERIFICATION_PATH))
            with self.assertRaisesRegex(CompileError, "lock exceeds the 1-byte budget"):
                compile_solutions(frontend, keys, 19, directory, max_lock_bytes=1)
            with (patch("fourthgraph.verification.plan.CircuitFixture", side_effect=ValueError("prover unavailable")),
                  self.assertRaisesRegex(CompileError, "prover unavailable")):
                compile_solutions(frontend, keys, 19, directory, policy="require-proof")
            script_only = VERIFICATION.replace(
                b"relation: advance decide ;",
                b"bsv-effect: increment u32 -- u32 ;\n: increment u32>cell 1 + cell>u32 ;\n"
                b"relation: increment decide ;",
            )
            _, script_report = compile_solutions(script_only, keys, 19, directory, source_path=VERIFICATION_PATH, r1cs=True)
            self.assertEqual(script_report["selected"], "script")
            self.assertIn("'u32>cell' is outside", script_report["candidates"]["r1cs"]["reason"])
            repeated = "bsv-effect: w0 u32 -- u32 ;\n: w0 advance ;\n"
            repeated += "".join(f"bsv-effect: w{i} u32 -- u32 ;\n: w{i} w{i - 1} w{i - 1} ;\n"
                                for i in range(1, 25))
            source = VERIFICATION.replace(b"relation: advance decide ;",
                                          (repeated + "relation: w24 decide ;").encode())
            with self.assertRaisesRegex(CompileError, r"line \d+, column \d+: .*budget before lowering"):
                compile_solutions(source, keys, 19, directory, source_path=VERIFICATION_PATH)
            with self.assertRaisesRegex(CompileError, r"circuit exceeds .* budget before lowering"):
                compile_circuit(source, source_path=VERIFICATION_PATH)
            word = SourceCompiler(source.decode(), source_path=VERIFICATION_PATH).words["w24"]
            for optimization in ("baseline", "stack"):
                with self.subTest(optimization=optimization), self.assertRaisesRegex(CompileError, "budget before lowering"):
                    compile_word(word, optimization)
        original = PROJECTS / "proof-counter/workflow.fth"
        self.assertEqual(compile_circuit(VERIFICATION, source_path=VERIFICATION_PATH), compile_circuit(original.read_bytes(), source_path=original))

    def test_reusing_scratch_preserves_proof_candidates_and_resolved_words(self):
        document = {"prime": str(FIELD), "useCustomGates": False, "nVars": 6, "nOutputs": 2,
                    "nPubInputs": 3, "nPrvInputs": 0, "nConstraints": 1,
                    "constraints": [[{}, {}, {"1": "1", "3": str(FIELD - 1), "0": str(FIELD - 1)}]]}
        key = VerificationKey.load(json.dumps(document).encode())
        keys = TestKeys().public
        builds = []
        frontend = SourceCompiler(VERIFICATION.decode(), source_path=VERIFICATION_PATH)

        def build_circuit(source, directory, *, has_route):
            builds.append(Path(directory))
            fixture = Mock(spec=CircuitFixture, key=key, source_sha256=sha256(source).hexdigest())
            fixture.describe.return_value = {"test": True}
            return fixture

        with self.assertRaisesRegex(ValueError, "must expose both next state and route"):
            ProofContract(VERIFICATION, replace(key, outputs=1), 19, keys, source_path=VERIFICATION_PATH)
        with (TemporaryDirectory() as directory, patch("fourthgraph.verification.plan.CircuitFixture", side_effect=build_circuit),
              patch("fourthgraph.verification.proof_contract.SourceCompiler", side_effect=AssertionError("resolved program reparsed"))):
            _, first = compile_solutions(frontend, keys, 19, directory, policy="require-proof", r1cs=True)
            _, second = compile_solutions(frontend, keys, 19, directory, policy="require-proof", r1cs=True)
            self.assertEqual(first, second)
            self.assertEqual(first["selected"], "r1cs")
            self.assertEqual(len(set(builds)), 2)


@unittest.skipUnless(os.environ.get("REGTEST_URL"), "requires tools/verify_node.sh")
class FundedLibraryTests(unittest.TestCase):
    def test_both_project_words_execute_in_one_input(self):
        node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
        replay = Replay(node, 1, "both", int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"]))
        word = SourceCompiler(COMPOSITION).words["advance-and-pay"]
        lock = (compile_word(word, "stack").script + push(NATIVE_LOCK) + asm("OP_EQUALVERIFY OP_0 OP_NUMEQUAL"))
        contract = SimpleNamespace(root=Output(ROOT_VALUE, lock), version=replay.version)
        deployment, _ = replay.deploy(contract, replay.fund(1), 0)
        previous = (UTXO(deployment, 0),)
        spend = Transaction((Input(deployment.txid_wire(), 0),), (Output(ROOT_VALUE - 1000, NATIVE_LOCK),))

        def witness(value, owner):
            return spend.with_script(0, number(value) + push(owner))

        replay.record(witness(U32 - 1, OWNER[:-1]), previous, expected=False)
        replay.record(witness(0, OWNER), previous, expected=False)
        replay.record(witness(U32 - 1, OWNER), previous)
