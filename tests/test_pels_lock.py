"""Check target selection and actual spends from the normal PELS Forth entry."""

from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from fourthgraph.benchmark.validation import CONTEXT_PIN, chain_metadata
from fourthgraph.bsv.script import push
from fourthgraph.bsv.transaction import MAX_MONEY, Input, Output, Transaction, preimage_forkid
from fourthgraph.compiler.lowering import compile_word
from fourthgraph.compiler.source import CompileError, SourceCompiler, evaluate
from fourthgraph.workflow.pels import assemble_pels, compile_pels
from fourthgraph.workflow.forkid_lowering import LinkedContext
from fourthgraph.workflow.protocol import BINDING_CODE, FLAG, build_artifact


SOURCE = """REQUIRE stdlib/pels.fth
bytes-param: recipient-lock 1 ;

: payout ( -- output ) 9999 1+ recipient-lock tx-output ;
: receipt ( -- output ) 0 bytes-hex 006a055245414459 tx-output ;

lock: settle ( )
    1 inputs= verify
    payout receipt 2 outputs= verify
    tx-locktime 42 = verify
;
"""
OUTPUTS = (Output(10_000, b"\x51"), Output(0, bytes.fromhex("006a055245414459")))


def chain_available():
    try:
        return chain_metadata()["commit"] == CONTEXT_PIN
    except ImportError:
        return False


def build(source=SOURCE, target="chronicle-v2", family="auto"):
    constraints = SourceCompiler(source, bindings={"recipient-lock": b"\x51"}).words["settle"].pels
    return build_artifact(compile_pels(constraints, target, family), source.encode())


def transactions(artifact, outputs=OUTPUTS, *, prevout_value=11_000):
    parent = Transaction((Input(bytes(32), 0),), (Output(prevout_value, bytes.fromhex(artifact["script_hex"])),))
    tx = Transaction((Input(parent.txid_wire(), 0),), outputs, version=artifact["transaction_versions"][-1], locktime=42)
    return parent, tx


class PelsLockTests(unittest.TestCase):
    def test_forth_fold_and_missing_predicates(self):
        artifact = build()
        self.assertEqual(artifact["constraints"]["outputs"],
                         [{"satoshis": out.value, "script_hex": out.script.hex()} for out in OUTPUTS])
        self.assertEqual(artifact["constraints"]["locktime"], 42)
        with self.assertRaisesRegex(CompileError, "verify one input and the complete ordered outputs"):
            build(SOURCE.replace("1 inputs= verify", "1 inputs= drop"))
        with self.assertRaisesRegex(CompileError, "positive literal count"):
            build(SOURCE.replace("2 outputs=", "3 outputs="))
        with self.assertRaisesRegex(CompileError, "need build-time Forth values"):
            build(SOURCE.replace("tx-locktime 42 =", "tx-locktime 42 <"))
        word = SourceCompiler(SOURCE, bindings={"recipient-lock": b"\x51"}).words["settle"]
        with self.assertRaisesRegex(CompileError, "requires a PELS transaction target"):
            compile_word(word)

    def test_constant_branches_keep_only_selected_constraints(self):
        original = build()
        source = SOURCE.replace("9999 1+", "9999 1 IF 0 IF 2 + ELSE 1+ THEN ELSE 0 verify 2 + THEN")
        source = source.replace("tx-locktime 42 = verify", "0 IF tx-locktime 43 = verify ELSE tx-locktime 42 = verify THEN 1")
        branched = build(source)
        self.assertEqual(branched["constraints"], original["constraints"])
        self.assertEqual(branched["script_hex"], original["script_hex"])

        dynamic = SOURCE.replace("tx-locktime 42 = verify", "tx-locktime 42 = IF 1 ELSE 0 THEN verify")
        with self.assertRaisesRegex(CompileError, "PELS IF needs a build-time Forth flag"):
            build(dynamic)

    def test_compile_checks_output_total(self):
        fixed_amount = SOURCE.replace("tx-locktime 42 = verify", "tx-prevout-amount 10000 = verify")
        self.assertEqual(build(fixed_amount)["constraints"]["previous_amount"], 10_000)
        with self.assertRaisesRegex(CompileError, "output total exceeds the fixed prevout amount"):
            build(fixed_amount.replace("0 bytes-hex", "1 bytes-hex"))

        max_amount = SOURCE.replace("9999 1+", str(MAX_MONEY))
        self.assertEqual(build(max_amount)["constraints"]["outputs"][0]["satoshis"], MAX_MONEY)
        with self.assertRaisesRegex(CompileError, "output total exceeds the maximum satoshi amount"):
            build(max_amount.replace("0 bytes-hex", "1 bytes-hex"))

    def test_witness_checks_actual_prevout_amount_for_both_paths(self):
        artifact = build(family="both")
        funded_parent, funded = transactions(artifact, prevout_value=10_000)
        short_parent, underfunded = transactions(artifact, prevout_value=9_999)
        for family in artifact["paths"]:
            with self.subTest(family=family):
                signed, _ = assemble_pels(artifact, funded_parent, funded, family)
                self.assertEqual(signed.with_script(0, b""), funded)
                self.assertTrue(signed.inputs[0].script)
                with self.assertRaisesRegex(ValueError, "output total exceeds the actual prevout amount"):
                    assemble_pels(artifact, short_parent, underfunded, family)

    def test_provenance_distinguishes_source_constraints_and_emitted_bytes(self):
        program = SourceCompiler(SOURCE, bindings={"recipient-lock": b"\x51"})
        result = compile_pels(program.words["settle"].pels, "chronicle-v2", "auto", explain=True)
        for candidate in result["selection"]["candidates"]:
            code = bytes.fromhex(candidate["script_hex"])
            self.assertEqual(sha256(code).hexdigest(), candidate["script_sha256"])
            known, offset = {"constraints"}, 0
            for fragment in candidate["fragments"]:
                self.assertLessEqual(set(fragment["depends_on"]), known)
                self.assertEqual(fragment["offset"], offset)
                end = offset + fragment["bytes"]
                self.assertEqual(sha256(code[offset:end]).hexdigest(), fragment["sha256"])
                known.add(fragment["id"])
                offset = end
            self.assertEqual(offset, len(code))
        folded = build(SOURCE.replace("9999 1+", "10000"))
        original = build()
        self.assertNotEqual(original["source_sha256"], folded["source_sha256"])
        self.assertEqual(original["constraints_sha256"], folded["constraints_sha256"])
        self.assertEqual(original["script_sha256"], folded["script_sha256"])

    def test_target_policy_excludes_incompatible_coverage(self):
        self.assertEqual(build(target="bip143-v1")["selection"]["selected"], "bip143")
        self.assertEqual(build()["selection"]["selected"], "otda")
        self.assertEqual(set(build(family="both")["paths"]), {"bip143", "otda"})
        with self.assertRaisesRegex(CompileError, "Chronicle spend target"):
            build(target="bip143-v1", family="both")
        source = SOURCE.replace("tx-locktime 42 = verify", "tx-prevout-amount 11000 = verify")
        selected = build(source)
        self.assertEqual(selected["selection"]["selected"], "bip143")
        self.assertIn("otda", selected["selection"]["excluded_families"])
        for family in ("otda", "both"):
            with self.assertRaisesRegex(CompileError, "no authenticated prevout amount"):
                build(source, family=family)

    def test_counted_outputs_and_typed_unrolling(self):
        source = SOURCE.replace("payout receipt 2 outputs= verify",
                                "3 0 ?DO 10000 I + recipient-lock tx-output LOOP 3 outputs= verify")
        result = build(source)
        self.assertEqual([out["satoshis"] for out in result["constraints"]["outputs"]], [10000, 10001, 10002])
        program = SourceCompiler("""
            : total ( -- cell ) 0 3 0 DO I + 2 0 ?DO I + LOOP LOOP ;
            : empty-loop ( -- cell ) 42 0 0 ?DO I + LOOP ;
        """)
        self.assertEqual(evaluate(program.words["total"]), (6,))
        self.assertEqual(evaluate(program.words["empty-loop"]), (42,))
        with self.assertRaisesRegex(CompileError, "literal limit and start"):
            SourceCompiler(": dynamic ( cell -- cell ) 0 ?DO I LOOP 0 ;")
        with self.assertRaisesRegex(CompileError, "expansion budget"):
            SourceCompiler(": excessive ( -- cell ) 0 100 0 DO 100 0 DO I + LOOP LOOP ;")

    def test_cli_uses_artifact_to_assemble_the_requested_path(self):
        command = [sys.executable, "-m", "fourthgraph.workflow.protocol"]
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            source, manifest = directory / "settle.fth", directory / "lock.json"
            source.write_text(SOURCE)
            built = subprocess.check_output(command + [
                str(source), "--entry", "settle", "--bind-bytes", "recipient-lock=51", "--sighash-family", "both",
            ])
            manifest.write_bytes(built)
            artifact = json.loads(built)
            parent, candidate = transactions(artifact)
            for name, tx in (("parent.hex", parent), ("unsigned.hex", candidate)):
                (directory / name).write_text(tx.serialize().hex())
            assembled = json.loads(subprocess.check_output(command + [
                "pels-witness", str(manifest), "--parent", str(directory / "parent.hex"),
                "--unsigned", str(directory / "unsigned.hex"), "--sighash-family", "otda",
            ]))
            signed = Transaction.parse(bytes.fromhex(assembled["transaction_hex"]))
            self.assertEqual(assembled["sighash_family"], "otda")
            self.assertEqual(signed.with_script(0, b""), candidate)
            self.assertTrue(signed.inputs[0].script)
            with self.assertRaisesRegex(ValueError, "select an available spend family"):
                assemble_pels(artifact, parent, candidate)
            with self.assertRaisesRegex(ValueError, "ordered outputs"):
                assemble_pels(artifact, parent, replace(candidate, outputs=candidate.outputs[::-1]), "otda")

    @unittest.skipUnless(chain_available(), "requires pinned chain-gang")
    def test_materialized_locks_enforce_the_forth_contract(self):
        from fourthgraph.bsv.chain_gang import validate_at_heights

        def validate(tx, parent, activation=2):
            validate_at_heights(tx, (parent,), spend_height=4, activation_height=activation, utxo_heights=(3,))

        amount_source = SOURCE.replace("tx-locktime 42 = verify", "tx-prevout-amount 11000 = verify")
        amount_lock = build(amount_source)
        wide_script = bytes.fromhex("006a4d2c01") + bytes(300)
        large_output = SOURCE.replace("006a055245414459", wide_script.hex())
        compact = build(SOURCE, family="both")
        full = build(large_output, family="bip143")
        self.assertEqual(full["selection"]["layout"], "full")
        for artifact, outputs in (
            (build(target="bip143-v1"), OUTPUTS), (build(family="otda"), OUTPUTS),
            (compact, OUTPUTS), (amount_lock, OUTPUTS),
            (full, (OUTPUTS[0], Output(0, wide_script))),
        ):
            parent, candidate = transactions(artifact, outputs)
            for name in artifact["paths"]:
                with self.subTest(path=name, target=artifact["target"], layout=artifact["selection"]["layout"]):
                    signed, _ = assemble_pels(artifact, parent, candidate, name)
                    activation = 10 if artifact["target"] == "bip143-v1" else 2
                    validate(signed, parent, activation)
                    with self.assertRaises((ValueError, RuntimeError)):
                        validate(replace(signed, outputs=signed.outputs[::-1]), parent, activation)
                    if artifact["constraints"]["locktime"] is not None:
                        with self.assertRaises((ValueError, RuntimeError)):
                            validate(replace(signed, locktime=43), parent, activation)
                    if name == "otda":
                        with self.assertRaises((ValueError, RuntimeError)):
                            validate(signed, parent, activation=10)
        parent, candidate = transactions(amount_lock)
        prevout = replace(parent.outputs[0], value=11_001)
        parent = replace(parent, outputs=(prevout,))
        candidate = replace(candidate, inputs=(Input(parent.txid_wire(), 0),))
        with self.assertRaisesRegex(ValueError, "prevout amount"):
            assemble_pels(amount_lock, parent, candidate)
        full = preimage_forkid(candidate, 0, prevout.value, BINDING_CODE, FLAG)
        context = LinkedContext(BINDING_CODE, FLAG, len(OUTPUTS)).pack(full)
        with self.assertRaises((ValueError, RuntimeError)):
            validate(candidate.with_script(0, push(context)), parent)
