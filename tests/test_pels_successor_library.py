"""Exercise a dynamic PELS successor rule with no payment-project imports."""

from hashlib import sha256
from importlib.metadata import PackageNotFoundError
import unittest

from fourthgraph.benchmark.validation import CONTEXT_PIN, chain_metadata
from fourthgraph.bsv.script import push
from fourthgraph.bsv.transaction import Input, Output, Transaction, preimage_forkid
from fourthgraph.compiler.script_builder import ScriptBuilder
from fourthgraph.stdlib import capabilities


SOURCE = """
REQUIRE stdlib/wallet/pels-verify.fth

: draft-tag ( -- bytes ) bytes-hex 0300000000 ;
: ready-tag ( -- bytes ) bytes-hex 0900000000 ;

: next-status ( script -- script )
    op-dup draft-tag bsv-push op-equal op-if
        op-drop ready-tag bsv-push
    op-else
        ready-tag bsv-push op-equalverify draft-tag bsv-push
    op-endif
;

: status-rule ( script -- script )
    op-8 op-num2bin op-swap next-status op-swap
;

: status-lock ( script bytes -- script )
    bsv-push op-codeseparator
    bsv-empty status-rule pels-verify op-drop op-1
;
"""
DRAFT, READY = (value.to_bytes(5, "little") for value in (3, 9))


def pinned_chain_available():
    try:
        return chain_metadata()["commit"] == CONTEXT_PIN
    except PackageNotFoundError:
        return False


class PelsSuccessorLibraryTests(unittest.TestCase):
    def setUp(self):
        self.builder = ScriptBuilder(SOURCE)

    def test_bundled_template_keeps_exact_script_and_records_imports(self):
        versions = {row.name for row in self.builder.library_imports}
        self.assertTrue({"std/wallet/pels-verify", "std/wallet/pels-binding",
                         "std/wallet/pels-successor"} <= versions)
        draft = self.builder.emit("status-lock", b"", DRAFT)
        self.assertEqual(len(draft), 645)
        self.assertEqual(sha256(draft).hexdigest(), "f2e8d422e2e6a27542590114a3ca46f564a62b1c872f778bd5f4030cca6e8e57")

    def test_catalog_records_build_and_spend_requirements(self):
        libraries = capabilities()
        for module, word, runtime in (
            ("pels-verify", "pels-verify", ["tail", "head", "state"]),
            ("pels-successor", "pels-assert-successor", ["state", "preimage"]),
        ):
            with self.subTest(word=word):
                interface = libraries[f"std/wallet/{module}"]["interfaces"][word]
                self.assertEqual([field["name"] for field in interface["runtime_inputs"]], runtime)
                build = {field["name"]: field["type"] for field in interface["build_parameters"]}
                self.assertEqual(build, {"prefix": "script", "state-amount-rule": "script"})
                context = {field["name"]: field["description"] for field in interface["transaction_context"]}
                self.assertEqual(context["sighash"], "BIP143 ALL (0x41)")
                self.assertEqual(context["input-count"], "Exactly one input")
                self.assertEqual(context["output-count"], "Exactly one successor output")
                self.assertIn("script-code", context)

    @unittest.skipUnless(pinned_chain_available(), "requires pinned chain-gang")
    def test_non_counter_rule_follows_actual_parent_outputs(self):
        from fourthgraph.bsv.chain_gang import validate_at_heights

        lock = self.builder.emit("status-lock", b"", DRAFT)
        parent = Transaction((Input(bytes(32), 0),), (Output(10_000, lock),))
        for phase, expected in enumerate((READY, DRAFT)):
            previous = parent.outputs[0]
            successor = push(expected) + previous.script[6:]
            self.assertEqual(successor, self.builder.emit("status-lock", b"", expected))
            tx = Transaction((Input(parent.txid_wire(), 0),), (Output(previous.value, successor),))
            preimage = preimage_forkid(tx, 0, previous.value, previous.script[7:], 0x41)
            witness = push(preimage[-8:]) + push(preimage[:-40])
            signed = tx.with_script(0, witness)
            validate_at_heights(signed, (parent,), spend_height=4 + phase, activation_height=2,
                                utxo_heights=(3 + phase,))
            parent = signed
