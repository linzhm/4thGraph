"""Build and exercise the bundled verifier without the payment example."""

from importlib import import_module
import unittest

from shared.evaluate import ScriptError, evaluate
from shared.script import asm, push

ScriptBuilder = import_module("projects.4thgraph.script_builder").ScriptBuilder


class Bip340LibraryTests(unittest.TestCase):
    def test_imported_verifier(self):
        app = ScriptBuilder("""
            REQUIRE stdlib/bip340.fth
            : detached ( script -- script ) bip340-verify ;
        """)
        self.assertEqual({item.name for item in app.library_imports},
                         {"std/bip340", "std/script-fragments", "std/secp256k1"})
        lock = app.emit("detached", b"")
        # Official BIP340 vector 0 plus the reconstructed even y coordinates.
        fields = (
            bytes(32),
            bytes.fromhex("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
            bytes.fromhex("388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672"),
            bytes.fromhex("e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca8215"
                          "25f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"),
            bytes.fromhex("7b64f7b795a4e915a02ff65c521b8d4b75d237e851143cc54b05da1342a65d08"),
        )
        outer = push(b"outer") + asm("OP_TOALTSTACK")
        self.assertEqual(evaluate(outer + b"".join(map(push, fields)) + lock), ([b"\x01"], [b"outer"]))
        with self.assertRaises(ScriptError):
            evaluate(push(bytes([1])) + b"".join(map(push, fields[1:])) + lock)
