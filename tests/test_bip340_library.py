"""Build and exercise the bundled verifier without the payment example."""

import unittest

from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.bsv.script import asm, push

from fourthgraph.compiler.script_builder import ScriptBuilder


class Bip340LibraryTests(unittest.TestCase):
    def test_imported_verifier(self):
        app = ScriptBuilder("""
            REQUIRE stdlib/bip340.fth
            : detached ( script -- script ) bip340-verify ;
        """)
        self.assertEqual({item.name for item in app.library_imports},
                         {"std/bip340", "std/bsv", "std/script-fragments", "std/secp256k1"})
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
        cases = {
            "changed message": (bytes([1]), *fields[1:]),
            "missing witness": fields[:-1],
            "extra main-stack item": (b"extra", *fields),
        }
        for index, label in enumerate(("key x", "key y", "signature", "nonce y"), start=1):
            value = fields[index]
            cases[f"short {label}"] = (*fields[:index], value[:-1], *fields[index + 1:])
            cases[f"long {label}"] = (*fields[:index], b"\0" + value, *fields[index + 1:])
        for index in (2, 4):
            value = fields[index]
            odd = value[:-1] + bytes([value[-1] ^ 1])
            cases[f"odd y at slot {index}"] = (*fields[:index], odd, *fields[index + 1:])
        for label, invalid in cases.items():
            with self.subTest(label=label), self.assertRaises(ScriptError):
                evaluate(outer + b"".join(map(push, invalid)) + lock)
