"""Check nChain's unmodified PUSHTX reference in a full synthetic spending Tx."""
import json
import unittest

from tx_engine import SIGHASH, Script
from src.zkscript.transaction_introspection.transaction_introspection import TransactionIntrospection
from src.zkscript.script_types.unlocking_keys.transaction_introspection import PushTxUnlockingKey
from handwritten import FLAGS, _assembly, push
from test_handwritten import parent, spend


class ReferenceTests(unittest.TestCase):
    def test_pushtx_all_six_types(self):
        suffix = Script.parse_string("OP_CHECKSIG")
        for t in FLAGS:
            with self.subTest(flag=hex(t)):
                flag = SIGHASH(t)
                lock = TransactionIntrospection.pushtx(
                    sighash_flags=flag, is_opcodeseparator=True, is_checksigverify=False
                )
                funding = parent(lock, 1000, "44")
                unsigned = spend([funding], [900])
                proof = PushTxUnlockingKey(unsigned, 0, suffix, 1000).to_unlocking_script(
                    sighash_flags=flag, is_sig_hash_preimage=True, append_constants=True
                )
                spend([funding], [900], proof).validate([funding])
                altered = spend([funding], [899], proof)
                if (t & 31) == 2:
                    altered.validate([funding])
                else:
                    with self.assertRaisesRegex(ValueError, "Error evaluating the script"):
                        altered.validate([funding])

    def test_byte_count_same_binding(self):
        # Both locks accept a BIP143 ALL preimage and end with separator + CHECKSIG.
        flag = SIGHASH(0x41)
        _, emit = _assembly(5)
        manual = Script()
        manual.append_data(push(bytes([flag])) + emit("OP_TOALTSTACK") + emit("OP_HASH256")
                           + emit("@UINT256BE") + emit("@K1_BIND_DIGEST_STANDARD"))
        upstream = TransactionIntrospection.pushtx(
            sighash_flags=flag, is_opcodeseparator=True, is_checksigverify=False,
            verify_constants=True, clean_constants=True, is_sig_hash_preimage=True)
        sizes = {}
        for name, lock in (("handwritten", manual), ("nchain", upstream)):
            p = parent(lock, 1000, "44")
            tx = spend([p], [900])
            proof = PushTxUnlockingKey(tx, 0, lock, 1000).to_unlocking_script(
                sighash_flags=flag, is_sig_hash_preimage=True, append_constants=name == "nchain")
            spend([p], [900], proof).validate([p])
            with self.assertRaises(ValueError):
                spend([p], [899], proof).validate([p])
            sizes[name] = {"lock": len(lock.raw_serialize()), "unlock": len(proof.raw_serialize())}
        print("BINDING_BYTES", json.dumps(sizes, sort_keys=True), flush=True)
