"""Check nChain's unmodified PUSHTX reference in a full synthetic spending Tx."""
import unittest

from tx_engine import SIGHASH, Script
from src.zkscript.transaction_introspection.transaction_introspection import TransactionIntrospection
from src.zkscript.script_types.unlocking_keys.transaction_introspection import PushTxUnlockingKey
from handwritten import FLAGS
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
