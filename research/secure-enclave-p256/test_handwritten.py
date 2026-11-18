import hashlib
import unittest
from importlib.metadata import version

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from tx_engine import SIGHASH, Script, Tx, TxIn, TxOut, sig_hash_preimage

from handwritten import FLAGS, locking_script, unlocking_script


def parent(lock, amount, label):
    return Tx(1, [TxIn(label * 32, 0, Script())], [TxOut(amount, lock)], 0)


def spend(parents, amounts, unlock=None, index=0, sequences=None):
    sequences = sequences or [0xffffffff] * len(parents)
    inputs = [TxIn(tx.id(), 0, unlock if i == index and unlock is not None else Script(), sequences[i])
              for i, tx in enumerate(parents)]
    return Tx(1, inputs, [TxOut(amount, Script.parse_string("OP_1")) for amount in amounts], 0)


class PaymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Public fixture key, never a wallet credential.
        cls.key = ec.derive_private_key(7, ec.SECP256R1())
        cls.pub = cls.key.public_key().public_bytes(serialization.Encoding.X962,
                                                    serialization.PublicFormat.UncompressedPoint)
        owner = hashlib.new("ripemd160", hashlib.sha256(cls.pub).digest()).digest()
        cls.default = parent(locking_script(owner), 1000, "11")
        lock = locking_script(owner, tuple(FLAGS))
        cls.funding = parent(lock, 1000, "11")
        cls.fee = parent(Script.parse_string("OP_1"), 500, "22")
        cls.extra = parent(Script.parse_string("OP_1"), 400, "33")
        print(f"tx-engine {version('tx-engine')}; default lock {len(cls.default.tx_outs[0].script_pubkey.raw_serialize())} bytes; six-type lock {len(lock.raw_serialize())} bytes", flush=True)

    def witness(self, flag, parents, amounts, index=0, parent_bytes=None, sig_override=None, claimed_type=None, key=None):
        tx = spend(parents, amounts, index=index)
        # Only the single final OP_CHECKSIG is after the executed separator.
        amount = parents[index].tx_outs[0].amount
        p = sig_hash_preimage(tx, index, Script.parse_string("OP_CHECKSIG"), amount, SIGHASH(flag))
        self.assertEqual(len(p), 158)
        self.assertEqual(p[68:100], parents[index].hash())
        self.assertEqual(p[-4:], flag.to_bytes(4, "little"))
        digest = hashlib.sha256(b"BSV/SecureEnclave/P256/v1\x00" + p).digest()
        key = self.key if key is None else key
        pub = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        der = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(der)
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        if claimed_type is not None:
            p = p[:-4] + claimed_type.to_bytes(4, "little")
        return unlocking_script(parent_bytes or parents[index].serialize(), p, pub, sig_override or sig)

    def expect(self, valid, parents, amounts, unlock, index=0, sequences=None):
        tx = spend(parents, amounts, unlock, index, sequences)
        if valid:
            tx.validate(parents)
        else:
            with self.assertRaisesRegex(ValueError, "Error evaluating the script"):
                tx.validate(parents)

    def test_all_six_modes_on_one_lock(self):
        parents = [self.funding, self.fee]
        for flag in FLAGS:
            with self.subTest(flag=hex(flag)):
                sig = self.witness(flag, parents, [800, 300])
                self.expect(True, parents, [800, 300], sig)
                # Preserve the exact scriptSig for every mutation.
                self.expect((flag & 31) == 2, parents, [799, 300], sig)
                self.expect((flag & 31) == 2, parents, [1100], sig)
                self.expect((flag & 31) != 1, parents, [800, 299], sig)
                self.expect(bool(flag & 128), parents + [self.extra], [800, 300], sig)
                self.expect(False, parents, [800, 300], sig, sequences=[0xfffffffe, 0xffffffff])
                self.expect(flag != 0x41, parents, [800, 300], sig, sequences=[0xffffffff, 0xfffffffe])

    def test_retarget_recipients(self):
        parents = [self.funding, self.fee]
        destination = Script.parse_string("OP_DUP OP_HASH160 0x" + "ab" * 20 + " OP_EQUALVERIFY OP_CHECKSIG")
        for flag in FLAGS:
            with self.subTest(flag=hex(flag)):
                sig = self.witness(flag, parents, [800, 300])
                inputs = [TxIn(parents[0].id(), 0, sig), TxIn(parents[1].id(), 0, Script())]
                retargeted = Tx(1, inputs, [TxOut(1100, destination)], 0)
                if (flag & 31) == 2:
                    retargeted.validate(parents)
                else:
                    with self.assertRaisesRegex(ValueError, "Error evaluating the script"):
                        retargeted.validate(parents)

    def test_signed_type_cannot_be_changed_to_none(self):
        parents = [self.funding, self.fee]
        sig = self.witness(0x41, parents, [800, 300], claimed_type=0x42)
        self.expect(False, parents, [800, 300], sig)

    def test_single_missing_pair_and_none_unpaired(self):
        parents = [self.fee, self.funding]
        for flag in (0x42, 0xc2, 0x43, 0xc3):
            with self.subTest(flag=hex(flag)):
                sig = self.witness(flag, parents, [900], index=1)
                self.expect((flag & 31) == 2, parents, [900], sig, index=1)

    def test_lock_allowlist(self):
        parents = [self.default, self.fee]
        for flag in FLAGS:
            with self.subTest(flag=hex(flag)):
                self.expect(flag == 0x41, parents, [800, 300], self.witness(flag, parents, [800, 300]))

    def test_parent_and_signature(self):
        parents = [self.funding, self.fee]
        for override in ({"parent_bytes": self.fee.serialize()}, {"sig_override": bytes(64)}):
            self.expect(False, parents, [800, 300], self.witness(0x41, parents, [800, 300], **override))

    def test_two_independent_authorizations(self):
        controller = ec.derive_private_key(13, ec.SECP256R1())
        pub = controller.public_key().public_bytes(serialization.Encoding.X962,
                                                  serialization.PublicFormat.UncompressedPoint)
        owner = hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()
        # B has a different private key. Each B lock permits exactly its designated mode.
        for b_flag in (0x43, 0x41):
            b = parent(locking_script(owner, (b_flag,)), 500, "55")
            parents = [self.funding, b]
            for a_flag in (0x42, 0xc2):
                with self.subTest(a=hex(a_flag), b=hex(b_flag)):
                    amounts = [800, 300]
                    a_sig = self.witness(a_flag, parents, amounts)
                    b_sig = self.witness(b_flag, parents, amounts, index=1, key=controller)
                    inputs = [TxIn(self.funding.id(), 0, a_sig), TxIn(b.id(), 0, b_sig)]

                    def child(values):
                        return Tx(1, inputs, [TxOut(v, Script.parse_string("OP_1")) for v in values], 0)

                    child(amounts).validate(parents)
                    if b_flag == 0x43:
                        child([799, 300]).validate(parents)
                    else:
                        with self.assertRaisesRegex(ValueError, "Error evaluating the script"):
                            child([799, 300]).validate(parents)
                    with self.assertRaisesRegex(ValueError, "Error evaluating the script"):
                        child([800, 299]).validate(parents)
                    # Strip B and its signature. Keep the original A scriptSig, replace all outputs.
                    # 900 sat is affordable by A alone, so failure cannot be due to overspending.
                    self.expect(a_flag == 0xc2, [self.funding], [900], a_sig)

    def test_prior_secure_enclave_format_vector(self):
        p = bytes.fromhex("010000006906346983736310bedde3e7d86af3999a4eb87295f429e8e58189cfa7f25875752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632ad09dc2a9f5ac84e9f40a7b8113b958fef4bbf8cc9c00d03d0f4f7b728e8aa88270000000001ace803000000000000ffffffff10a6bf93b4eca215f9f7201a9e2fb6c4a6b53e094c6c1750c43c97ed86bbbdd00000000041000000")
        raw = bytes.fromhex("3ae7b158956c12b5f1429b6702bac89acf3d728f5aed1ca7f2d26d98b4923e7051f325c04de0c4eece97768385fc43132a4e5d0cf1b0ba2b338683398545bb22")
        der = utils.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        self.key.public_key().verify(der, b"BSV/SecureEnclave/P256/v1\x00" + p, ec.ECDSA(hashes.SHA256()))


if __name__ == "__main__":
    unittest.main()
