"""Offline acceptance and paired small-sample timings for native SHA256d payment locks."""
import hashlib
import json
from time import perf_counter_ns
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from tx_engine import Script, Tx, TxIn, TxOut, sig_hash, sig_hash_preimage

from handwritten import (flags_for, locking_script, match_locking_script, native_unlocking_script,
                         replace_owner_hash160)
from test_handwritten import parent

SUFFIX = Script.parse_string("OP_CHECKSIG")
TRUE = Script.parse_string("OP_1")


def signer(secret=7):
    key = ec.derive_private_key(secret, ec.SECP256R1())
    pub = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return key, pub, hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()


def child(parents, amounts, witnesses=None):
    witnesses = witnesses or {}
    return Tx(2, [TxIn(p.id(), 0, witnesses.get(i, Script())) for i, p in enumerate(parents)],
              [TxOut(a, TRUE) for a in amounts], 0)


def witness(ver, key, parents, amounts, index, flag, *, wrong_parent=None, tagged=False):
    tx = child(parents, amounts)
    amount = parents[index].tx_outs[0].amount
    pre = bytes(sig_hash_preimage(tx, index, SUFFIX, amount, flag))
    digest = hashlib.sha256(hashlib.sha256(pre).digest()).digest()
    if digest != bytes(sig_hash(tx, index, SUFFIX, amount, flag)):
        raise AssertionError("engine preimage/digest mismatch")
    if tagged:
        digest = hashlib.sha256(b"BSV/SecureEnclave/P256/v1\x00" + pre).digest()
    r, s = utils.decode_dss_signature(key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()), deterministic_signing=True)))
    pub = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    unlock = native_unlocking_script(wrong_parent or parents[index].serialize(), pre, pub, sig, version=ver, input_index=index)
    return unlock, pre


def from_raw(raw):
    out = Script()
    out.append_data(raw)
    return out


class DigestPaymentTests(unittest.TestCase):
    def test_flags_positions_and_commitments(self):
        key, _, owner = signer()
        for ver in (5, 6):
            flags = flags_for(ver)
            p = parent(locking_script(owner, flags, version=ver), 1000, "22")
            fee = parent(TRUE, 500, "33")
            for ix in (0, 1):
                parents = [p, fee] if ix == 0 else [fee, p]
                for flag in flags:
                    with self.subTest(ver=ver, ix=ix, flag=flag):
                        w, _ = witness(ver, key, parents, [650, 700], ix, flag)
                        child(parents, [650, 700], {ix: w}).validate(parents)
                        changed = [650, 700]
                        changed[ix] -= 1
                        tx = child(parents, changed, {ix: w})
                        if flag & 31 == 2:
                            tx.validate(parents)
                        else:
                            with self.assertRaises(ValueError):
                                tx.validate(parents)
                        if ix == 1 and flag & 31 == 3:
                            with self.assertRaises(ValueError):
                                child(parents, [650], {ix: w}).validate(parents)

    def test_hints_and_owner(self):
        key, _, owner = signer()
        fee = parent(TRUE, 500, "33")
        for ver in (5, 6):
            raw = locking_script(owner, flags_for(ver), version=ver).raw_serialize()
            parsed = match_locking_script(raw)
            self.assertEqual((parsed.version, parsed.owner_hash160, set(parsed.allowed_types)), (ver, owner, set(flags_for(ver))))
            self.assertEqual(match_locking_script(replace_owner_hash160(raw, bytes(20))).version, ver)
            self.assertIsNone(match_locking_script(raw[:-1]))
            parents = [fee, parent(from_raw(raw), 1000, "22"), parent(TRUE, 100, "44")]
            flag = 0x61 if ver == 6 else 0x41
            args = (ver, key, parents, [900], 1, flag)
            w, _ = witness(*args)
            child(parents, [900], {1: w}).validate(parents)
            original = w.raw_serialize()
            rejected = [from_raw(original[:-32] + bytes(32)), witness(*args, wrong_parent=fee.serialize())[0],
                        witness(*args, tagged=True)[0], witness(ver, signer(11)[0], parents, [900], 1, flag)[0]]
            if ver == 6:
                for hint in (0, 2, 3):
                    rejected.append(from_raw(original[:-37] + hint.to_bytes(4, "little") + original[-33:]))
            for invalid in rejected:
                with self.assertRaises(ValueError):
                    child(parents, [900], {1: invalid}).validate(parents)

    def test_compactsize_253(self):
        key, _, owner = signer()
        parents = [Tx(1, [TxIn(f"{i+1:064x}", 0, Script())], [TxOut(5, TRUE)], 0) for i in range(252)]
        parents.append(parent(locking_script(owner, version=6), 1000, "44"))
        w, pre = witness(6, key, parents, [900], 252, 0x61)
        self.assertEqual(pre[4:7], bytes.fromhex("fdfd00"))
        child(parents, [900], {252: w}).validate(parents)

    def test_mixed_inputs(self):
        a, _, ha = signer()
        b, _, hb = signer(13)
        parents = [parent(locking_script(ha, (0x42,), version=5), 1000, "22"),
                   parent(locking_script(hb, version=6), 500, "33")]
        wa, _ = witness(5, a, parents, [900], 0, 0x42)
        wb, _ = witness(6, b, parents, [900], 1, 0x61)
        child(parents, [900], {0: wa, 1: wb}).validate(parents)
        with self.assertRaises(ValueError):
            child(parents, [899], {0: wa, 1: wb}).validate(parents)

    def test_single_unpaired(self):
        key, _, owner = signer()
        for ver in (5, 6):
            flag = 0x43 if ver == 5 else 0x63
            parents = [parent(TRUE, 500, "33"), parent(locking_script(owner, (flag,), version=ver), 1000, "22")]
            if ver == 5:
                w, pre = witness(ver, key, parents, [900], 1, flag)
                self.assertEqual(pre[118:150], bytes(32))
                with self.assertRaises(ValueError):
                    child(parents, [900], {1: w}).validate(parents)
            else:
                # Engine 0.13.1 raises here; the pinned BSV node returns uint256(1).
                with self.assertRaises(ValueError):
                    sig_hash_preimage(child(parents, [900]), 1, SUFFIX, 1000, flag)


def sample():
    pools, report = {}, {}
    for ver in (5, 6):
        cases = []
        for j in range(8):
            key, _, owner = signer(7+j)
            lock = locking_script(owner, version=ver)
            parents = [parent(lock, 1000, "22")]
            w, pre = witness(ver, key, parents, [900-j], 0, 0x41 if ver == 5 else 0x61)
            tx = child(parents, [900-j], {0: w})
            tx.validate(parents)
            cases.append((tx, parents))
        pools[ver] = cases
        report[ver] = dict(lock=len(lock.raw_serialize()), preimage=len(pre), parent=len(parents[0].serialize()),
                           unlock=len(w.raw_serialize()), spending_tx=len(tx.serialize()), elapsed_ns=0, validations=0)
    for block in range(16):
        for ver in ((5, 6) if block % 2 == 0 else (6, 5)):
            start = perf_counter_ns()
            for k in range(32):
                tx, parents = pools[ver][k % 8]
                tx.validate(parents)
            report[ver]["elapsed_ns"] += perf_counter_ns() - start
            report[ver]["validations"] += 32
    print("NATIVE_SAMPLE", json.dumps(report, sort_keys=True), flush=True)


if __name__ == "__main__":
    sample()
