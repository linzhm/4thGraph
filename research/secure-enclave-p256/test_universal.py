"""Input-level acceptance on the released BSV interpreter, with supplied local UTXOs."""
from dataclasses import replace
import os
import json
from time import perf_counter_ns
from pathlib import Path
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
import requests
from tx_engine import Script, Tx, TxIn, TxOut, sig_hash, sig_hash_preimage

from handwritten import UNIVERSAL_FLAGS, locking_script, match_locking_script, replace_owner_hash160
from test_native import TRUE, child, parent, signer
from universal import authorization, universal_unlocking_script


def sign(auth, key):
    der = key.sign(auth.digest(), ec.ECDSA(utils.Prehashed(hashes.SHA256()), deterministic_signing=True))
    r, s = utils.decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def check(tx, parents, ix, valid=True):
    out = parents[ix].tx_outs[0]
    cookie = Path(os.environ["REGTEST_COOKIE"]).read_text().strip().split(":", 1)
    flags = sum(1 << b for b in (1, 2, 3, 16, 18, 19, 20, 21))
    request = dict(tx=tx.serialize().hex(), n=ix, flags=flags, reportflags=True,
                   txo=dict(lock=out.script_pubkey.raw_serialize().hex(), value=out.amount, height=3))
    r = requests.post("http://127.0.0.1:18443", auth=tuple(cookie), timeout=30,
                      json=dict(jsonrpc="1.0", id=1, method="verifyscript", params=[[request], False, 5000]))
    data = r.json()
    if data.get("error"):
        raise AssertionError(data["error"])
    answer = data["result"][0]
    if answer["result"] != ("ok" if valid else "error"):
        raise AssertionError((valid, answer))
    if answer["flags"] & flags != flags:
        raise AssertionError(("missing verification flags", answer))


class UniversalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key, cls.pub, owner = signer()
        cls.lock = locking_script(owner, version=8)
        cls.p = parent(cls.lock, 1000, "22")
        cls.fee = parent(TRUE, 500, "33")

    def data(self, parents, ix, amounts, flag):
        a = authorization(child(parents, amounts), ix, parents[ix].tx_outs[0].amount, flag)
        return a, sign(a, self.key)

    def unlock(self, parents, ix, a, signature):
        return universal_unlocking_script(parents[ix].serialize(), a, self.pub, signature)

    def test_all_modes_same_utxo(self):
        for ix in (0, 1):
            parents = [self.p, self.fee] if ix == 0 else [self.fee, self.p]
            for flag in UNIVERSAL_FLAGS:
                with self.subTest(ix=ix, flag=hex(flag)):
                    a, sig = self.data(parents, ix, [650, 700], flag)
                    w = self.unlock(parents, ix, a, sig)
                    tx = child(parents, [650, 700], {ix: w})
                    tx.validate(parents)
                    check(tx, parents, ix)
                    values = [650, 700]
                    values[ix] -= 1
                    check(child(parents, values, {ix: w}), parents, ix, valid=(flag & 31 == 2))

    def test_unpaired(self):
        parents = [self.fee, self.p]
        for flag in (0x43, 0xc3, 0x63, 0xe3):
            with self.subTest(flag=hex(flag)):
                a, sig = self.data(parents, 1, [900], flag)
                self.assertEqual(a.companion, bool(flag & 0x20))
                w = self.unlock(parents, 1, a, sig)
                tx = child(parents, [900], {1: w})
                tx.validate(parents)
                check(tx, parents, 1)
                if a.companion:
                    script = Script.parse_string("OP_CHECKSIG")
                    self.assertEqual(bytes(sig_hash(tx, 1, script, 1000, flag)), b"\x01" + bytes(31))
                    with self.assertRaises(ValueError):
                        sig_hash_preimage(tx, 1, script, 1000, flag)
                check(child(parents, [899], {1: w}), parents, 1)
                check(child(parents, [898, 1], {1: w}), parents, 1, False)
                if a.companion:
                    other = [self.fee, parent(self.lock, 1000, "55")]
                    a2, _ = self.data(other, 1, [900], flag)
                    check(child(other, [900], {1: self.unlock(other, 1, a2, sig)}), other, 1, False)
                    normal, nsig = self.data(parents, 1, [900], flag & ~0x20)
                    self.assertNotEqual(normal.digest(), a.digest())
                    check(child(parents, [900], {1: self.unlock(parents, 1, a, nsig)}), parents, 1, False)

    def test_policy_and_mixed(self):
        _, _, owner = signer()
        lock = locking_script(owner, (0x63,), version=7)
        parsed = match_locking_script(lock.raw_serialize())
        self.assertEqual((parsed.version, parsed.allowed_types), (7, (0x63,)))
        self.assertEqual(match_locking_script(replace_owner_hash160(lock.raw_serialize(), bytes(20))).allowed_types, (0x63,))
        ps = [self.fee, parent(lock, 1000, "88")]
        for flag in (0x43, 0x63):
            a, sig = self.data(ps, 1, [900], flag)
            check(child(ps, [900], {1: self.unlock(ps, 1, a, sig)}), ps, 1, flag == 0x63)
        ps = [self.p, parent(self.lock, 1000, "77")]
        wa = self.unlock(ps, 0, *self.data(ps, 0, [900], 0x42))
        wb = self.unlock(ps, 1, *self.data(ps, 1, [900], 0x61))
        tx = child(ps, [900], {0: wa, 1: wb})
        tx.validate(ps)
        check(tx, ps, 0)
        check(tx, ps, 1)

    def test_ordinal_and_size(self):
        ps = [self.fee, self.p, parent(TRUE, 100, "66")]
        a, sig = self.data(ps, 1, [900], 0x61)
        for ix in (0, 2, 3):
            w = self.unlock(ps, 1, replace(a, ordinal=ix), sig)
            check(child(ps, [900], {1: w}), ps, 1, False)
        ps = [Tx(1, [TxIn(f"{i+1:064x}", 0, Script())], [TxOut(5, TRUE)], 0) for i in range(252)] + [self.p]
        a, sig = self.data(ps, 252, [900], 0x61)
        check(child(ps, [900], {252: self.unlock(ps, 252, a, sig)}), ps, 252)
        print("UNIVERSAL_LOCK_BYTES", len(self.lock.raw_serialize()), flush=True)

    def test_small_sample(self):
        # End-to-end loopback RPC time, including transaction encoding and HTTP.
        # All keys, signatures, spend objects and native proof inputs are prepared first.
        ps = [self.fee, self.p]
        cases = {}
        for name, flag, amounts in (("bip143_all", 0x41, [800, 500]), ("otda_all", 0x61, [800, 500]),
                                    ("bip143_unpaired", 0x43, [900]), ("otda_unpaired", 0x63, [900])):
            a, sig = self.data(ps, 1, amounts, flag)
            w = self.unlock(ps, 1, a, sig)
            tx = child(ps, amounts, {1: w})
            check(tx, ps, 1)
            cases[name] = (tx, {"elapsed_ns": 0, "count": 0, "preimage": len(a.preimage),
                                "unlock": len(w.raw_serialize()), "lock": len(self.lock.raw_serialize())})
        for i in range(32):
            names = list(cases)
            names = names[i % 4:] + names[:i % 4]
            for name in names:
                tx, stats = cases[name]
                start = perf_counter_ns()
                check(tx, ps, 1)
                stats["elapsed_ns"] += perf_counter_ns() - start
                stats["count"] += 1
        print("UNIVERSAL_RPC_SAMPLE", json.dumps({k: v[1] for k, v in cases.items()}, sort_keys=True), flush=True)

    def test_public_witness_boundaries(self):
        # Malformed public fields must fail under the real node, independently
        # of how strictly a wallet checks its own output.
        from handwritten import GROUP_ORDER_R1
        ps = [self.p]
        a, good = self.data(ps, 0, [900], 0x41)
        order = GROUP_ORDER_R1
        r, s = int.from_bytes(good[:32], "big"), int.from_bytes(good[32:], "big")
        inverse = pow(s, -1, order)

        def run(rr, ss, inv, valid=False):
            w = Script()
            for field in (ps[0].serialize(), a.preimage, self.pub,
                          rr.to_bytes(32, "big") + ss.to_bytes(32, "big"),
                          bytes(4), inv.to_bytes(32, "little")):
                w.append_pushdata(field)
            w.append_data(bytes([0]))
            check(child(ps, [900], {0: w}), ps, 0, valid)

        run(r, s, inverse, True)
        for rr, ss in ((0, s), (order, s), (r, 0), (r, order)):
            with self.subTest(r_valid=(0 < rr < order), s_valid=(0 < ss < order)):
                run(rr, ss, inverse)
        for bad_inverse in (0, order, (inverse + 1) % order):
            run(r, s, bad_inverse)
        # ECDSA has two valid s representatives. A corresponding inverse is required.
        run(r, order - s, inverse)
        run(r, order - s, order - inverse, True)

    def test_point_validation_independent_of_owner_hash(self):
        from hashlib import new, sha256
        key, _, _ = signer()
        prime = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
        for x, y in ((0, 0), (prime, 1), (1, prime)):
            invalid = bytes([4]) + x.to_bytes(32, "big") + y.to_bytes(32, "big")
            owner = new("ripemd160", sha256(invalid).digest()).digest()
            ps = [parent(locking_script(owner, version=8), 1000, "22")]
            a = authorization(child(ps, [900]), 0, 1000, 0x41)
            w = universal_unlocking_script(ps[0].serialize(), a, invalid, sign(a, key))
            check(child(ps, [900], {0: w}), ps, 0, False)

    def test_checked_wallet_output(self):
        from tempfile import TemporaryDirectory
        from pathlib import Path
        from checked_wallet import sign_spend

        def device_callback(digest):
            der = self.key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()), deterministic_signing=True))
            r, s = utils.decode_dss_signature(der)
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")

        ps = [self.fee, self.p]
        with TemporaryDirectory() as directory:
            ledger = Path(directory) / "history.sqlite"
            for flag, amounts in ((0x41, [900]), (0x61, [900]), (0x63, [900])):
                tx = child(ps, amounts)
                w = sign_spend(tx, 1, self.p, flag, self.pub, device_callback, ledger)
                check(child(ps, amounts, {1: w}), ps, 1)
