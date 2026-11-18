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
from tx_engine import Script, Tx, TxIn, TxOut

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
        cls.lock = locking_script(owner, UNIVERSAL_FLAGS, version=7)
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
                    check(child(parents, [650, 700], {ix: w}), parents, ix)
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
                check(child(parents, [900], {1: w}), parents, 1)
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
