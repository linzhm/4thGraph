"""BIP327 interoperability, interrupted signing, and matched BSV 2-of-2 acceptance."""

from dataclasses import replace
import json
import os
from pathlib import Path
import unittest

from bip340 import verify
from compare_threshold import TEMPLATES, native_2of2_coin
from musig2_fixture import FixtureNonce, Policy, SigningRound, fixture_keys
from shared.benchmark_cases import synthetic_parent
from shared.benchmark_validation import Node, chain_verdict
from shared.transaction import Input, Transaction
from test_schnorr import MODES


class MuSig2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = (Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
                    if "REGTEST_COOKIE" in os.environ else None)

    def check_spend(self, tx, parents, expected):
        self.assertIs(chain_verdict(tx, parents), all(expected))
        if self.node:
            self.assertEqual(self.node.verdicts(tx, parents), expected)

    def test_bip327_two_party_signature_aggregation_vectors(self):
        path = Path(__file__).with_name("comparison") / "bip327-sig-agg.json"
        data = json.loads(path.read_text(encoding="ascii"))
        self.assertEqual(len(data["vectors"]), 2)
        for index, row in enumerate(data["vectors"]):
            with self.subTest(vector=index):
                public, nonces, shares = (tuple(map(bytes.fromhex, row[field]))
                                          for field in ("pubkeys", "nonces", "partials"))
                policy = Policy(public)
                self.assertEqual(policy.aggregate_x.hex(), row["aggregate_x"])
                signing_round = SigningRound(policy, bytes.fromhex(row["message"]), nonces)
                self.assertEqual(signing_round.combine(shares).hex(), row["signature"])

    def test_abort_retry_and_distinct_participants(self):
        keys = fixture_keys("musig2/abort")
        public = tuple(key.public_key.format() for key in keys)
        with self.assertRaisesRegex(ValueError, "distinct"):
            Policy((public[0], public[0]))
        policy = Policy(public)
        self.assertNotEqual(Policy(public[::-1]).aggregate_x, policy.aggregate_x)
        message = b"\x68" * 32

        def begin(label):
            return tuple(FixtureNonce(key, policy, message, f"musig2/{label}/{i}")
                         for i, key in enumerate(keys))

        first = begin("first")
        public_nonces = tuple(nonce.public for nonce in first)
        with self.assertRaisesRegex(ValueError, "both public nonces"):
            SigningRound(policy, message, public_nonces[:1])
        first_round = SigningRound(policy, message, public_nonces)
        stale = first[0].sign(first_round, 0)
        with self.assertRaisesRegex(ValueError, "both 32-byte partial"):
            first_round.combine((stale,))
        first[1].cancel()
        for i, nonce in enumerate(first):
            with self.assertRaisesRegex(ValueError, "consumed or canceled"):
                nonce.sign(first_round, i)

        retry = begin("retry")
        retry_public = tuple(nonce.public for nonce in retry)
        self.assertTrue(all(a != b for a, b in zip(public_nonces, retry_public, strict=True)))
        retry_round = SigningRound(policy, message, retry_public)
        wrong_message = SigningRound(policy, bytes(32), retry_public)
        with self.assertRaisesRegex(ValueError, "signing session"):
            retry[0].sign(wrong_message, 0)
        shares = tuple(nonce.sign(retry_round, i) for i, nonce in enumerate(retry))
        for round_to_check, parts in ((retry_round, (stale, shares[1])), (retry_round, shares[::-1]),
                                      (wrong_message, shares)):
            with self.assertRaisesRegex(ValueError, "partial_sig_verify"):
                round_to_check.combine(parts)
        signature = retry_round.combine(shares)
        self.assertTrue(verify(policy.aggregate_x, message, signature))
        self.assertFalse(verify(policy.aggregate_x, bytes(32), signature))
        for key in keys:
            only_one = key.sign_schnorr(message, aux_randomness=bytes(32))
            self.assertFalse(verify(policy.aggregate_x, message, only_one))

    def test_native_rejects_missing_second_signature(self):
        coin = native_2of2_coin("native/missing", 10_000)
        parent = synthetic_parent("native/missing/parent", coin)
        unsigned = Transaction((Input(parent.txid_wire(), 0),), (replace(coin.output, value=9_900),))
        signed = coin.unlock(unsigned, 0, parent, 0x41, None)
        self.check_spend(signed, (parent,), [True])
        witness = signed.inputs[0].script
        incomplete = signed.with_script(0, witness[:2 + witness[1]])
        self.check_spend(incomplete, (parent,), [False])

    def test_paired_payment_matrix(self):
        for name, template in TEMPLATES.items():
            coins = tuple(template.create(f"matrix/input/{i}", 10_000) for i in range(2))
            parents = tuple(synthetic_parent(f"matrix/parent/{i}", coin) for i, coin in enumerate(coins))
            outputs = tuple(template.create(f"matrix/output/{i}", 9_950).output for i in range(2))
            inputs = tuple(Input(parent.txid_wire(), 0, sequence=0xfffffffe) for parent in parents)
            for version in (1, 2):
                unsigned = Transaction(inputs, outputs, version=version)
                for mode in MODES:
                    with self.subTest(template=name, version=version, sighash=hex(mode)):
                        signed = unsigned
                        for i, coin in enumerate(coins):
                            signed = coin.unlock(signed, i, parents[i], mode, None)
                        self.assertEqual(signed.with_script(0, b"").with_script(1, b""), unsigned)
                        self.check_spend(signed, parents, [True, True])
                        self.check_spend(replace(signed, locktime=1), parents, [False, False])
                        changed = replace(signed, outputs=(replace(outputs[0], value=9_949), outputs[1]))
                        expected = {1: [False, False], 2: [True, True], 3: [False, True]}[mode & 31]
                        self.check_spend(changed, parents, expected)


if __name__ == "__main__":
    unittest.main()
