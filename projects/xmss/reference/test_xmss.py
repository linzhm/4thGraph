"""Check RFC vectors, signer boundaries, and generated Script semantics."""

from hashlib import sha256
import json
import unittest

from fixtures import VECTORS, funding, signing_cases, unsigned_spend
from payment import authorization, sign_spend
from script import locking_script, verifier
from shared.evaluate import ScriptError, evaluate
from shared.script import asm, push
from xmss import LEAVES, N, WOTS_BYTES, _address, _chain, _digits, _endpoints, _hash, _ltree, key_parts, verify


class XMSSReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = json.loads(VECTORS.read_text())
        cls.key = bytes.fromhex(fixture['public_key'])
        cls.seed_test_only = bytes.fromhex(fixture['seed_test_only'])
        cls.vectors = fixture['vectors']
        cls.locking_sha256 = fixture['locking_sha256']

    def test_fixtures_and_script(self):
        lock = locking_script(self.key, transaction=False)
        cases = list(signing_cases(funding(self.key)))
        self.assertEqual(len(cases), 34)
        self.assertEqual(sha256(locking_script(self.key)).hexdigest(), self.locking_sha256)
        for (index, digest, metadata), vector in zip(cases, self.vectors, strict=True):
            with self.subTest(index=index):
                self.assertEqual({field: vector[field] for field in metadata}, metadata)
                self.assertEqual(vector['index'], index)
                self.assertEqual(bytes.fromhex(vector['message']), digest)
                signature = bytes.fromhex(vector['signature'])
                self.assertEqual(int.from_bytes(signature[:4], 'big'), index)
                self.assertTrue(verify(self.key, digest, signature))
                self.assertEqual(evaluate(lock, [digest, signature]), ([b'\x01'], []))

    def test_mutations_are_rejected(self):
        vector = self.vectors[-1]
        message = bytes.fromhex(vector['message'])
        signature = bytes.fromhex(vector['signature'])
        lock = locking_script(self.key, transaction=False)
        offsets = (3, 4, 4 + N, 4 + N + WOTS_BYTES - 1, *range(4 + N + WOTS_BYTES, len(signature), N))
        for offset in offsets:
            altered = signature[:offset] + bytes([signature[offset] ^ 1]) + signature[offset + 1:]
            self.assertFalse(verify(self.key, message, altered))
            with self.assertRaises(ScriptError):
                evaluate(lock, [message, altered])
        rejected = (LEAVES.to_bytes(4, 'big') + signature[4:], signature[:-1], signature + b'\x00')
        for candidate in rejected:
            self.assertFalse(verify(self.key, message, candidate))
            with self.assertRaises(ScriptError):
                evaluate(lock, [message, candidate])
        self.assertFalse(verify(self.key, message + b'\x00', signature))
        with self.assertRaises(ScriptError):
            evaluate(lock, [message + b'\x00', signature])

    def test_key_encoding_and_stack_isolation(self):
        vector = self.vectors[0]
        message = bytes.fromhex(vector['message'])
        signature = bytes.fromhex(vector['signature'])
        for key in (self.key[4:], self.key[:3] + b'\x02' + self.key[4:]):
            self.assertFalse(verify(key, message, signature))
            with self.assertRaises(ValueError):
                locking_script(key)
        main, alternate = b'main-stack marker', b'altstack marker'
        program = push(alternate) + asm('OP_TOALTSTACK') + verifier(self.key)
        self.assertEqual(evaluate(program, [main, signature, message]), ([main], [alternate]))

    def test_last_valid_leaf(self):
        # The pinned C helper's vectors end at leaf 1022. Derive the final
        # synthetic proof using that leaf's authentication path and test seed.
        old_index = LEAVES - 2
        index = LEAVES - 1
        message = bytes.fromhex(self.vectors[-1]['message'])
        prior = bytes.fromhex(self.vectors[-1]['signature'])
        root, public_seed = key_parts(self.key)
        wots_start, path_start = 4 + N, 4 + N + WOTS_BYTES
        prior_digest = _hash(2, prior[4:wots_start] + root + old_index.to_bytes(N, 'big') + message)
        endpoints = list(_endpoints(prior[wots_start:path_start], prior_digest, public_seed, old_index))
        adjacent_leaf = _ltree(endpoints, public_seed, old_index)

        # The adjacent leaf replaces only the lowest sibling in the path.
        randomizer = _hash(3, self.seed_test_only[N:2 * N] + index.to_bytes(N, 'big'))
        digest = _hash(2, randomizer + root + index.to_bytes(N, 'big') + message)
        signature_parts = []
        for chain, digit in enumerate(_digits(digest)):
            address = _address(0, index, chain, 0, 0)
            start = _hash(4, self.seed_test_only[:N] + public_seed + address)
            signature_parts.append(_chain(start, public_seed, index, chain, 0, digit))
        signature = index.to_bytes(4, 'big') + randomizer + b''.join(signature_parts)
        signature += adjacent_leaf + prior[path_start + N:]
        self.assertTrue(verify(self.key, message, signature))
        self.assertEqual(evaluate(locking_script(self.key, transaction=False), [message, signature]), ([b'\x01'], []))

    def test_wallet_callback_and_witness(self):
        vector = next(v for v in self.vectors if v['kind'] == 'payment' and v['flag'] == 0x41)
        parents = funding(self.key)
        tx = unsigned_spend(parents, vector['version'], vector['paired'])
        calls = []

        def sign(message):
            calls.append(message.hex())
            return bytes.fromhex(vector['signature'])

        with self.assertRaisesRegex(ValueError, 'funding outpoint mismatch'):
            sign_spend(tx, 1, parents[0].serialize(), self.key, sign)
        self.assertEqual(calls, [])
        signed = sign_spend(tx, 1, parents[1].serialize(), self.key, sign)
        self.assertEqual(calls, [vector['message']])
        auth = authorization(tx, 1, 10_000)
        self.assertEqual(signed.inputs[1].script, auth.witness(bytes.fromhex(vector['signature'])))
        with self.assertRaisesRegex(ValueError, 'signature from external signer'):
            sign_spend(tx, 1, parents[1].serialize(), self.key, lambda digest: b'')


if __name__ == '__main__':
    unittest.main()
