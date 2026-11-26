from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
from pathlib import Path
import unittest
from lamport import *
from script import locking_script, binding, N, R
from payment import authorization, sign_payment, sign_spend
from fixtures import INVALID_PREVOUT_CASES, fixture, test_secret, cases, mode_cases
from engines import development_valid, chain_valid
from fourthgraph.bsv.evaluate import evaluate, ScriptError
from fourthgraph.bsv.pushtx import COMPANION_CODE, ONE_DER, PUBLIC, binding_der, check_binding
from fourthgraph.bsv.script import asm, number, push
from fourthgraph.bsv.transaction import Output, Transaction, Input

ROOT = Path(__file__).resolve().parents[1]


class LamportTests(unittest.TestCase):
    def test_keygen_and_lengths(self):
        secret, key = generate_keypair()
        self.assertEqual((len(secret),len(key)),(16384,16384))
        self.assertEqual(public_key(secret),key)
        self.assertNotEqual(generate_keypair()[1],key)
        for bad in (b'',bytes(16383),bytes(16385),None):
            with self.assertRaises(ValueError): public_key(bad)
        for digest in (bytes(31),bytes(33),None):
            with self.assertRaises(ValueError): sign_digest(secret,digest)
            self.assertFalse(verify_digest(key,digest,bytes(8192)))
        self.assertFalse(verify_digest(key[:-1],bytes(32),bytes(8192)))

    def test_bit_order_and_boundary_digests(self):
        secret = test_secret(); key = public_key(secret)
        lock = locking_script(key,transaction=False)
        for digest in (bytes(32),b'\xff'*32,b'\x80'+bytes(31),bytes(31)+b'\x01',b'\xaa'*32,b'\x55'*32,sha256(b'abc').digest()):
            with self.subTest(digest=digest.hex()):
                sig = sign_digest(secret,digest)
                self.assertTrue(verify_digest(key,digest,sig))
                self.assertEqual(evaluate(lock,[digest,sig]),([b'\x01'],[]))
                for i in range(256):
                    offset = (2*i+((digest[i//8]>>(i%8))&1))*32
                    self.assertEqual(sig[i*32:(i+1)*32],secret[offset:offset+32])
        sig = sign_digest(secret,bytes(32))
        for i in range(256):
            mutated = bytearray(sig); mutated[32*i] ^= 1
            self.assertFalse(verify_digest(key,bytes(32),bytes(mutated)))
            with self.assertRaises(ScriptError): evaluate(lock,[bytes(32),bytes(mutated)])
        for digest,s in ((bytes(31),sig),(bytes(33),sig),(bytes(32),sig[:-1]),(bytes(32),sig+b'\0')):
            with self.assertRaises(ScriptError): evaluate(lock,[digest,s])

    def test_guard_is_atomic_and_consumes_even_identical_retry(self):
        signer = OneTimeSigner(test_secret())
        with self.assertRaises(ValueError): signer.sign(b'bad')
        def attempt(_):
            try: return signer.sign(bytes(32))
            except ValueError: return None
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(attempt,range(16)))
        self.assertEqual(sum(x is not None for x in results),1)
        with self.assertRaises(ValueError): signer.sign(bytes(32))

    def test_reuse_exposes_forgery(self):
        # Chosen complementary DIGESTS demonstrate why the primitive is one-time.
        # This is not a claim that real transaction preimages are freely selectable.
        secret = test_secret(); key = public_key(secret)
        zero = sign_digest(secret,bytes(32)); one = sign_digest(secret,b'\xff'*32)
        target = sha256(b'never signed').digest()
        forged = b''.join((one if b else zero)[i*32:(i+1)*32] for i,b in enumerate(bits(target)))
        self.assertTrue(verify_digest(key,target,forged))
        self.assertEqual(evaluate(locking_script(key,transaction=False),[target,forged]),([b'\x01'],[]))

    def test_every_digest_bit_is_checked(self):
        secret = test_secret(); key = public_key(secret); digest = bytes(32)
        sig = sign_digest(secret,digest); lock = locking_script(key,transaction=False)
        for i in range(256):
            bad = bytearray(digest); bad[i//8] ^= 1 << (i%8)
            with self.assertRaises(ScriptError): evaluate(lock,[bytes(bad),sig])

    def test_complete_input_differential(self):
        for label,tx,parents,index,expected in cases():
            with self.subTest(case=label):
                self.assertEqual(development_valid(tx,parents[index],index),expected)
                self.assertEqual(chain_valid(tx, parents, expect_bad_prevout=label in INVALID_PREVOUT_CASES),
                                 expected)

    def test_full_sighash_matrix(self):
        for label,tx,parents,index,expected in mode_cases():
            with self.subTest(case=label):
                self.assertEqual(development_valid(tx,parents[index],index),expected)
                self.assertEqual(chain_valid(tx,parents),expected)

    def test_external_signer_contract(self):
        secret,key,_,parent,tx,*_ = fixture()
        calls = []
        def callback(digest):
            calls.append(digest)
            return sign_digest(secret,digest)
        for bad_index, funding, flag in (
            (1,parent,0x41), (0,Transaction(parent.inputs,parent.outputs,locktime=1),0x41),
            (0,parent,0x61), (0,parent,0x01),
        ):
            with self.assertRaises(ValueError):
                sign_spend(tx,bad_index,funding.serialize(),key,callback,sighash=flag)
        self.assertEqual(calls,[])
        signed = sign_spend(tx,0,parent.serialize(),key,callback)
        self.assertEqual(calls,[authorization(tx,0,10000,legacy=True).digest()])
        self.assertTrue(chain_valid(signed,[parent]))
        with self.assertRaises(ValueError):
            sign_spend(signed,0,parent.serialize(),key,callback)
        self.assertEqual(len(calls),1)
        def bad_callback(digest):
            calls.append(digest)
            return bytes(8192)
        with self.assertRaisesRegex(ValueError,'external signer'):
            sign_spend(tx,0,parent.serialize(),key,bad_callback)
        self.assertEqual(len(calls),2)

    def test_unpaired_single_requires_opt_in_before_signing(self):
        for flag in (0x43, 0x63, 0xc3, 0xe3):
            with self.subTest(sighash=hex(flag)):
                secret = test_secret(b'unpaired-single-consent/' + bytes([flag]))
                key = public_key(secret)
                parent = Transaction((Input(b'\x11' * 32, 0),), (Output(1000, locking_script(key)),))
                tx = Transaction((Input(b'\x22' * 32, 0), Input(parent.txid_wire(), 0)), (Output(900, b'\x51'),))
                calls = []

                def sign(digest):
                    calls.append(digest)
                    return sign_digest(secret, digest)

                with self.assertRaisesRegex(ValueError, 'explicit opt-in'):
                    sign_spend(tx, 1, parent.serialize(), key, sign, sighash=flag)
                self.assertEqual(calls, [])

                signed = sign_spend(tx, 1, parent.serialize(), key, sign, sighash=flag, allow_unpaired_single=True)
                self.assertEqual(calls, [authorization(tx, 1, 1000, flag).digest()])
                self.assertTrue(development_valid(signed, parent, 1))

    def test_binding_der_edges(self):
        # Exercise small/large/minimal DER s and modulo n boundaries without trying
        # to find transaction preimages with those astronomically rare digests.
        from ecdsa import VerifyingKey, SECP256k1
        from ecdsa.util import sigdecode_der
        for h in (0,1,N-1,N,(N-R+1)%N,(N-R-1)%N,(N-R+128)%N,2**256-1):
            digest=h.to_bytes(32,'big')
            def check(sig,key):
                self.assertEqual(key,PUBLIC); self.assertEqual(sig[-1],0x41)
                r,s=sigdecode_der(sig[:-1],N)
                self.assertEqual(r,R); self.assertTrue(1<=s<=N//2)
                return VerifyingKey.from_string(key,curve=SECP256k1).verify_digest(sig[:-1],digest,sigdecode=sigdecode_der)
            self.assertEqual(evaluate(binding(),[digest],check),([b'\x01'],[]))
            self.assertEqual(evaluate(binding_der(compact=True), [digest]), evaluate(binding_der(), [digest]))
        for code in (binding(), binding_der(compact=True)):
            with self.assertRaises(ScriptError):
                evaluate(code, [(N-R).to_bytes(32, 'big')], lambda *_: True)

    def test_compact_binding_keeps_native_checks_in_order(self):
        digest = (N - R + 128).to_bytes(32, 'big')
        (der,), _ = evaluate(binding_der(), [digest])
        for selector, flag in ((0, 0x41), (0, 0x61), (1, 0x43), (1, 0xc3)):
            with self.subTest(selector=selector, flag=hex(flag)):
                prefix = number(selector) + asm('OP_TOALTSTACK') + push(bytes([flag])) + asm('OP_TOALTSTACK')
                expected = [(ONE_DER + bytes([flag | 0x20]), PUBLIC)] if selector else []
                expected.append((der + bytes([flag]), PUBLIC))
                calls = []

                def accept(signature, public_key):
                    calls.append((signature, public_key))
                    return True

                code = prefix + check_binding(COMPANION_CODE, compact=True)
                self.assertEqual(evaluate(code, [digest], accept), ([b'\x01'], []))
                self.assertEqual(calls, expected)

    def test_binding_digest_equivalence_is_explicit(self):
        from ecdsa import SECP256k1, VerifyingKey, BadSignatureError
        from ecdsa.util import sigdecode_der
        self.assertGreater(R+N, SECP256k1.curve.p())
        h = 123456789
        for z, expected in ((h,True),((-h-2*R)%N,True),(h+1,False)):
            def check(sig,key):
                try:
                    return VerifyingKey.from_string(key,curve=SECP256k1).verify_digest(
                        sig[:-1],z.to_bytes(32,'big'),sigdecode=sigdecode_der)
                except BadSignatureError: return False
            self.assertEqual(evaluate(binding(),[h.to_bytes(32,'big')],check),
                             ([b'\x01' if expected else b''],[]))

    def test_payment_and_fresh_change(self):
        secret,key,lock,parent,*_ = fixture()
        signer = OneTimeSigner(secret)
        with self.assertRaises(ValueError): sign_payment(parent.serialize(),0,[Output(9900,lock)],100,signer.public_key,signer.sign)
        with self.assertRaises(ValueError): sign_payment(parent.serialize(),0,[Output(9000,b'\x51')],100,signer.public_key,signer.sign)
        with self.assertRaises(ValueError): sign_payment(parent.serialize(),1,[Output(9900,b'\x51')],100,signer.public_key,signer.sign)
        other = OneTimeSigner(test_secret(b'next'))
        tx = sign_payment(parent.serialize(),0,[Output(9900,locking_script(other.public_key))],100,signer.public_key,signer.sign)
        self.assertTrue(chain_valid(tx,[parent]))
        next_tx = sign_payment(tx.serialize(),0,[Output(9800,b'\x51')],100,other.public_key,other.sign)
        self.assertTrue(chain_valid(next_tx,[tx]))
        with self.assertRaises(ValueError): sign_payment(parent.serialize(),0,[Output(9900,b'\x51')],100,signer.public_key,signer.sign)
        with self.assertRaises(ValueError): sign_payment(parent.serialize(),0,[Output(9900,b'\x51')],100,public_key(test_secret(b'wrong')),signer.sign)

    def test_reproducible_vectors(self):
        from measure import universal_vector, vector
        self.assertEqual(json.loads((ROOT/'versions/v0.1.0/vector.json').read_text()),vector())
        self.assertEqual(json.loads((ROOT/'versions/v0.1.0/universal-vectors.json').read_text()),universal_vector())

    def test_v020_candidate_artifacts_reproduce(self):
        from fixed_template import TEMPLATE_DIRECTORY, v020_forth_pattern
        from generate_template import build_artifacts

        for filename, expected in build_artifacts().items():
            self.assertEqual((TEMPLATE_DIRECTORY / filename).read_text(encoding='ascii'), expected, filename)
        pattern = v020_forth_pattern()
        self.assertEqual(evaluate(pattern.program), (list(pattern.fixed_parts), []))


if __name__ == '__main__': unittest.main()
