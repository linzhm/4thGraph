"""Standard vectors, OpenSSL interoperability, generator and payment negatives."""
import base64
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from assemble import PACKED_SM3_TEMPLATE_VERSION, SIGNED_RESIDUE_TEMPLATE_VERSION, SIGNED_WINDOW_TEMPLATE_VERSION
from assemble import POINT_KERNEL_FILE, TEMPLATE_VERSION, TEMPLATE_VERSIONS
from assemble import WINDOW_DOUBLING_TEMPLATE_VERSION, WINDOW_KERNEL_FILE
from assemble import AFFINE_GENERATOR_TEMPLATE_VERSION, AFFINE_KERNEL_FILE
from assemble import CARRIED_FIELD_TEMPLATE_VERSION, CARRIED_KERNEL_FILE
from assemble import BYTE_KERNEL_FILE
from assemble import assemble, forth_compiler, sm3_blocks
from byte_fields import BYTE_KERNEL_NAMES, compile_byte_kernels
from point_kernels import AFFINE_KERNEL_NAME, WINDOW_KERNEL_NAME, compile_kernels, load_kernels
from point_kernels import CARRIED_KERNEL_NAMES, compile_carried_kernels
from p2pkh_sm2 import *
from sm2 import *
from sm3_script import hash_script,compress,IV
from tune_window import evaluate_kernels, window_vectors
from fourthgraph.bsv.evaluate import evaluate,ScriptError
from fourthgraph.bsv.script import asm, decode_num, encode_num, push, number, assemble as assemble_blocks
from fourthgraph.bsv.transaction import *

ROOT=Path(__file__).resolve().parents[1]
SM3_PROFILES = ({}, {'optimized': True}, {'compact': True}, {'scheduled': True}, {'packed': True},
                {'split_rotations': True}, {'stream_schedule': True})


def der(tag,raw):
    size = len(raw)
    if size < 128:
        length = bytes((size,))
    else:
        encoded = size.to_bytes((size.bit_length() + 7) // 8, 'big')
        length = bytes((0x80 | len(encoded),)) + encoded
    return bytes((tag,)) + length + raw


def der_signature(sig):
    def scalar(b):
        b=b.lstrip(b'\0') or b'\0'
        return der(2,(b'\0' if b[0]&128 else b'')+b)
    return der(48,scalar(sig[:32])+scalar(sig[32:]))


def raw_signature(sig):
    from ecdsa.util import sigdecode_der
    r,s=sigdecode_der(sig,N)
    return be32(r)+be32(s)


def public_pem(key):
    algorithm=der(48,der(6,bytes.fromhex('2a8648ce3d0201'))+der(6,bytes.fromhex('2a811ccf5501822d')))
    raw=der(48,algorithm+der(3,b'\0'+key))
    return b'-----BEGIN PUBLIC KEY-----\n'+base64.encodebytes(raw)+b'-----END PUBLIC KEY-----\n'


def native_checker(tx,index,value):
    from ecdsa import VerifyingKey,SECP256k1,BadSignatureError
    from ecdsa.util import sigdecode_der
    digest=hash256(preimage_all(tx,index,value))
    def check(signature,key):
        if signature[-1:]!=b'\x41': return False
        try: return VerifyingKey.from_string(key,curve=SECP256k1).verify_digest(signature[:-1],digest,sigdecode=sigdecode_der)
        except (BadSignatureError,ValueError): return False
    return check


def fixture(d=1,k=2,*,template_version=TEMPLATE_VERSION):
    key=encode_public(mul(d)); lock=locking_script_from_public_key(key, version=template_version)
    funding=Transaction((Input(b'\x22'*32,0),),(Output(1000,lock),))
    tx=Transaction((Input(funding.txid_wire(),0),),(Output(900,b'\x51'),))
    pre=preimage_all(tx,0,1000); sig=fixture_sign(d,hash256(pre),k)
    return key,lock,funding,tx,pre,sig


def valid_script(lock,witness,tx,value=1000,index=0):
    try:
        stack,alt=evaluate(lock,witness,native_checker(tx,index,value))
        return stack==[b'\x01'] and alt==[]
    except ScriptError: return False


class SM2Tests(unittest.TestCase):
    def test_standard_vector(self):
        v=json.loads((ROOT/'versions/v1.0.0/sm2-standard.json').read_text())
        q=bytes.fromhex(v['public_key']); m=bytes.fromhex(v['message']); sig=bytes.fromhex(v['signature'])
        self.assertEqual(za(q).hex(),v['za'])
        self.assertEqual(message_digest(q,m).hex(),v['digest'])
        self.assertEqual(fixture_sign(int(v['private_key_test_only'],16),m,int(v['nonce_test_only'],16)),sig)
        self.assertTrue(verify(q,m,sig))
        self.assertFalse(verify(q,m,sig,b'other identity'))
        self.assertFalse(verify(q,m+b'!',sig))
        self.assertFalse(verify(q,m,sig[:32]+be32(N-int.from_bytes(sig[32:],'big'))))
        with self.assertRaises(ValueError): za(q,b'x'*8192)

    def test_sm3_generated_boundary_lengths(self):
        rng=random.Random(4818)
        for n in (0,3,55,56,63,64,65,82,119,120,127,128,210):
            message=rng.randbytes(n)
            for profile in SM3_PROFILES:
                with self.subTest(length=n,profile=profile):
                    stack,alt=evaluate(hash_script(n,**profile),[b'lower',message])
                    self.assertEqual(stack,[b'lower',sm3(message)]); self.assertEqual(alt,[])
        self.assertEqual(sm3(b'abc').hex(),'66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')

    def test_sm3_fixed_prefix_midstate(self):
        for d in (1,2,19,N-2):
            key=encode_public(mul(d)); prefix=b'\0\x80'+USER_ID+be32(A)+be32(B)+be32(G[0])+be32(G[1])
            state=compress(compress(IV,prefix[:64]),prefix[64:128])
            for profile in SM3_PROFILES:
                with self.subTest(key=d,profile=profile):
                    stack,alt=evaluate(hash_script(82,state,128,**profile),[prefix[128:]+key[1:]])
                    self.assertEqual(stack,[za(key)]); self.assertEqual(alt,[])

    def test_compact_sm3_preserves_lower_stack_and_checks_input_length(self):
        lower=[(1 << 32).to_bytes(5,'little'), b'\x80', b'lower']
        for profile in SM3_PROFILES[2:]:
            script=hash_script(64,**profile)
            for data in (bytes(64), b'\xff'*64, b'\x80\x01'*32):
                with self.subTest(profile=profile, word=data[:2].hex()):
                    self.assertEqual(evaluate(script,lower+[data]),(lower+[sm3(data)],[]))
            for length in (63,65):
                with self.subTest(profile=profile, length=length), self.assertRaisesRegex(ScriptError,'NUMEQUALVERIFY'):
                    evaluate(script,lower+[bytes(length)])

    def test_openssl_standard_and_round_trip(self):
        self.assertIsNotNone(shutil.which('openssl'),'OpenSSL with SM2 is required')
        v=json.loads((ROOT/'versions/v1.0.0/sm2-standard.json').read_text())
        with tempfile.TemporaryDirectory() as directory:
            d=Path(directory)
            (d/'pub.pem').write_bytes(public_pem(bytes.fromhex(v['public_key'])))
            (d/'message').write_bytes(bytes.fromhex(v['message']))
            (d/'signature').write_bytes(der_signature(bytes.fromhex(v['signature'])))
            def run(*args): return subprocess.run(['openssl',*args],cwd=d,check=True,capture_output=True).stdout
            run('pkeyutl','-verify','-pubin','-inkey','pub.pem','-rawin','-digest','sm3','-pkeyopt','distid:'+USER_ID.decode(),'-in','message','-sigfile','signature')
            run('genpkey','-algorithm','SM2','-out','private.pem')
            key=run('pkey','-in','private.pem','-pubout','-outform','DER')[-65:]
            def signer(message,user_id):
                (d/'message').write_bytes(message)
                return raw_signature(run('pkeyutl','-sign','-inkey','private.pem','-rawin','-digest','sm3','-pkeyopt','distid:'+user_id.decode(),'-in','message'))
            lock=locking_script_from_public_key(key)
            parent=Transaction((Input(b'\x55'*32,0),),(Output(1000,lock),))
            signed=sign_payment(parent.serialize(),0,[Output(900,b'\x51')],100,key,signer)
            items,_=evaluate(signed.inputs[0].script)
            self.assertTrue(valid_script(lock,items,signed))

    def test_canonical_recognition(self):
        key,lock,*_=fixture()
        manifest=json.loads((ROOT/'versions/v1.0.0/layout.json').read_text())
        self.assertEqual(len(lock),manifest['script_bytes'])
        self.assertEqual(identify(lock),(1,public_key_hash160(key)))
        self.assertEqual(recognize(lock),public_key_hash160(key))
        for at in (0,49,70,1000,len(lock)-1):
            mutated=bytearray(lock); mutated[at]^=1
            self.assertIsNone(recognize(bytes(mutated)))
        self.assertIsNone(recognize(lock[:-1])); self.assertIsNone(recognize(lock+b'\0'))
        with self.assertRaises(ValueError): locking_script_from_owner_hash(bytes(19))
        r1=bytes.fromhex('046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5')
        with self.assertRaises(ValueError): public_key_hash160(r1)

    def test_forth_build_and_recognition(self):
        owner = bytes(range(20))
        sizes = []
        for version in TEMPLATE_VERSIONS:
            with self.subTest(version=version):
                lock = locking_script_from_owner_hash(owner, version=version)
                self.assertEqual(lock, assemble(owner, version))
                if version < SIGNED_RESIDUE_TEMPLATE_VERSION:
                    self.assertEqual(lock, assemble_blocks(ROOT/'reference/asm', owner, sm3_blocks(version=version)))
                self.assertEqual(identify(lock), (version, owner))
                self.assertIsNone(identify(lock[:-1]))
                self.assertIsNone(identify(lock[:-1] + b'\x51'))
                sizes.append(len(lock))
        self.assertEqual(sizes, sorted(set(sizes), reverse=True))

    def test_full_script_random_keys(self):
        for version in TEMPLATE_VERSIONS:
            for d,k in ((1,2),(7,19),(19,7),(N-2,N-1),(12345,67890)):
                key,lock,parent,tx,pre,sig=fixture(d,k,template_version=version)
                with self.subTest(version=version,d=d): self.assertTrue(valid_script(lock,[pre,key,sig],tx))

    def test_point_kernels_reproduce_signed_coordinates(self):
        kernels = compile_kernels()
        self.assertEqual(kernels, load_kernels(POINT_KERNEL_FILE))
        previous = forth_compiler(bytes(20), PACKED_SM3_TEMPLATE_VERSION)
        old_add = previous.emit("sm2-add-points", b"")
        old_double = previous.emit("sm2-double-point", b"")
        new_add = kernels["sm2-add-kernel"]
        new_double = kernels["sm2-double-kernel"]
        self.assertLess(len(new_add), len(old_add))
        self.assertLess(len(new_double), len(old_double))

        infinity = (0, -7, 0)
        x, y = mul(7)
        point, inverse = (x, y, 1), (x, -y, 1)
        x2, y2 = mul(19)
        scaled = (-(2*x2 % P), -(2*y2 % P), -2)
        cached = (P, 3*B % P, 17, 1)
        for left, right in ((infinity, infinity), (infinity, point), (point, infinity),
                            (point, point), (point, inverse), (scaled, point), (scaled, scaled)):
            with self.subTest(left=left, right=right):
                add_stack = [encode_num(value) for value in (*cached, *left, *right)]
                double_stack = [encode_num(value) for value in (*cached, *left)]
                self.assertEqual(evaluate(new_add, add_stack), evaluate(old_add, add_stack))
                self.assertEqual(evaluate(new_double, double_stack), evaluate(old_double, double_stack))

    def test_window_kernel_reproduces_five_doublings(self):
        names = (WINDOW_KERNEL_NAME,)
        kernels = compile_kernels(names)
        self.assertEqual(kernels, load_kernels(WINDOW_KERNEL_FILE, names))
        grouped = kernels[WINDOW_KERNEL_NAME]
        previous = 5 * load_kernels(POINT_KERNEL_FILE)["sm2-double-kernel"]
        self.assertLess(len(grouped), len(previous))
        x, y = mul(19)
        scaled = (-(2*x % P), -(2*y % P), -2)
        prefix = (P, 3*B % P, 17)
        for point in ((0, 1, 0), (0, -7, 0), (x, y, 1), scaled):
            with self.subTest(point=point):
                stack = [encode_num(value) for value in (*prefix, *point)]
                self.assertEqual(evaluate(grouped, stack), evaluate(previous, stack))

    def test_signed_windows_match_scalar_multiplication(self):
        for version in (SIGNED_WINDOW_TEMPLATE_VERSION, WINDOW_DOUBLING_TEMPLATE_VERSION,
                        AFFINE_GENERATOR_TEMPLATE_VERSION, CARRIED_FIELD_TEMPLATE_VERSION):
            with self.subTest(version=version):
                self.check_signed_windows(version)

    def check_signed_windows(self, version):
        compiler = forth_compiler(bytes(20), version)
        window = compiler.emit("sm2-window", b"")
        qx, qy = mul(7)
        cached = [encode_num(value) for value in (P, 3*B % P, 17)]
        cases = (
            (0, 0), (1, 0), (0, 1), (15, 16), (16, 31), (31, 32),
            (N-7, 1), (N-1, N-1), (1 << 255, N-2), (N-2, 1 << 255),
            ((1 << 256)-1, (1 << 256)-1),
        )
        for s, t in cases:
            with self.subTest(s=s, t=t):
                setup = b"".join(number(value) + asm("OP_TOALTSTACK") for value in (s, t, qy, qx))
                stack, alt = evaluate(setup + window, cached)
                self.assertEqual(alt, [])
                self.assertEqual(stack[:len(cached)], cached)
                generator_slots = 2*16 if version >= AFFINE_GENERATOR_TEMPLATE_VERSION else 3*17
                self.assertEqual(len(stack), len(cached) + generator_slots + 3*17 + 3)
                x, y, z = (decode_num(value) % P for value in stack[-3:])
                self.assertTrue(x or y or z)
                inverse_z = pow(z, -1, P) if z else None
                actual = (x*inverse_z % P, y*inverse_z % P) if z else None
                self.assertEqual(actual, add(mul(s), mul(t, (qx, qy))))

    def test_carried_window_kernels_reproduce_template_9(self):
        kernels = compile_carried_kernels()
        self.assertEqual(kernels, load_kernels(CARRIED_KERNEL_FILE, CARRIED_KERNEL_NAMES))
        evaluate_kernels(kernels, window_vectors())

    def test_packed_fields_preserve_unsigned_values_and_stack_order(self):
        kernels, _ = compile_byte_kernels()
        self.assertEqual(kernels, load_kernels(BYTE_KERNEL_FILE, BYTE_KERNEL_NAMES))
        compiler = forth_compiler(bytes(20), CARRIED_FIELD_TEMPLATE_VERSION)
        unpack = compiler.emit("sm2-unpack-packed-fields", b"")
        fields = (bytes(192), bytes(range(192)), b"\xff"*192)
        for data in fields:
            r, s, x, y, e, digest = (data[index:index+32] for index in range(0, len(data), 32))
            setup = push(b"flag") + asm("OP_TOALTSTACK") + push(digest) + asm("OP_TOALTSTACK")
            stack = [b"preimage", b"\x04"+x+y, r+s, e]
            expected = [encode_num(int.from_bytes(part, "big")) for part in (digest, e, y, x, s, r)]
            self.assertEqual(evaluate(setup+unpack, stack), ([b"preimage"], [b"flag", *expected]))
            stack[1] = b"\x02"+x+y
            with self.assertRaises(ScriptError):
                evaluate(setup+unpack, stack)

    def test_affine_kernel_reproduces_projective_addition(self):
        names = (AFFINE_KERNEL_NAME,)
        kernels = compile_kernels(names)
        self.assertEqual(kernels, load_kernels(AFFINE_KERNEL_FILE, names))
        general = load_kernels(POINT_KERNEL_FILE)["sm2-add-kernel"]
        affine = kernels[AFFINE_KERNEL_NAME]
        self.assertLess(len(affine), len(general))
        x, y = mul(19)
        scaled = (-(2*x % P), -(2*y % P), -2)
        prefix = (P, 3*B % P, 17)
        for left, right in (((0, 1, 0), (x, y)), ((x, y, 1), (x, y)),
                            ((x, y, 1), (x, -y)), (scaled, mul(7))):
            with self.subTest(left=left, right=right):
                stack = [encode_num(value) for value in (*prefix, *left, *right)]
                self.assertEqual(evaluate(affine, stack), evaluate(general, [*stack, b'\x01']))

    def test_compact_byte_reversal_matches_legacy(self):
        previous = forth_compiler(bytes(20), WINDOW_DOUBLING_TEMPLATE_VERSION).emit("sm2-reverse32", b"")
        compact = forth_compiler(bytes(20), AFFINE_GENERATOR_TEMPLATE_VERSION).emit("sm2-reverse32", b"")
        self.assertLess(len(compact), len(previous))
        for data in (bytes(range(32)), bytes(32), bytes(range(224, 256))):
            with self.subTest(data=data):
                self.assertEqual(evaluate(compact, [b'prefix', data]), ([b'prefix', data[::-1]], []))

    def test_script_rejects_invalid_signature_and_key(self):
        key,lock,parent,tx,pre,sig=fixture()
        bad_signatures=[be32(0)+sig[32:],be32(N)+sig[32:],sig[:32]+be32(0),sig[:32]+be32(N),be32(1)+be32(N-1),sig[:-1],sig+b'\0',sig[:32]+be32(N-int.from_bytes(sig[32:],'big')),fixture_sign(1,hash256(pre),3,b'wrong ID')]
        for value in bad_signatures:
            with self.subTest(signature=value.hex()): self.assertFalse(valid_script(lock,[pre,key,value],tx))
        # Malformed key gets its own matching owner hash, so the point check is exercised.
        for q in (b'\x04'+bytes(64),b'\x04'+be32(P)+key[33:],b'\x03'+key[1:]):
            owner=new('ripemd160',sha256(q).digest()).digest()
            self.assertFalse(valid_script(locking_script_from_owner_hash(owner),[pre,q,sig],tx))
        self.assertFalse(valid_script(lock,[pre,encode_public(mul(2)),sig],tx))
        self.assertFalse(valid_script(lock,[b'extra',pre,key,sig],tx))

    def test_transaction_and_preimage_tampering(self):
        key,lock,parent,tx,pre,sig=fixture()
        variants=[replace(tx,outputs=(Output(899,b'\x51'),)),replace(tx,locktime=1),replace(tx,version=1),replace(tx,inputs=(replace(tx.inputs[0],sequence=1),)),replace(tx,inputs=(replace(tx.inputs[0],vout=1),)),replace(tx,inputs=(replace(tx.inputs[0],txid=b'\x33'*32),)),replace(tx,outputs=(Output(900,b'\x00'),))]
        for changed in variants:
            self.assertFalse(valid_script(lock,[pre,key,sig],changed))
            p=preimage_all(changed,0,1000)
            s=fixture_sign(1,hash256(p),3)
            self.assertFalse(valid_script(lock,[p,key,s],tx))
        self.assertFalse(valid_script(lock,[pre,key,sig],tx,value=1001))
        for changed in (pre[:-1],pre+b'\0',pre[:-4]+b'\x42\0\0\0',pre[:105]+b'\xad'+pre[106:]):
            self.assertFalse(valid_script(lock,[changed,key,fixture_sign(1,hash256(changed),3)],tx))

    def test_infinity_rejected(self):
        # s=1, t=2, Q=-(1/2)G => sG+tQ=infinity.
        key=encode_public(mul(N-pow(2,-1,N)))
        self.assertFalse(verify_digest(key,bytes(32),be32(1)+be32(1)))
        inputs=b''.join(number(x) for x in (P,1,1,*parse_public(key),0))
        for version in TEMPLATE_VERSIONS:
            point_code=forth_compiler(bytes(20), version).emit("sm2-verify-sm2-point", b"")
            with self.subTest(version=version), self.assertRaises(ScriptError):
                evaluate(inputs+point_code)

    def test_high_x_candidate(self):
        # Construct a valid verification relation with x >= n (negligible random probability).
        x=N
        while True:
            y=pow((x*x*x+A*x+B)%P,(P+1)//4,P)
            if (y*y-x*x*x-A*x-B)%P==0: break
            x+=1
        e=123; r=(e+x)%N; s=456; t=(r+s)%N
        q=mul(pow(t,-1,N),add((x,y),mul(N-s)))
        self.assertTrue(verify_digest(encode_public(q),be32(e),be32(r)+be32(s)))
        inputs=b''.join(number(v) for v in (P,r,s,*q,e))
        for version in TEMPLATE_VERSIONS:
            point_code=forth_compiler(bytes(20), version).emit("sm2-verify-sm2-point", b"")
            with self.subTest(version=version):
                self.assertEqual(evaluate(inputs+point_code),([],[]))

    def test_payment_vector_and_consecutive_payments(self):
        v=json.loads((ROOT/'versions/v1.0.0/spend-all.json').read_text())
        key,lock,parent,tx,pre,sig=fixture()
        self.assertEqual(key.hex(),v['public_key'])
        self.assertEqual(parent.txid(),v['parent_txid'])
        self.assertEqual(tx.serialize().hex(),v['unsigned_tx_hex'])
        self.assertEqual(pre.hex(),v['preimage_hex']); self.assertEqual(sig.hex(),v['signature_hex'])
        self.assertEqual(hash256(pre).hex(),v['message_hex'])
        self.assertEqual(za(key).hex(),v['za_hex'])
        self.assertEqual(message_digest(key,hash256(pre)).hex(),v['sm2_digest_hex'])
        signed=tx.with_script(0,current_input_unlock(tx,0,1000,key,sig))
        self.assertEqual(signed.inputs[0].script.hex(),v['script_sig_hex']); self.assertEqual(signed.txid(),v['signed_txid'])
        parent=Transaction((Input(b'\x33'*32,0),),(Output(10000,lock),))
        lengths=[]
        for hop in range(3):
            signed=sign_payment(parent.serialize(),0,[Output(parent.outputs[0].value-100,lock)],100,key,lambda m,uid: fixture_sign(1,m,hop+2,uid))
            witness,_=evaluate(signed.inputs[0].script)
            self.assertTrue(valid_script(lock,witness,signed,value=parent.outputs[0].value))
            lengths.append(len(signed.inputs[0].script)); parent=signed
        self.assertEqual(lengths,[291]*3)
        with self.assertRaises(ValueError): sign_payment(parent.serialize(),0,[Output(1,b'\x51')],0,key,lambda *_: sig)
        with self.assertRaises(ValueError): sign_payment(parent.serialize(),0,[Output(parent.outputs[0].value-100,b'\x51')],100,key,lambda *_: bytes(64))
        with self.assertRaises(ValueError): Transaction.parse(parent.serialize()+b'\0')

    def test_release_defaults_to_pinned_v1(self):
        manifest = json.loads((ROOT/'versions/v1.0.0/layout.json').read_text())
        base_owner = bytes.fromhex(manifest['base_owner_hash160'])
        lock = assemble(base_owner)
        self.assertEqual(len(lock), 144925)
        self.assertEqual(sha256(lock).hexdigest(), manifest['base_script_sha256'])
        self.assertEqual(locking_script_from_owner_hash(base_owner), lock)
        key = encode_public(mul(1))
        self.assertEqual(identify(locking_script_from_public_key(key)), (1, public_key_hash160(key)))
        cli = [sys.executable, str(ROOT/'reference/generate_lock.py'), '--owner-hash160', base_owner.hex()]
        result = json.loads(subprocess.check_output(cli))
        self.assertEqual(result['version'], 1)
        self.assertEqual(result['script_sha256'], manifest['base_script_sha256'])
        self.assertEqual(subprocess.check_output([*cli, '--format', 'raw']), lock)
        self.assertEqual(subprocess.check_output([*cli, '--version', '1', '--format', 'raw']), lock)
        for version in TEMPLATE_VERSIONS[1:]:
            candidate = assemble(base_owner, version)
            self.assertEqual(subprocess.check_output([*cli, '--version', str(version), '--format', 'raw']), candidate)
        for version in (0, TEMPLATE_VERSIONS[-1] + 1, TEMPLATE_VERSIONS[-1] + 2):
            with self.subTest(version=version):
                for construct in (assemble, locking_script_from_owner_hash):
                    with self.assertRaisesRegex(ValueError, 'unsupported P2PKH-SM2 template'):
                        construct(base_owner, version=version)
                self.assertNotEqual(subprocess.run([*cli, '--version', str(version)],
                                                   capture_output=True).returncode, 0)


if __name__=='__main__': unittest.main()
