"""Complete transaction coverage cases. Run with the pinned chain-gang build."""
import json
from dataclasses import replace
from pathlib import Path
import unittest

from tx_engine import Script, Tx, sig_hash_preimage
from p2pkh_sm2 import (authorization, current_input_unlock, identify, locking_script_from_public_key,
                       sign_input, sign_payment)
from sighash import ANYONECANPAY, CHRONICLE, COMPANION_CODE, SINGLE, SUPPORTED_TYPES
from sm2 import encode_public, fixture_sign, mul
from shared.script import push
from shared.transaction import Input, Output, Transaction, hash256

DIRECTORY = Path(__file__).resolve().parents[1] / 'template'


def script(raw):
    program = Script()
    program.append_data(raw)
    return program


def engine_tx(tx):
    return Tx.parse(tx.serialize())


def chain_check(tx, parents, index, valid=True):
    try:
        engine_tx(tx).validate([engine_tx(p) for p in parents])
    except ValueError:
        if valid:
            raise
    else:
        if not valid:
            raise AssertionError(f'chain-gang accepted an invalid signature at input {index}')


def scenario(paired=True, *, version=2, template_version=2):
    key = encode_public(mul(7))
    def parent(tag, lock, value):
        return Transaction((Input(bytes([tag])*32, 4),), (Output(value, lock),))
    parents = (parent(0x22, b'\x51', 500),
               parent(0x33, locking_script_from_public_key(key, version=template_version), 1500))
    other, owned = parents
    inputs = (Input(other.txid_wire(), 0, sequence=5), Input(owned.txid_wire(), 0, sequence=8))
    outputs = (Output(400, b'\x51'), Output(1200, b'\x51'), Output(200, b'\x51')) if paired else (Output(1500,b'\x51'),)
    return key, parents, Transaction(inputs, outputs, version=version, locktime=42)


def signed_case(tx, parents, key, flag, nonce):
    return sign_input(tx, 1, parents[1].serialize(), key,
                      lambda msg, uid: fixture_sign(7, msg, nonce, uid), flag)


def mode_cases(check):
    """Run the same positive and negative complete spends on each independent engine."""
    key, parents, tx = scenario()
    alternative = replace(parents[0], locktime=777)
    for flag in sorted(SUPPORTED_TYPES):
        base = flag & 31
        signed = signed_case(tx, parents, key, flag, 100 + flag)
        check(signed, parents, 1)
        # Change a complete output, with total output value still below the input total.
        for j in range(len(tx.outputs)):
            outputs = list(tx.outputs)
            outputs[j] = replace(outputs[j], value=outputs[j].value-1)
            check(replace(signed, outputs=tuple(outputs)), parents, 1,
                  base == 2 or (base == SINGLE and j != 1))
        check(replace(signed, inputs=(replace(tx.inputs[0], txid=alternative.txid_wire()),
                                      signed.inputs[1])), (alternative,parents[1]), 1, bool(flag & ANYONECANPAY))
        check(replace(signed, inputs=(replace(tx.inputs[0], sequence=10),signed.inputs[1])),
              parents, 1, bool(flag & ANYONECANPAY) or base != 1)
        check(replace(signed, locktime=43), parents, 1, False)
    key, parents, tx = scenario(False)
    # Sign the altered witness messages with the actual test key. Rejection must
    # come from the lock or its native transaction binding, not a stale SM2 signature.
    companion = authorization(tx, 1, 1500, 0x63).preimage
    ordinary = authorization(tx, 1, 1500, 0x43).preimage
    for nonce, malformed in enumerate((
        ordinary[:-4] + bytes.fromhex('43010000'),
        ordinary[:-4] + bytes.fromhex('23000000'),
        companion[:-4] + bytes.fromhex('41000000'),
        companion[:121] + bytes([1]) + companion[122:],
        companion[:105] + bytes([0xac]) + companion[106:],
        ordinary[:-4] + bytes.fromhex('63000000'),
    ), 2000):
        signature = fixture_sign(7, hash256(malformed), nonce)
        check(tx.with_script(1, push(malformed) + push(key) + push(signature)), parents, 1, False)
    for flag in (0x43, 0xc3, 0x63, 0xe3):
        signed = signed_case(tx, parents, key, flag, 512 + flag)
        check(signed, parents, 1)
        new_parent = replace(parents[1], locktime=1)
        check(replace(signed, inputs=(tx.inputs[0], replace(signed.inputs[1], txid=new_parent.txid_wire()))),
              (parents[0], new_parent), 1, False)
        check(replace(signed, outputs=tx.outputs+(Output(1,b'\x51'),)), parents, 1, False)
        check(replace(signed, outputs=(Output(1400,b'\x51'),)), parents, 1)
        check(replace(signed, inputs=(replace(tx.inputs[0], txid=alternative.txid_wire()),signed.inputs[1])),
              (alternative, parents[1]), 1, bool(flag & ANYONECANPAY))
    # Mixed algorithms within one transaction; both inputs belong to the same SM2 key.
    other = replace(parents[1], locktime=91)
    parents = (other, parents[1])
    tx = replace(tx, inputs=(Input(other.txid_wire(),0), tx.inputs[1]),
                 outputs=(Output(500,b'\x51'),Output(900,b'\x51')))
    first = sign_input(tx,0,other.serialize(),key,lambda m,uid: fixture_sign(7,m,991,uid),0x41)
    mixed = signed_case(first,parents,key,0x63,992)
    check(mixed,parents,0)
    check(mixed,parents,1)


def activation_cases(check):
    # Use transaction version 1 on both sides so only activation flags and UTXO era differ.
    for paired in (True, False):
        key, parents, tx = scenario(paired, version=1)
        for flag in sorted(SUPPORTED_TYPES) if paired else (0x43, 0xc3, 0x63, 0xe3):
            signed = signed_case(tx, parents, key, flag, 1100 + flag)
            check(signed, parents, 1, not bool(flag & CHRONICLE), chronicle_active=False, old_output=True)
            check(signed, parents, 1, True, chronicle_active=True, old_output=True)
            check(signed, parents, 1, True, chronicle_active=True, old_output=False)


class ModeTests(unittest.TestCase):
    def test_complete_modes(self):
        mode_cases(chain_check)

    def test_signing_vectors_against_engine(self):
        vectors = json.loads((DIRECTORY/'sighash-modes.json').read_text())
        self.assertEqual(len(vectors),16)
        for paired in (True, False):
            key, parents, tx = scenario(paired)
            for flag in sorted(SUPPORTED_TYPES) if paired else (0x43,0xc3,0x63,0xe3):
                with self.subTest(paired=paired, flag=hex(flag)):
                    auth=authorization(tx,1,1500,flag)
                    expected_companion = not paired and flag in (0x63,0xe3)
                    self.assertEqual(auth.companion, expected_companion)
                    native = engine_tx(tx)
                    if expected_companion:
                        # sig_hash_preimage finds the last lexical separator. Supply ac and
                        # substitute the exact four-byte executed suffix before hashing.
                        reference = bytes(sig_hash_preimage(native,1,script(b'\xac'),1500,flag ^ CHRONICLE))
                        self.assertEqual(reference[104:106], b'\x01\xac')
                        reference = reference[:104] + bytes([len(COMPANION_CODE)]) + COMPANION_CODE + reference[106:]
                    else:
                        reference = bytes(sig_hash_preimage(native,1,script(b'\xac'),1500,flag))
                    self.assertEqual(auth.preimage,reference)
                    entry = vectors[('paired-' if paired else 'unpaired-')+f'{flag:02x}']
                    self.assertEqual(auth.message.hex(),entry['message_hex'])
                    self.assertEqual(auth.preimage.hex(),entry['preimage_hex'])
                    self.assertEqual(auth.companion,entry['companion'])
                    altered_amount=authorization(tx,1,1499,flag)
                    self.assertEqual(auth.message==altered_amount.message,bool(flag & CHRONICLE) and not auth.companion)

    def test_upgrade_boundary_and_v1(self):
        key,parents,tx=scenario(version=1)
        # All six regular combinations work in a pre-Chronicle spend on the wallet side.
        for flag in SUPPORTED_TYPES:
            if flag & CHRONICLE:
                with self.assertRaisesRegex(ValueError,'disabled'):
                    sign_input(tx,1,parents[1].serialize(),key,None,flag,chronicle_active=False)
            else:
                a=authorization(tx,1,1500,flag,chronicle_active=False)
                sig=fixture_sign(7,a.message,flag+700)
                signed=tx.with_script(1,current_input_unlock(tx,1,1500,key,sig,flag,chronicle_active=False))
                chain_check(signed,parents,1)
        key, parents, tx = scenario(template_version=1)
        self.assertEqual(identify(parents[1].outputs[0].script)[0],1)
        prior=json.loads((DIRECTORY/'spend-all-v1.json').read_text())
        old_key=encode_public(mul(1))
        old_parent=Transaction((Input(b'\x22'*32,0),),(Output(1000,locking_script_from_public_key(old_key,version=1)),))
        signed=sign_payment(old_parent.serialize(),0,[Output(900,b'\x51')],100,old_key,
                            lambda m,uid: fixture_sign(1,m,2,uid))
        self.assertEqual(signed.txid(),prior['signed_txid'])
        chain_check(signed,[old_parent],0)
        for flag in SUPPORTED_TYPES-{0x41}:
            with self.assertRaisesRegex(ValueError,'v1'):
                sign_input(tx,1,parents[1].serialize(),key,None,flag)
        for flag in (0x01,0x21,0x40,0x44,0x51,0x1041,-1):
            with self.assertRaisesRegex(ValueError,'unsupported'):
                authorization(tx,1,1500,flag)


if __name__ == '__main__':
    unittest.main()
