"""Complete-input differential tests: BSV Node 1.2.3 and pinned chain-gang."""
from dataclasses import replace
import os
from pathlib import Path
import unittest
import requests
from assemble import PACKED_SM3_TEMPLATE_VERSION, SIGNED_RESIDUE_TEMPLATE_VERSION, TEMPLATE_VERSION, TEMPLATE_VERSIONS
from test_sm2 import fixture
from test_sighash import chain_check, mode_cases, activation_cases
from p2pkh_sm2 import *
from sm2 import *
from fourthgraph.bsv.differential import node_script_valid
from fourthgraph.bsv.script import push


def check_node(tx, parents, index, valid=True, *, chronicle_active=True, old_output=False):
    previous=parents[index].outputs[tx.inputs[index].vout]
    cookie=Path(os.environ['REGTEST_COOKIE']).read_text().strip().split(':',1)
    flags = sum(1 << b for b in (1,2,3,16,18,19))
    if chronicle_active:
        flags |= 1 << 20
        if not old_output:
            flags |= 1 << 21
    request=dict(tx=tx.serialize().hex(),n=index,flags=flags,reportflags=True,
                 txo=dict(lock=previous.script.hex(),value=previous.value,height=3 if chronicle_active and not old_output else 1))
    response=requests.post(os.environ.get('REGTEST_URL', 'http://127.0.0.1:18443'),auth=tuple(cookie),timeout=30,
        json=dict(jsonrpc='1.0',id=1,method='verifyscript',params=[[request],False,5000]))
    response.raise_for_status()
    data = response.json()
    if node_script_valid(data, flags, chronicle_active=chronicle_active) != valid:
        raise AssertionError((valid, data['result'][0]))


def check(tx, parents, index, valid=True):
    check_node(tx, parents, index, valid)
    chain_check(tx, parents, index, valid)


class NodeTests(unittest.TestCase):
    def test_sighash_coverage(self):
        for template_version in TEMPLATE_VERSIONS:
            with self.subTest(template_version=template_version):
                mode_cases(check_node, template_version=template_version)

    def test_chronicle_flags(self):
        for template_version in TEMPLATE_VERSIONS:
            with self.subTest(template_version=template_version):
                activation_cases(check_node, template_version=template_version)

    def test_consecutive_payments(self):
        qa=encode_public(mul(1)); qb=encode_public(mul(7))
        start=locking_script_from_public_key(qa)
        parent=Transaction((Input(b'\x22'*32,0),),(Output(10000,start),))
        versions = (*TEMPLATE_VERSIONS[1:], TEMPLATE_VERSION)
        participants = ((1, qa, qb), (7, qb, qa))
        for hop, version in enumerate(versions):
            d, q, destination = participants[hop % len(participants)]
            dest=locking_script_from_public_key(destination, version=version)
            signed=sign_payment(parent.serialize(),0,[Output(parent.outputs[0].value-100,dest)],100,q,lambda m,uid: fixture_sign(d,m,hop+2,uid))
            check(signed,[parent],0)
            self.assertEqual(len(signed.inputs[0].script),291)
            parent=signed

    def test_multi_input_and_multiple_outputs(self):
        key,lock,parent,_,_,_=fixture()
        other=Transaction((Input(b'\x55'*32,0),),(Output(500,b'\x51'),))
        tx=Transaction((Input(other.txid_wire(),0),Input(parent.txid_wire(),0)),(Output(400,b'\x51'),Output(1000,b'\x51')))
        pre=preimage_all(tx,1,1000); sig=fixture_sign(1,hash256(pre),2)
        signed=tx.with_script(1,current_input_unlock(tx,1,1000,key,sig))
        check(signed,[other,parent],1)
        check(replace(signed,outputs=tuple(reversed(signed.outputs))),[other,parent],1,False)
        alternative = replace(other, locktime=1)
        changed = replace(signed, inputs=(replace(signed.inputs[0], txid=alternative.txid_wire()), signed.inputs[1]))
        check(changed, [alternative, parent], 1, False)

    def test_two_sm2_inputs_and_two_sm2_outputs(self):
        keys = (encode_public(mul(1)), encode_public(mul(7)))
        locks = tuple(locking_script_from_public_key(key) for key in keys)
        parents = tuple(Transaction((Input(bytes([index + 1]) * 32, 0),), (Output(1000, lock),))
                        for index, lock in enumerate(locks))
        tx = Transaction(tuple(Input(parent.txid_wire(), 0) for parent in parents),
                         tuple(Output(900, lock) for lock in reversed(locks)))
        for flag in (0x41, 0x61):
            with self.subTest(flag=hex(flag)):
                first = sign_input(tx, 0, parents[0].serialize(), keys[0],
                                   lambda message, user_id: fixture_sign(1, message, 2, user_id), flag)
                signed = sign_input(first, 1, parents[1].serialize(), keys[1],
                                    lambda message, user_id: fixture_sign(7, message, 3, user_id), flag)
                for index in (0, 1):
                    check(signed, parents, index)

    def test_rejects_mutations(self):
        for version in (TEMPLATE_VERSION, SIGNED_RESIDUE_TEMPLATE_VERSION, PACKED_SM3_TEMPLATE_VERSION):
            with self.subTest(version=version):
                self.check_mutations(version)

    def check_mutations(self, version):
        key,lock,parent,tx,pre,sig=fixture(template_version=version)
        signed=tx.with_script(0,push(pre)+push(key)+push(sig))
        check(signed,[parent],0)
        check(replace(signed,outputs=(Output(899,b'\x51'),)),[parent],0,False)
        check(replace(signed,locktime=1),[parent],0,False)
        for bad in (be32(0)+sig[32:],be32(N)+sig[32:],sig[:32]+be32(0),sig[:32]+be32(N),be32(1)+be32(N-1),sig[:63],sig+b'\0',fixture_sign(1,hash256(pre),3,b'wrong ID')):
            check(tx.with_script(0,push(pre)+push(key)+push(bad)),[parent],0,False)
        for bad in (pre[:-1],pre+b'\0',pre[:-4]+b'\x42\0\0\0',pre[:105]+b'\xad'+pre[106:]):
            check(tx.with_script(0,push(bad)+push(key)+push(fixture_sign(1,hash256(bad),3))),[parent],0,False)
        bad=preimage_all(replace(tx,outputs=(Output(899,b'\x51'),)),0,1000)
        check(tx.with_script(0,push(bad)+push(key)+push(fixture_sign(1,hash256(bad),3))),[parent],0,False)
        check(tx.with_script(0,push(b'extra')+signed.inputs[0].script),[parent],0,False)
        check(tx.with_script(0,push(pre)+push(encode_public(mul(2)))+push(sig)),[parent],0,False)
        for malformed in (b'\x04'+bytes(64),b'\x04'+be32(P)+key[33:],b'\x03'+key[1:]):
            owner=new('ripemd160',sha256(malformed).digest()).digest()
            bad_parent=replace(parent,outputs=(Output(1000,locking_script_from_owner_hash(owner,version=version)),))
            bad_tx=replace(tx,inputs=(Input(bad_parent.txid_wire(),0),))
            bad_pre=preimage_all(bad_tx,0,1000)
            check(bad_tx.with_script(0,push(bad_pre)+push(malformed)+push(fixture_sign(1,hash256(bad_pre),3))),[bad_parent],0,False)

if __name__=='__main__': unittest.main()
