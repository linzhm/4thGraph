"""Complete-input differential tests: BSV Node 1.2.3 and pinned chain-gang."""
from dataclasses import replace
import os
from pathlib import Path
import unittest
import requests
from test_sm2 import fixture
from test_sighash import chain_check, mode_cases, activation_cases
from p2pkh_sm2 import *
from sm2 import *
from shared.script import push


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
    response.raise_for_status(); data=response.json()
    if data.get('error'): raise AssertionError(data['error'])
    result=data['result'][0]
    if result['result']!=('ok' if valid else 'error') or result['flags']!=flags:
        raise AssertionError((valid,result))


def check(tx, parents, index, valid=True):
    check_node(tx, parents, index, valid)
    chain_check(tx, parents, index, valid)


class NodeTests(unittest.TestCase):
    def test_sighash_coverage(self):
        mode_cases(check_node)

    def test_chronicle_flags(self):
        activation_cases(check_node)

    def test_consecutive_payments(self):
        qa=encode_public(mul(1)); qb=encode_public(mul(7))
        la=locking_script_from_public_key(qa); lb=locking_script_from_public_key(qb)
        parent=Transaction((Input(b'\x22'*32,0),),(Output(10000,la),))
        for hop,(d,q,dest) in enumerate(((1,qa,lb),(7,qb,la),(1,qa,lb))):
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
        check(replace(signed,inputs=(replace(signed.inputs[0],txid=b'\x77'*32),signed.inputs[1])),[other,parent],1,False)

    def test_rejects_mutations(self):
        key,lock,parent,tx,pre,sig=fixture()
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
            bad_parent=replace(parent,outputs=(Output(1000,locking_script_from_owner_hash(owner)),))
            bad_tx=replace(tx,inputs=(Input(bad_parent.txid_wire(),0),))
            bad_pre=preimage_all(bad_tx,0,1000)
            check(bad_tx.with_script(0,push(bad_pre)+push(malformed)+push(fixture_sign(1,hash256(bad_pre),3))),[bad_parent],0,False)

if __name__=='__main__': unittest.main()
