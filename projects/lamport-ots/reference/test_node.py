"""BSV Node 1.2.3 RPC conformance. Fails if REGTEST_COOKIE is not supplied."""
import os
from pathlib import Path
import unittest
import requests
from fixtures import INVALID_PREVOUT_CASES, cases, fixture, test_secret, mode_cases
from lamport import OneTimeSigner, public_key, sign_digest
from payment import sign_payment
from script import locking_script
from engines import chain_valid
from fourthgraph.bsv.transaction import Output, Transaction, Input
from fourthgraph.bsv.script import push
from fourthgraph.bsv.differential import node_script_valid


def node_check(tx, parent, index, *, chronicle=True, funding_height=3, expect_push_only=False):
    previous = parent.outputs[0]
    cookie = Path(os.environ['REGTEST_COOKIE']).read_text().strip().split(':',1)
    flags = sum(1<<b for b in (1,2,3,16,18,19))
    if expect_push_only:
        flags |= 1 << 5
    if chronicle:
        flags |= 1 << 20
        if funding_height >= 2:
            flags |= 1 << 21
    request = dict(tx=tx.serialize().hex(),n=index,flags=flags,reportflags=True,
                   txo=dict(lock=previous.script.hex(),value=previous.value,height=funding_height))
    response = requests.post(os.environ.get('REGTEST_URL','http://127.0.0.1:18443'),auth=tuple(cookie),timeout=30,
        json=dict(jsonrpc='1.0',id=1,method='verifyscript',params=[[request],False,5000]))
    response.raise_for_status()
    return node_script_valid(response.json(), flags, chronicle_active=chronicle, expect_push_only=expect_push_only)


class NodeTests(unittest.TestCase):
    def test_complete_input_matrix(self):
        count = 0
        for label,tx,parents,index,expected in cases():
            with self.subTest(case=label):
                self.assertEqual(node_check(tx,parents[index],index),expected)
                self.assertEqual(chain_valid(tx, parents, expect_bad_prevout=label in INVALID_PREVOUT_CASES),
                                 expected)
                count += 1
        print(f'BSV Node + chain-gang: {count} complete-input cases')

    def test_full_sighash_matrix(self):
        count = 0
        for label,tx,parents,index,expected in mode_cases():
            with self.subTest(case=label):
                self.assertEqual(node_check(tx,parents[index],index),expected)
                self.assertEqual(chain_valid(tx,parents),expected)
                count += 1
        print(f'BSV Node + chain-gang: {count} universal sighash cases')

    def test_fresh_key_payment_chain(self):
        secret,_,_,parent,*_ = fixture()
        first = OneTimeSigner(secret)
        second = OneTimeSigner(test_secret(b'node-next'))
        tx = sign_payment(parent.serialize(),0,[Output(9900,locking_script(second.public_key))],100,first.public_key,first.sign)
        self.assertTrue(node_check(tx,parent,0))
        spend = sign_payment(tx.serialize(),0,[Output(9800,b'\x51')],100,second.public_key,second.sign)
        self.assertTrue(node_check(spend,tx,0))

    def test_digest_only_is_not_a_payment_lock(self):
        secret = test_secret(); key = public_key(secret)
        digest = bytes(32); sig = sign_digest(secret,digest)
        parent = Transaction((Input(b'\x55'*32,0),),(Output(1000,locking_script(key,transaction=False)),))
        # The same proof can spend to two different destinations: intentional warning.
        for output in (Output(900,b'\x51'),Output(800,b'\x00')):
            tx = Transaction((Input(parent.txid_wire(),0,push(digest)+push(sig)),),(output,))
            self.assertTrue(node_check(tx,parent,0))
            self.assertTrue(chain_valid(tx,[parent]))


if __name__ == '__main__': unittest.main()
