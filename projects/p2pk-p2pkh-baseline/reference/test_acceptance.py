"""Bounded acceptance matrix for complete native secp256k1 inputs."""

from base64 import b64encode
from dataclasses import replace
from functools import cache
from itertools import product
import json
from math import prod
import os
from pathlib import Path
import unittest
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from tx_engine import Tx

from script_lab import OTHER_PUB, OWNER_PUB, TEMPLATES
from fourthgraph.bsv.script import push
from fourthgraph.bsv.transaction import (
    ANYONECANPAY, CHRONICLE, SIGHASH_ALL, SIGHASH_NONE, Input, Output, Transaction,
    hash256, preimage_forkid, preimage_otda,
)


SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SIGHASH_FLAGS = (0x41, 0x42, 0x43, 0x61, 0x62, 0x63, 0xc1, 0xc2, 0xc3, 0xe1, 0xe2, 0xe3)
WITNESSES = (('p2pk', None), ('p2pkh', OWNER_PUB), ('p2pkh', OTHER_PUB))
MUTATIONS = (
    'unchanged', 'version', 'locktime', 'current_sequence', 'other_sequence',
    'current_outpoint', 'other_outpoint', 'signed_amount', 'current_output', 'other_output',
)
AXES = (WITNESSES, (1, 2), (0, 1), SIGHASH_FLAGS, (1, 2), MUTATIONS)
CASE_COUNT = 2_880
ACCEPT_COUNT = 368
NODE_FLAGS = sum(1 << bit for bit in (1, 2, 3, 16, 18, 19, 20, 21))
BASE_FLAGS = NODE_FLAGS & ~((1 << 20) | (1 << 21))
CONTEXTS = (
    (1, 1, BASE_FLAGS),
    (3, 1, BASE_FLAGS | (1 << 20)),
    (3, 3, NODE_FLAGS),
)
SINGLE_FLAGS = (0x43, 0x63, 0xc3, 0xe3)
BOUND_WITNESSES = (('p2pk', None), ('p2pkh', OWNER_PUB))
UNPAIRED_MUTATIONS = ('unchanged', 'other_output', 'current_sequence', 'add_output', 'wrong_digest')


def preserves_authorization(mutation, flag):
    base = flag & 0x1f
    anyone = bool(flag & ANYONECANPAY)
    commitments = {
        'unchanged': False,
        'version': True,
        'locktime': True,
        'current_sequence': True,
        'other_sequence': not anyone and base == SIGHASH_ALL,
        'current_outpoint': True,
        'other_outpoint': not anyone,
        'signed_amount': not bool(flag & CHRONICLE),
        'current_output': base != SIGHASH_NONE,
        'other_output': base == SIGHASH_ALL,
    }
    return not commitments[mutation]


def digest(tx, index, previous, flag, amount):
    if flag & CHRONICLE:
        if flag in SINGLE_FLAGS and index >= len(tx.outputs):
            return b'\x01' + bytes(31)
        image = preimage_otda(tx, index, previous.script, flag)
    else:
        image = preimage_forkid(tx, index, amount, previous.script, flag)
    return hash256(image)


@cache
def fixture(template, version, index):
    lock = bytes.fromhex(TEMPLATES[template][1])
    owned = Transaction((Input(b'\x11' * 32, 0),), (Output(10_000, lock),))
    other = Transaction((Input(b'\x22' * 32, 0),), (Output(1_000, b'\x51'),))
    parents = (owned, other) if index == 0 else (other, owned)
    tx = Transaction(tuple(Input(parent.txid_wire(), 0, sequence=1_000 + i)
                           for i, parent in enumerate(parents)),
                     (Output(4_000, b'\x51'), Output(5_000, b'\x51')), version=version)
    return tx, parents


def mutate(tx, parents, index, mutation):
    if mutation == 'version':
        return replace(tx, version=3 - tx.version), parents
    if mutation == 'locktime':
        return replace(tx, locktime=1), parents
    if mutation in ('unchanged', 'signed_amount'):
        return tx, parents
    field = index if mutation.startswith('current_') else 1 - index
    inputs = list(tx.inputs)
    if mutation.endswith('_sequence'):
        inputs[field] = replace(inputs[field], sequence=inputs[field].sequence + 1)
        return replace(tx, inputs=tuple(inputs)), parents
    if mutation.endswith('_outpoint'):
        changed_parents = list(parents)
        changed_parents[field] = replace(parents[field], locktime=1)
        inputs[field] = replace(inputs[field], txid=changed_parents[field].txid_wire())
        return replace(tx, inputs=tuple(inputs)), tuple(changed_parents)
    if mutation.endswith('_output'):
        outputs = list(tx.outputs)
        outputs[field] = replace(outputs[field], value=outputs[field].value + 1)
        return replace(tx, outputs=tuple(outputs)), parents
    raise AssertionError(f'unknown fixture mutation {mutation}')


@cache
def sign(scalar, message):
    # Public test key scalars. These fixture keys must never receive funds.
    key = ec.derive_private_key(scalar, ec.SECP256K1())
    algorithm = ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    r, s = utils.decode_dss_signature(key.sign(message, algorithm))
    signature = utils.encode_dss_signature(r, min(s, SECP256K1_ORDER - s))
    key.public_key().verify(signature, message, algorithm)
    return signature


def unlock(tx, index, scalar, signed_digest, flag, public_key):
    witness = push(sign(scalar, signed_digest) + bytes((flag,)))
    if public_key is not None:
        witness += push(public_key)
    return tx.with_script(index, witness)


def request_for(tx, index, previous, flags, height):
    return dict(tx=tx.serialize().hex(), n=index, flags=flags, reportflags=True,
                txo=dict(lock=previous.script.hex(), value=previous.value, height=height))


class NativeAcceptance(unittest.TestCase):
    def test_complete_input_matrix(self):
        self.assertEqual(prod(map(len, AXES)), CASE_COUNT)
        self.assertTrue(all(len(set(axis)) == len(axis) for axis in AXES))
        for scalar, expected in ((1, OWNER_PUB), (2, OTHER_PUB)):
            key = ec.derive_private_key(scalar, ec.SECP256K1()).public_key()
            self.assertEqual(key.public_bytes(serialization.Encoding.X962,
                                              serialization.PublicFormat.CompressedPoint), expected)
        visited, accepted, node_cases = set(), set(), []
        cookie_path = os.environ.get('REGTEST_COOKIE')
        for case in product(*AXES):
            (template, public_key), version, index, flag, scalar, mutation = case
            with self.subTest(template=template, owner_key=public_key == OWNER_PUB, version=version,
                              index=index, sighash=hex(flag), scalar=scalar, mutation=mutation):
                self.assertTrue(all(value in axis for value, axis in zip(case, AXES)))
                self.assertNotIn(case, visited)
                visited.add(case)
                tx, parents = fixture(template, version, index)
                previous = parents[index].outputs[0]
                signed_amount = previous.value - 1 if mutation == 'signed_amount' else previous.value
                signed_digest = digest(tx, index, previous, flag, signed_amount)
                spend, parents = mutate(tx, parents, index, mutation)
                actual_digest = digest(spend, index, previous, flag, previous.value)
                preserves = preserves_authorization(mutation, flag)
                self.assertEqual(signed_digest == actual_digest, preserves)
                expected = preserves and scalar == 1 and public_key in (None, OWNER_PUB)
                spend = unlock(spend, index, scalar, signed_digest, flag, public_key)
                self.check_engine(spend, parents, expected)
                if expected:
                    accepted.add(case)
                if cookie_path:
                    node_cases.append((case, request_for(spend, index, previous, NODE_FLAGS, 3), expected))

        self.assertEqual(len(visited), CASE_COUNT)
        self.assertEqual(len(accepted), ACCEPT_COUNT)
        if cookie_path:
            self.assertEqual(len(node_cases), CASE_COUNT)
            self.check_node(cookie_path, node_cases)

    def test_unpaired_single_mutations(self):
        axes = (BOUND_WITNESSES, (1, 2), SINGLE_FLAGS, UNPAIRED_MUTATIONS)
        visited, accepted, node_cases = set(), set(), []
        self.assertEqual(prod(map(len, axes)), 80)
        self.assertTrue(all(len(set(axis)) == len(axis) for axis in axes))
        for case in product(*axes):
            (template, public_key), version, flag, mutation = case
            with self.subTest(case=case):
                self.assertTrue(all(value in axis for value, axis in zip(case, axes)))
                self.assertNotIn(case, visited)
                visited.add(case)
                tx, parents = fixture(template, version, 1)
                tx = replace(tx, outputs=tx.outputs[:1])
                previous = parents[1].outputs[0]
                signed_digest = digest(tx, 1, previous, flag, previous.value)
                expected = mutation in ('unchanged', 'other_output') or (
                    mutation == 'current_sequence' and bool(flag & CHRONICLE))
                if mutation == 'add_output':
                    spend = replace(tx, outputs=tx.outputs + (Output(1, b'\x51'),))
                elif mutation == 'wrong_digest':
                    spend = tx
                    signed_digest = bytes([signed_digest[0] ^ 0x80]) + signed_digest[1:]
                else:
                    spend, parents = mutate(tx, parents, 1, mutation)
                self.assertEqual(signed_digest == digest(spend, 1, previous, flag, previous.value), expected)
                spend = unlock(spend, 1, 1, signed_digest, flag, public_key)
                self.check_engine(spend, parents, expected)
                if expected:
                    accepted.add(case)
                node_cases.append((case, request_for(spend, 1, previous, NODE_FLAGS, 3), expected))
        self.assertEqual(len(visited), 80)
        self.assertEqual(len(accepted), 40)
        if cookie_path := os.environ.get('REGTEST_COOKIE'):
            self.assertEqual(len(node_cases), 80)
            self.check_node(cookie_path, node_cases)

    def test_chronicle_activation_contexts(self):
        modes = tuple((flag, True) for flag in SIGHASH_FLAGS) + tuple((flag, False) for flag in SINGLE_FLAGS)
        axes = (BOUND_WITNESSES, (1, 2), modes, CONTEXTS)
        visited, accepted, node_cases = set(), set(), []
        self.assertEqual(prod(map(len, axes)), 192)
        self.assertTrue(all(len(set(axis)) == len(axis) for axis in axes))
        for case in product(*axes):
            (template, public_key), version, (flag, paired), (spend_height, utxo_height, flags) = case
            with self.subTest(case=case):
                self.assertTrue(all(value in axis for value, axis in zip(case, axes)))
                self.assertNotIn(case, visited)
                visited.add(case)
                tx, parents = fixture(template, version, 1)
                if not paired:
                    tx = replace(tx, outputs=tx.outputs[:1])
                previous = parents[1].outputs[0]
                spend = unlock(tx, 1, 1, digest(tx, 1, previous, flag, previous.value), flag, public_key)
                expected = spend_height >= 2 or not flag & CHRONICLE
                self.check_engine(spend, parents, expected, spend_height=spend_height, utxo_height=utxo_height)
                if expected:
                    accepted.add(case)
                node_cases.append((case, request_for(spend, 1, previous, flags, utxo_height), expected))
        self.assertEqual(len(visited), 192)
        self.assertEqual(len(accepted), 160)
        if cookie_path := os.environ.get('REGTEST_COOKIE'):
            self.assertEqual(len(node_cases), 192)
            self.check_node(cookie_path, node_cases)

    def check_engine(self, spend, parents, expected, *, spend_height=3, utxo_height=3):
        engine_tx = Tx.parse(spend.serialize())
        engine_parents = [Tx.parse(parent.serialize()) for parent in parents]
        heights = [(txin.txid[::-1].hex(), txin.vout, utxo_height) for txin in spend.inputs]
        if expected:
            engine_tx.validate_with_chronicle_context(engine_parents, spend_height, 2, heights, True)
        else:
            with self.assertRaisesRegex((ValueError, RuntimeError), 'Error evaluating the script'):
                engine_tx.validate_with_chronicle_context(engine_parents, spend_height, 2, heights, True)

    def check_node(self, cookie_path, cases):
        cookie = b64encode(Path(cookie_path).read_bytes().strip()).decode()
        headers = {'Authorization': 'Basic ' + cookie, 'Content-Type': 'application/json'}
        url = os.environ.get('REGTEST_URL', 'http://127.0.0.1:18443')
        for start in range(0, len(cases), 48):
            batch = cases[start:start + 48]
            data = json.dumps(dict(jsonrpc='1.0', id=start, method='verifyscript',
                                   params=[[entry[1] for entry in batch], False, 5000])).encode()
            with urlopen(Request(url, data, headers), timeout=30) as response:
                reply = json.load(response)
            self.assertIsNone(reply['error'])
            self.assertEqual(len(reply['result']), len(batch))
            for (case, request, expected), result in zip(batch, reply['result']):
                with self.subTest(node_case=case):
                    self.assertEqual(result['flags'], request['flags'])
                    self.assertEqual(result['result'], 'ok' if expected else 'error', result)
