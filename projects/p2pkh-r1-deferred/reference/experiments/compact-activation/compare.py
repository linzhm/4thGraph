"""Run the funding-size experiment with the reference project's pinned dependencies."""
from hashlib import sha256
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REFERENCE = HERE.parent.parent
sys.path[:0] = [str(REFERENCE), str(REFERENCE.parents[2])]

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

import deferred
from shared.evaluate import evaluate
from shared.script import asm, assemble
from test_deferred import DeferredTests, fixture

K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
K1_GENERATOR_X = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798


def check_digest_ranges(binder):
    program = asm('OP_TOALTSTACK') + binder
    for first in range(256):
        # Exercise lower and upper boundaries as well as a nonconstant suffix.
        for tail in (bytes(31), bytes([255]) * 31, sha256(bytes([first])).digest()[1:]):
            digest = bytes([first]) + tail
            flag = bytes([0x43])
            (signature, public_key), alt = evaluate(program, [digest, flag])
            delta = 1 if first < 126 else -125 if first < 252 else -251
            expected_s = int.from_bytes(digest, 'big') + delta * 2**248
            assert not alt and signature[-1:] == flag
            assert 0 < expected_s <= K1_ORDER // 2 and len(signature) == 71
            assert utils.decode_dss_signature(signature[:-1]) == (K1_GENERATOR_X, expected_s)
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key)
            key.verify(signature[:-1], digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))


def main():
    binder = assemble(HERE, bytes(20), entry='BIND_RAW_DIGEST')
    check_digest_ranges(binder)
    baseline = fixture()[3].outputs[0]
    # Keep the existing lock's branches, amount, owner, target and native
    # CHECKSIG suffixes. Both binding sites now operate on the raw digest.
    blocks = dict(deferred._binder_blocks(), UINT256BE=b'', K1_BIND_DIGEST=binder)
    with patch.object(deferred, '_binder_blocks', return_value=blocks):
        candidate = fixture()[3].outputs[0]
        tests = unittest.TestSuite(DeferredTests(name) for name in (
            'test_preflight_rejects_mismatch',
            'test_complete_batch_and_r1_spend_in_chain_gang',
            'test_activation_constraints_in_chain_gang',
            'test_all_modes_keep_the_forkid_output_constraint',
            'test_malformed_zero_commitment_fails_in_chain_gang',
        ))
        if not unittest.TextTestRunner(verbosity=2).run(tests).wasSuccessful():
            return 1
    for label, output in [('current', baseline), ('candidate', candidate)]:
        size = len(output.serialize())
        print(f'{label}: scriptPubKey={len(output.script)} B, TxOut={size} B, 1000 outputs={1000 * size} B')
    return 0


if __name__ == '__main__':
    sys.exit(main())
