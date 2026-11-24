"""Regenerate all public XMSS payment fixtures using the pinned C oracle."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from payment import authorization
from script import locking_script
from shared.transaction import SIGHASH_SINGLE, SIGHASH_TYPES, Input, Output, Transaction
from xmss import SIGNATURE_BYTES, verify

ORACLE_REVISION = '171ccbd26f098542a67eb5d2b128281c80bd71a6'
VECTORS = Path(__file__).resolve().parents[1] / 'template' / 'vectors.json'
RAW_MESSAGE = bytes(range(32))


def funding(public_key):
    other = Transaction((Input(b'\x45' * 32, 0),), (Output(1_000, b'\x51'),))
    xmss = Transaction((Input(b'\x6a' * 32, 0),), (Output(10_000, locking_script(public_key)),))
    return other, xmss


def unsigned_spend(parents, version, paired):
    inputs = tuple(Input(parent.txid_wire(), 0) for parent in parents)
    outputs = (Output(500, b'\x51'), Output(10_400, b'\x51')) if paired else (Output(10_900, b'\x51'),)
    return Transaction(inputs, outputs, version=version)


def signing_cases(parents):
    yield 0, RAW_MESSAGE, {'kind': 'raw'}
    index = 0
    for version in (1, 2):
        for flag in sorted(SIGHASH_TYPES):
            for paired in (True, False) if flag & 31 == SIGHASH_SINGLE else (True,):
                spend = unsigned_spend(parents, version, paired)
                auth = authorization(spend, 1, 10_000, flag)
                index += 31
                yield index, auth.digest(), {'kind': 'payment', 'version': version, 'flag': flag, 'paired': paired}
    yield 1022, RAW_MESSAGE, {'kind': 'raw'}


def generate(binary):
    with TemporaryDirectory(prefix='xmss-test-only-') as directory:
        state = str(Path(directory) / 'public-fixture-state')
        public_key = subprocess.check_output([binary, 'key', state], timeout=120)
        parents = funding(public_key)
        cases = list(signing_cases(parents))
        records = b''.join(index.to_bytes(4, 'big') + digest for index, digest, _ in cases)
        signatures = subprocess.check_output([binary, 'sign', state], input=records, timeout=300)
    if len(signatures) != len(cases) * SIGNATURE_BYTES:
        raise ValueError('unexpected size of the C reference signatures')

    vectors = []
    for position, (index, message, metadata) in enumerate(cases):
        signature = signatures[position * SIGNATURE_BYTES:(position + 1) * SIGNATURE_BYTES]
        if int.from_bytes(signature[:4], 'big') != index or not verify(public_key, message, signature):
            raise ValueError('C and Python verification disagree')
        vectors.append({**metadata, 'index': index, 'message': message.hex(), 'signature': signature.hex()})
    lock = parents[1].outputs[0].script
    return {
        'algorithm': 'XMSS-SHA2_10_256', 'oracle_commit': ORACLE_REVISION,
        'seed_test_only': bytes(range(96)).hex(), 'public_key': public_key.hex(),
        'locking_sha256': sha256(lock).hexdigest(), 'vectors': vectors,
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('oracle', type=Path)
    args = parser.parse_args()
    print(json.dumps(generate(str(args.oracle.resolve(strict=True))), indent=2))
