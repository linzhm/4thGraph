"""Emit the RFC 8391 verifier and a transaction-bound BSV payment lock."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from shared.pushtx import authorization_checks, check_binding
from shared.script import asm, number, push
from shared.wots_sha2_script import endpoints_script
from wots import KEY_BYTES, N, SIGNATURE_BYTES

# ScriptCode suffixes differ from Lamport; the extra OP_NOPs are domain tags.
ORDINARY_CODE = asm('OP_NOP OP_ENDIF OP_CHECKSIG')
COMPANION_CODE = asm('OP_NOP OP_IF OP_CHECKSIGVERIFY OP_ELSE OP_CODESEPARATOR') + ORDINARY_CODE


def verifier(key):
    """Consume packed signature and digest, preserving existing altstack items."""
    if not isinstance(key, bytes) or len(key) != KEY_BYTES:
        raise ValueError('WOTS+ public key must be 64 bytes')
    public_seed, commitment = key[:N], key[N:]
    prf_prefix = (3).to_bytes(N, 'big') + public_seed + bytes(20)
    code = bytearray(push(prf_prefix) + asm('OP_ROT OP_ROT'))
    code += endpoints_script() + asm('OP_SHA256') + push(commitment)
    return bytes(code) + asm('OP_EQUALVERIFY OP_2DROP')


def locking_script(key, *, transaction=True):
    """Build a payment lock or a detached digest verifier for tests."""
    if not transaction:
        shape = asm('OP_DEPTH OP_2 OP_NUMEQUALVERIFY OP_OVER OP_SIZE')
        shape += number(N) + asm('OP_NUMEQUALVERIFY OP_DROP OP_SIZE')
        shape += number(SIGNATURE_BYTES) + asm('OP_NUMEQUALVERIFY OP_SWAP')
        return shape + verifier(key) + asm('OP_1')
    shape = authorization_checks(ORDINARY_CODE, COMPANION_CODE)
    shape += asm('OP_SIZE') + number(SIGNATURE_BYTES) + asm('OP_NUMEQUALVERIFY')
    shape += asm('OP_SWAP OP_HASH256 OP_DUP OP_TOALTSTACK')
    return shape + verifier(key) + asm('OP_FROMALTSTACK') + check_binding(COMPANION_CODE)
