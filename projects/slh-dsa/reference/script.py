"""Generate transaction-bound SLH-DSA-SHA2-128s Bitcoin Script."""
from functools import cache
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from runar_slh import emit_verify_slh_dsa
from shared.pushtx import authorization_checks, check_binding
from shared.script import asm, number, push
from slh import KEY_BYTES, SIGNATURE_BYTES

# Match the binding's CODESEPARATOR suffixes and distinguish this template
# from the Lamport and WOTS+ suffixes (zero and one NOP, respectively).
ORDINARY_CODE = asm('OP_NOP OP_NOP OP_ENDIF OP_CHECKSIG')
COMPANION_CODE = asm('OP_NOP OP_NOP OP_IF OP_CHECKSIGVERIFY OP_ELSE OP_CODESEPARATOR') + ORDINARY_CODE


@cache
def _verification_program():
    program = bytearray()
    emit_verify_slh_dsa(program.extend)
    return bytes(program)


def verifier(key):
    """Consume signature and raw message, preserving earlier altstack items."""
    if not isinstance(key, bytes) or len(key) != KEY_BYTES:
        raise ValueError('SLH-DSA-SHA2-128s public key must be 32 bytes')
    # FIPS 205 pure signing with empty context: 00 || 00 || M.
    domain = push(b'\x00\x00') + asm('OP_SWAP OP_CAT OP_SWAP')
    return domain + push(key) + _verification_program() + asm('OP_VERIFY')


def locking_script(key, *, transaction=True):
    """Build a payment lock, or a detached message verifier for tests."""
    if not transaction:
        shape = asm('OP_DEPTH OP_2 OP_NUMEQUALVERIFY OP_SIZE')
        shape += number(SIGNATURE_BYTES) + asm('OP_NUMEQUALVERIFY OP_SWAP')
        return shape + verifier(key) + asm('OP_1')
    shape = authorization_checks(ORDINARY_CODE, COMPANION_CODE)
    shape += asm('OP_SIZE') + number(SIGNATURE_BYTES) + asm('OP_NUMEQUALVERIFY')
    shape += asm('OP_SWAP OP_HASH256 OP_DUP OP_TOALTSTACK')
    return shape + verifier(key) + asm('OP_FROMALTSTACK') + check_binding(COMPANION_CODE)
