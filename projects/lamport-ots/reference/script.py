"""Unrolled Lamport verifier and fixed-r PUSHTX transaction binding."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from shared.pushtx import N, R, PUBLIC, ORDINARY_CODE, COMPANION_CODE
from shared.pushtx import authorization_checks, binding_der, check_binding
from shared.script import asm, push, number
from lamport import KEY_BYTES, require_bytes


def binding():
    return binding_der() + push(b'\x41') + asm('OP_CAT') + push(PUBLIC) + asm('OP_CODESEPARATOR OP_CHECKSIG')


def verifier(key):
    """Input S,H; output empty stack. Retains any earlier altstack entries."""
    require_bytes(key, KEY_BYTES, 'public key')
    code = bytearray()
    for byte in range(32):
        code += asm('OP_1 OP_SPLIT OP_SWAP') + push(b'\0') + asm('OP_CAT OP_BIN2NUM OP_SWAP OP_TOALTSTACK')
        for bit in range(8):
            i = byte*8 + bit
            p0, p1 = key[64*i:64*i+32], key[64*i+32:64*i+64]
            code += asm('OP_DUP OP_2 OP_MOD OP_IF') + push(p1) + asm('OP_ELSE') + push(p0)
            code += asm('OP_ENDIF OP_TOALTSTACK OP_2 OP_DIV OP_SWAP') + number(32)
            code += asm('OP_SPLIT OP_SWAP OP_SHA256 OP_FROMALTSTACK OP_EQUALVERIFY OP_SWAP')
        code += asm('OP_DROP OP_FROMALTSTACK')
    return bytes(code) + asm('OP_0 OP_EQUALVERIFY OP_0 OP_EQUALVERIFY')


def _v1_script(key, *, transaction=True):
    """Witness: [158-byte ForkID ALL preimage OR 32-byte digest, 8192-byte signature]."""
    code = asm('OP_DEPTH OP_2 OP_NUMEQUALVERIFY OP_OVER OP_SIZE')
    code += number(158 if transaction else 32) + asm('OP_NUMEQUALVERIFY OP_DROP OP_SIZE')
    code += number(8192) + asm('OP_NUMEQUALVERIFY')
    if transaction:
        code += asm('OP_OVER') + number(104) + asm('OP_SPLIT OP_NIP OP_2 OP_SPLIT OP_DROP') + push(b'\x01\xac') + asm('OP_EQUALVERIFY')
        code += asm('OP_OVER') + number(154) + asm('OP_SPLIT OP_NIP') + push(b'\x41\0\0\0') + asm('OP_EQUALVERIFY OP_SWAP OP_HASH256 OP_DUP OP_TOALTSTACK')
    else:
        code += asm('OP_SWAP')
    code += verifier(key)
    return code + (asm('OP_FROMALTSTACK') + binding() if transaction else asm('OP_1'))


def legacy_locking_script(key):
    """The original two-push ForkID ALL template, preserved byte-for-byte."""
    return _v1_script(key)


def locking_script(key, *, transaction=True):
    """Universal lock witness: preimage, packed signature, companion selector."""
    if not transaction:
        return _v1_script(key, transaction=False)
    code = authorization_checks(ORDINARY_CODE, COMPANION_CODE)
    code += asm('OP_SIZE') + number(8192) + asm('OP_NUMEQUALVERIFY OP_SWAP OP_HASH256 OP_DUP OP_TOALTSTACK')
    return code + verifier(key) + asm('OP_FROMALTSTACK') + check_binding(COMPANION_CODE)
