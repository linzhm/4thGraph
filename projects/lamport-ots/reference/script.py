"""Unrolled Lamport verifier and fixed-r PUSHTX transaction binding."""
from hashlib import sha256
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))
from fourthgraph.bsv.pushtx import N, R, PUBLIC, ORDINARY_CODE, COMPANION_CODE
from fourthgraph.bsv.pushtx import authorization_checks, binding_der, check_binding
from fourthgraph.bsv.script import asm, push, number
from lamport import KEY_BYTES, SIGNATURE_BYTES, require_bytes


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


def _committed_verifier(key):
    """Rebuild the ordered public-key pairs and check their SHA-256 commitment."""
    require_bytes(key, KEY_BYTES, 'public key')
    code = bytearray(asm('OP_0 OP_TOALTSTACK'))
    for _ in range(32):
        # Altstack holds the accumulated public key and the remaining digest.
        code += asm('OP_1 OP_SPLIT OP_SWAP') + push(b'\0') + asm('OP_CAT OP_BIN2NUM')
        code += asm('OP_SWAP OP_TOALTSTACK OP_0 OP_ROT')
        for _ in range(8):
            # Main stack: digest digit, current chunk, remaining interleaved proof.
            code += number(32) + asm('OP_SPLIT OP_SWAP OP_SHA256 OP_SWAP')
            code += number(32) + asm('OP_SPLIT OP_TOALTSTACK')
            # Bit 0 puts the selected hash first. Bit 1 puts its sibling first.
            code += asm('OP_3 OP_PICK OP_2 OP_MOD OP_IF OP_SWAP OP_ENDIF OP_CAT OP_CAT')
            code += asm('OP_SWAP OP_2 OP_DIV OP_SWAP OP_FROMALTSTACK')
        code += asm('OP_ROT OP_0 OP_EQUALVERIFY OP_FROMALTSTACK OP_FROMALTSTACK')
        code += asm('OP_3 OP_ROLL OP_CAT OP_TOALTSTACK')
    code += asm('OP_0 OP_EQUALVERIFY OP_0 OP_EQUALVERIFY OP_FROMALTSTACK OP_SHA256')
    return bytes(code) + push(sha256(key).digest()) + asm('OP_EQUALVERIFY')


def _v1_script(key, *, transaction=True):
    """Witness: [158-byte BIP143 ALL preimage OR 32-byte digest, 8192-byte signature]."""
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
    """The original two-push BIP143 ALL template, preserved byte-for-byte."""
    return _v1_script(key)


def locking_script(key, *, transaction=True):
    """Universal lock witness: preimage, packed signature, companion selector."""
    if not transaction:
        return _v1_script(key, transaction=False)
    return _payment_lock(SIGNATURE_BYTES, verifier(key))


def committed_locking_script(key):
    """Build the shorter payment lock with a commitment to the Lamport key."""
    return _payment_lock(KEY_BYTES, _committed_verifier(key))


def forth_committed_locking_script(key):
    """Build the experimental Forth-compiled committed-key payment lock."""
    from forth_verifier import committed_verifier_code

    require_bytes(key, KEY_BYTES, 'public key')
    verifier_code = committed_verifier_code() + push(sha256(key).digest()) + asm('OP_EQUALVERIFY')
    return _payment_lock(KEY_BYTES, verifier_code)


def _payment_lock(proof_bytes, verifier_code):
    code = authorization_checks(ORDINARY_CODE, COMPANION_CODE)
    code += asm('OP_SIZE') + number(proof_bytes) + asm('OP_NUMEQUALVERIFY OP_SWAP OP_HASH256 OP_DUP OP_TOALTSTACK')
    return code + verifier_code + asm('OP_FROMALTSTACK') + check_binding(COMPANION_CODE)
