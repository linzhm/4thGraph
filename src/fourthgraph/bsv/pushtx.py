"""Fixed-r PUSHTX transaction binding for signature verifiers."""
from fourthgraph.bsv.script import asm, number, push
from fourthgraph.bsv.transaction import ANYONECANPAY, CHRONICLE, FORKID, SIGHASH_ALL, SIGHASH_SINGLE, SIGHASH_TYPES

N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
R = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
PUBLIC = bytes.fromhex('02' + f'{R:064x}')
REVERSE32 = asm('OP_1 OP_SPLIT OP_SWAP OP_TOALTSTACK')*31 + asm('OP_FROMALTSTACK OP_CAT')*31
REVERSE32_ON_STACK = asm('OP_1 OP_SPLIT')*31 + asm('OP_SWAP OP_CAT')*31


def _binding_der_parts(compact):
    # H -> positive big-endian integer -> s=min((H+r)%n,n-(H+r)%n).
    # Construct strict DER in Script; no supplied ECDSA signature is trusted.
    reverse = REVERSE32_ON_STACK if compact else REVERSE32
    if compact:
        # Keep one copy of n for both the modulus and low-S subtraction.
        low_s = number(N) + asm('OP_TUCK OP_MOD OP_DUP OP_VERIFY OP_TUCK OP_SUB OP_MIN')
    else:
        low_s = (number(N) + asm('OP_MOD OP_DUP OP_VERIFY OP_DUP') + number(N) +
                 asm('OP_SWAP OP_SUB OP_MIN'))
    normalize = (push(b'\0') + asm('OP_CAT OP_BIN2NUM') + number(R) + asm('OP_ADD') +
                 low_s + asm('OP_SIZE OP_TOALTSTACK') + number(32) + asm('OP_NUM2BIN'))
    der = (number(32) + asm('OP_FROMALTSTACK OP_SUB OP_SPLIT OP_NIP OP_SIZE OP_TUCK OP_TOALTSTACK OP_CAT') +
           push(bytes.fromhex('0220'+f'{R:064x}'+'02')) + asm('OP_SWAP OP_CAT OP_FROMALTSTACK') + number(36) +
           asm('OP_ADD') + push(b'\x30') + asm('OP_SWAP OP_CAT OP_SWAP OP_CAT'))
    return reverse, normalize, reverse, der


def binding_der(*, compact=False):
    return b''.join(_binding_der_parts(compact))


def _public_from_der():
    # The fixed r starts at byte four of DER and is the x coordinate of the key.
    return (asm('OP_DUP OP_4 OP_SPLIT OP_NIP') + number(32)
            + asm('OP_SPLIT OP_DROP OP_2 OP_SWAP OP_CAT'))


def fixed_key_checksig_parts(sighash, *, compact=False, reuse_r=False):
    """Emit the fixed-key authentication as linkable code fragments."""
    der = _binding_der_parts(compact)
    flag = push(bytes([sighash])) + asm('OP_CAT')
    if not reuse_r:
        check = flag + push(PUBLIC) + asm('OP_CHECKSIG')
    else:
        check = _public_from_der() + asm('OP_SWAP') + flag + asm('OP_SWAP OP_CHECKSIG')
    return (*der, check)


def fixed_key_checksig(sighash, *, compact=False, reuse_r=False):
    """Authenticate a digest with the fixed PUSHTX key and flag."""
    return b''.join(fixed_key_checksig_parts(sighash, compact=compact, reuse_r=reuse_r))


# Lamport suffixes. Other verifiers can provide their own suffixes.
ORDINARY_CODE = asm('OP_ENDIF OP_CHECKSIG')
COMPANION_CODE = asm('OP_IF OP_CHECKSIGVERIFY OP_ELSE OP_CODESEPARATOR OP_ENDIF OP_CHECKSIG')
# Fixed (d=k=1) signature of the native OTDA unpaired SINGLE constant,
# read as big-endian ECDSA digest 01 00...00 (not integer 1).
ONE_DER = bytes.fromhex('30440220' + f'{R:064x}' + '0220' + f'{R+(1<<248):064x}')


def _check_bip143_shape(script_code):
    # Both templates use a single-byte CompactSize scriptCode length.
    if len(script_code) >= 253:
        raise ValueError('PUSHTX scriptCode must use a one-byte length')
    length = 157 + len(script_code)
    return (asm('OP_OVER OP_SIZE') + number(length) + asm('OP_NUMEQUALVERIFY') +
            number(104) + asm('OP_SPLIT OP_NIP') + number(len(script_code)+1) +
            asm('OP_SPLIT OP_DROP') + push(bytes([len(script_code)])+script_code) + asm('OP_EQUALVERIFY'))


def authorization_checks(ordinary_code, companion_code, *, compact=False, compact_shape=False):
    """Check the signed preimage shape and preserve its mode and type on altstack."""
    # Entry P S mode; alt: mode, then actual base binding's one-byte type.
    code = asm('OP_DEPTH OP_3 OP_NUMEQUALVERIFY OP_DUP OP_0 OP_EQUAL OP_OVER OP_1 OP_EQUAL OP_BOOLOR OP_VERIFY')
    code += asm('OP_DUP OP_TOALTSTACK')
    code += asm('OP_2 OP_PICK OP_SIZE OP_4 OP_SUB OP_SPLIT OP_NIP')
    # Check trailing three bytes are zero and validate the exact one-byte type.
    code += asm('OP_1 OP_SPLIT') + push(bytes(3)) + asm('OP_EQUALVERIFY OP_DUP')
    if compact:
        # Remove only the two optional bits. The remaining type must be
        # ForkID with one of the three defined base modes.
        mask = 0xff ^ (ANYONECANPAY | CHRONICLE)
        code += push(bytes([mask])) + asm('OP_AND OP_BIN2NUM')
        code += number(FORKID | SIGHASH_ALL) + number((FORKID | SIGHASH_SINGLE) + 1) + asm('OP_WITHIN')
    else:
        for i, flag in enumerate(sorted(SIGHASH_TYPES)):
            code += (asm('OP_OVER') if i else b'') + push(bytes([flag])) + asm('OP_EQUAL')
            if i:
                code += asm('OP_BOOLOR')
    code += asm('OP_VERIFY OP_TOALTSTACK OP_IF')
    # Reuse the authenticated type via altstack; only 0x43/c3 may take the companion branch.
    code += asm('OP_FROMALTSTACK OP_DUP OP_TOALTSTACK')
    if compact_shape:
        code += asm('0x7f OP_AND 0x43 OP_EQUALVERIFY')
    else:
        code += asm('OP_DUP') + push(b'\x43') + asm('OP_EQUAL OP_SWAP')
        code += push(b'\xc3') + asm('OP_EQUAL OP_BOOLOR OP_VERIFY')
    code += _check_bip143_shape(companion_code)
    code += asm('OP_OVER') + number(117 + len(companion_code)) + asm('OP_SPLIT OP_NIP') + number(32) + asm('OP_SPLIT OP_DROP')
    code += asm('OP_0 32 OP_NUM2BIN') if compact_shape else push(bytes(32))
    code += asm('OP_EQUALVERIFY OP_ELSE')
    code += asm('OP_FROMALTSTACK OP_DUP OP_TOALTSTACK') + push(b'\x20') + asm('OP_AND')
    code += push(b'\x20') + asm('OP_EQUAL OP_NOTIF') + _check_bip143_shape(ordinary_code)
    return code + asm('OP_ENDIF OP_ENDIF')


def _companion_der_from_public():
    # Copy the x coordinate. The fixed companion s shares its final 31 bytes.
    return (asm('OP_OVER OP_1 OP_SPLIT OP_NIP OP_DUP OP_1 OP_SPLIT OP_NIP')
            + push(ONE_DER[36:39]) + asm('OP_SWAP OP_CAT OP_CAT')
            + push(ONE_DER[:4]) + asm('OP_SWAP OP_CAT'))


def check_binding(companion_code, *, compact=False, reuse_r=False, compact_companion=False):
    """Consume the authorized digest and enforce the native current-input relation."""
    # Entry H; alt bottom-to-top mode, type. Both signatures are derived on chain.
    code = binding_der(compact=compact) + asm('OP_FROMALTSTACK OP_CAT')
    code += _public_from_der() if reuse_r else push(PUBLIC)
    code += asm('OP_FROMALTSTACK OP_DUP OP_IF OP_TOALTSTACK OP_OVER OP_SIZE OP_1SUB OP_SPLIT OP_NIP')
    code += push(b'\x20') + asm('OP_OR')
    code += _companion_der_from_public() if compact_companion else push(ONE_DER)
    code += asm('OP_SWAP OP_CAT')
    # The ordinary and companion signatures use the same public key.
    code += asm('OP_OVER') if reuse_r else push(PUBLIC)
    code += asm('OP_FROMALTSTACK OP_ENDIF OP_CODESEPARATOR') + companion_code
    return code
