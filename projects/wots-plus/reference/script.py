"""Emit the RFC 8391 verifier and a transaction-bound BSV payment lock."""
from functools import cache
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from fourthgraph.bsv.pushtx import authorization_checks, check_binding
from fourthgraph.bsv.script import asm, number, push
from wots import CHAINS, KEY_BYTES, N, SIGNATURE_BYTES, W

# ScriptCode suffixes differ from Lamport; the extra OP_NOPs are domain tags.
ORDINARY_CODE = asm('OP_NOP OP_ENDIF OP_CHECKSIG')
COMPANION_CODE = asm('OP_NOP OP_IF OP_CHECKSIGVERIFY OP_ELSE OP_CODESEPARATOR') + ORDINARY_CODE

COMPACT_PROFILES = ('compact', 'compact-v2', 'compact-v3')
CACHE_PROFILES = (False, True, 'steps', *COMPACT_PROFILES)


def _message_digits():
    # Entry: signature, digest. Leave the checksum on stack and the message
    # nibbles on altstack, with the first (high nibble of byte zero) on top.
    code = bytearray(asm('OP_0'))
    for byte_index in reversed(range(N)):
        code += asm('OP_SWAP') + number(byte_index) + asm('OP_SPLIT')
        code += push(b'\0') + asm('OP_CAT OP_BIN2NUM')
        code += asm('OP_DUP OP_16 OP_MOD OP_DUP OP_TOALTSTACK')
        code += asm('OP_SWAP OP_16 OP_DIV OP_DUP OP_TOALTSTACK OP_ADD OP_ROT OP_ADD')
    maximum = 2 * N * (W - 1)
    return bytes(code) + asm('OP_NIP') + number(maximum) + asm('OP_SWAP OP_SUB')


def _chain(index, *, cached_constants):
    # Entry: PRF prefix, checksum, accumulated endpoints, remaining signature.
    code = bytearray(number(N) + asm('OP_SPLIT OP_SWAP OP_4 OP_PICK'))
    code += push(index.to_bytes(4, 'big')) + asm('OP_CAT OP_SWAP OP_FROMALTSTACK')
    if cached_constants:
        # Fixed depths include the PRF prefix, checksum, and current chain state.
        mask_zero = asm('OP_10 OP_PICK')
        mask_one = asm('OP_9 OP_PICK')
        function_prefix = asm('OP_9 OP_PICK')
    else:
        mask_zero = asm('OP_0 OP_4 OP_NUM2BIN')
        mask_one = push(b'\0\0\0\1')
        function_prefix = asm('OP_0') + number(N) + asm('OP_NUM2BIN')
    # Complete the hash chain from the signed digit through step 14. The last
    # eight bytes of ADRS encode the step and keyAndMask in big-endian order.
    for step in range(W - 1):
        code += asm('OP_DUP') + number(step) + asm('OP_GREATERTHAN OP_NOTIF OP_SWAP')
        # There are eleven live items above the step table at this access.
        step_bytes = (number(11 + W - 2 - step) + asm('OP_PICK') if cached_constants == 'steps'
                      else push(step.to_bytes(4, 'big')))
        code += asm('OP_2 OP_PICK') + step_bytes + asm('OP_CAT OP_DUP')
        code += mask_zero + asm('OP_CAT OP_SHA256 OP_SWAP')
        code += mask_one + asm('OP_CAT OP_SHA256 OP_ROT OP_XOR OP_CAT')
        code += function_prefix + asm('OP_SWAP OP_CAT OP_SHA256 OP_SWAP OP_ENDIF')
    # Drop the digit and chain prefix, then append the new endpoint.
    code += asm('OP_DROP OP_NIP OP_ROT OP_SWAP OP_CAT OP_SWAP')
    return bytes(code)


@cache
def _compact_chain(profile='compact'):
    from fourthgraph.compiler.script_builder import ScriptBuilder

    builder = ScriptBuilder.from_file(Path(__file__).with_name('compact.fth'))
    # Open gates from step 14 to 0. The hashes run in order as the gates close.
    code = builder.emit(f'{profile}-chain-start', b'')
    if profile != 'compact':
        # The counter starts at 15 minus the signed digit. The first false
        # gate consumes zero, and the innermost gate consumes the final flag.
        code += builder.emit('compact-countdown-gate', b'') * (W - 2) + asm('OP_IF')
        table_depth = 9
    else:
        for limit in reversed(range(2, W)):
            code = builder.emit('compact-if-digit-below', code, limit)
        code += asm('OP_OVER OP_NOTIF')
        table_depth = 11
    for step in range(W - 1):
        # The highest step is the nearest table entry.
        code = builder.emit(f'{profile}-hash-step', code, table_depth + W - 2 - step)
        code += asm('OP_ENDIF')
    return builder.emit(f'{profile}-chain-end', code)


def _checksum_digits(depth):
    # Three checksum nibbles, most significant first when popped from altstack.
    return (number(depth) + asm('OP_PICK OP_DUP OP_16 OP_MOD OP_TOALTSTACK OP_16 OP_DIV')
            + asm('OP_DUP OP_16 OP_MOD OP_TOALTSTACK OP_16 OP_DIV OP_TOALTSTACK'))


def _compact_constants(public_seed, *, synthesize):
    # The chain appends its one-byte index to the first 23 address bytes.
    prf_base = push((3).to_bytes(N, 'big') + public_seed + bytes(23))
    if synthesize:
        # Build each suffix as zero[3] || step || zero[4].
        suffixes = asm('OP_0 OP_3 OP_NUM2BIN')
        suffixes += b''.join(
            asm('OP_DUP') + number(step) + asm('OP_5 OP_NUM2BIN OP_CAT OP_SWAP')
            for step in range(W - 1)
        )
        suffixes += asm('OP_DROP')
        selector_bit = asm('OP_0') + number(3 * N - 1) + asm('OP_NUM2BIN OP_1 OP_CAT')
        zero_prefix = asm('OP_0') + number(N) + asm('OP_NUM2BIN')
    else:
        suffixes = b''.join(push(step.to_bytes(4, 'big') + bytes(4)) for step in range(W - 1))
        selector_bit = push(bytes(3 * N - 1) + b'\x01')
        zero_prefix = push(bytes(N))
    return suffixes + selector_bit + zero_prefix + prf_base


def _compact_verifier(public_seed, commitment, *, profile):
    synthesize = profile == 'compact-v3'
    constants = _compact_constants(public_seed, synthesize=synthesize)
    roll = number(W + 3) + asm('OP_ROLL')
    if profile != 'compact':
        # Keep the checksum below the cache so step table entries are closer.
        index = push(b'\0') if synthesize else asm('OP_0')
        prefix = _message_digits() + constants + roll + asm('OP_0 OP_SWAP') + index
        checksum_depth = W + 5
    else:
        prefix = constants + roll * 2 + _message_digits() + asm('OP_SWAP OP_0 OP_SWAP OP_0')
        checksum_depth = 3
    chain = _compact_chain(profile)
    cleanup = asm('OP_2DROP') * ((W + 3) // 2) + asm('OP_DROP')
    return (prefix + chain * (2 * N)
            + _checksum_digits(checksum_depth) + chain * (CHAINS - 2 * N)
            + asm('OP_DROP OP_0 OP_EQUALVERIFY OP_SHA256') + push(commitment)
            + asm('OP_EQUALVERIFY') + cleanup)


def verifier(key, *, cached_constants=False):
    """Consume packed signature and digest, preserving existing altstack items."""
    if not isinstance(key, bytes) or len(key) != KEY_BYTES:
        raise ValueError('WOTS+ public key must be 64 bytes')
    public_seed, commitment = key[:N], key[N:]
    if cached_constants in COMPACT_PROFILES:
        return _compact_verifier(public_seed, commitment, profile=cached_constants)
    prf_prefix = (3).to_bytes(N, 'big') + public_seed + bytes(20)
    if type(cached_constants) is not bool and cached_constants != 'steps':
        raise ValueError('unknown WOTS+ constant cache profile')
    if cached_constants:
        code = bytearray()
        if cached_constants == 'steps':
            code += b''.join(push(step.to_bytes(4, 'big')) for step in range(W - 1))
        code += push(bytes(N)) + push(bytes(4)) + push(b'\0\0\0\1')
        depth = 5 + (W - 1 if cached_constants == 'steps' else 0)
        code += push(prf_prefix) + (number(depth) + asm('OP_ROLL')) * 2
    else:
        code = bytearray(push(prf_prefix) + asm('OP_ROT OP_ROT'))
    code += _message_digits() + asm('OP_SWAP OP_0 OP_SWAP')
    for index in range(2 * N):
        code += _chain(index, cached_constants=cached_constants)
    code += _checksum_digits(2)
    for index in range(2 * N, CHAINS):
        code += _chain(index, cached_constants=cached_constants)
    code += asm('OP_0 OP_EQUALVERIFY OP_SHA256') + push(commitment)
    code += asm('OP_EQUALVERIFY OP_2DROP')
    if cached_constants:
        code += asm('OP_2DROP OP_DROP')
        if cached_constants == 'steps':
            code += asm('OP_2DROP') * ((W - 1) // 2) + asm('OP_DROP')
    return bytes(code)


def locking_script(key, *, transaction=True, cached_constants=False):
    """Build a payment lock or a detached digest verifier for tests."""
    if not transaction:
        shape = asm('OP_DEPTH OP_2 OP_NUMEQUALVERIFY OP_OVER OP_SIZE')
        shape += number(N) + asm('OP_NUMEQUALVERIFY OP_DROP OP_SIZE')
        shape += number(SIGNATURE_BYTES) + asm('OP_NUMEQUALVERIFY OP_SWAP')
        return shape + verifier(key, cached_constants=cached_constants) + asm('OP_1')
    if cached_constants in ('steps', *COMPACT_PROFILES):
        from fixed_template import lock_for_key

        return lock_for_key(key, profile=cached_constants)
    return _payment_script(key, cached_constants=cached_constants)


def _payment_script(key, *, cached_constants):
    compact = cached_constants == 'compact-v3'
    shape = authorization_checks(ORDINARY_CODE, COMPANION_CODE, compact=compact)
    shape += asm('OP_SIZE') + number(SIGNATURE_BYTES) + asm('OP_NUMEQUALVERIFY')
    shape += asm('OP_SWAP OP_HASH256 OP_DUP OP_TOALTSTACK')
    return (shape + verifier(key, cached_constants=cached_constants)
            + asm('OP_FROMALTSTACK') + check_binding(COMPANION_CODE, compact=compact))
