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

COMPACT_PROFILES = (
    'compact', 'compact-v2', 'compact-v3', 'compact-v4', 'compact-v5', 'compact-v6', 'compact-v7', 'compact-v8',
    'compact-v9', 'compact-v10', 'compact-v11',
)
LAZY_MESSAGE_PROFILES = ('compact-v10', 'compact-v11')
MAIN_BUFFER_PROFILES = ('compact-v8', 'compact-v9', *LAZY_MESSAGE_PROFILES)
BUFFERED_PROFILES = ('compact-v6', 'compact-v7', *MAIN_BUFFER_PROFILES)
CACHE_PROFILES = (False, True, 'steps', *COMPACT_PROFILES)
MESSAGE_BYTE_SUFFIX = asm('OP_SPLIT 0x00 OP_CAT OP_BIN2NUM OP_DUP OP_16 OP_MOD OP_DUP OP_TOALTSTACK'
                          ' OP_SWAP OP_16 OP_DIV OP_DUP OP_TOALTSTACK OP_ADD OP_ROT OP_ADD')
MESSAGE_NIBBLE_SUFFIX = asm('OP_SPLIT OP_DUP OP_15 OP_AND OP_BIN2NUM OP_DUP OP_TOALTSTACK'
                            ' OP_SWAP OP_4 OP_RSHIFT OP_BIN2NUM OP_DUP OP_TOALTSTACK OP_ADD OP_ROT OP_ADD')
MESSAGE_PAIRED_NIBBLE_SUFFIX = asm('OP_SPLIT OP_DUP OP_4 OP_RSHIFT OP_BIN2NUM'
                                  ' OP_SWAP OP_15 OP_AND OP_BIN2NUM OP_2DUP OP_TOALTSTACK OP_TOALTSTACK'
                                  ' OP_ADD OP_ROT OP_ADD')
# Zero stays a one-byte false flag, which the countdown consumes before any arithmetic.
MESSAGE_NIBBLE_SPLIT = asm('OP_DUP OP_15 OP_AND OP_TOALTSTACK OP_4 OP_RSHIFT')
MESSAGE_RAW_NIBBLES = MESSAGE_NIBBLE_SPLIT + asm('OP_TOALTSTACK')
# Leave the remaining digest and the low nibble on altstack, with the high nibble on main.
MESSAGE_PAIR_DECODE = asm('OP_1 OP_SPLIT OP_TOALTSTACK') + MESSAGE_NIBBLE_SPLIT
# For indexes over 16, a length-based split costs the same as a literal and repeats exactly.
MESSAGE_WIDE_SPLIT = asm('OP_SIZE OP_1SUB OP_SPLIT') + MESSAGE_RAW_NIBBLES
MESSAGE_WIDE_SPLITS = N - 17
NIBBLE_SUFFIXES = {
    'compact-v7': MESSAGE_NIBBLE_SUFFIX,
    'compact-v8': MESSAGE_PAIRED_NIBBLE_SUFFIX,
    'compact-v9': MESSAGE_RAW_NIBBLES,
}
FIRST_ADDRESS_NORMALIZED_PROFILES = (*NIBBLE_SUFFIXES, *LAZY_MESSAGE_PROFILES)
# Twelve table entries above the delta keep its update at an OP_16 pick.
DELTA_TABLE_OFFSET = 3
STEP_SUFFIX_BYTES = 8
STEP_TABLE_SPLIT = number(STEP_SUFFIX_BYTES) + asm('OP_SPLIT')


def _message_digits(*, step_counts=False, byte_suffix=MESSAGE_BYTE_SUFFIX):
    # Entry: signature, digest. Leave the checksum on stack and the message
    # nibbles on altstack, with the first (high nibble of byte zero) on top.
    # Complementing the digest makes each stored nibble the remaining step
    # count and makes their sum the checksum itself.
    code = bytearray(asm('OP_INVERT OP_0' if step_counts else 'OP_0'))
    for byte_index in reversed(range(N)):
        code += asm('OP_SWAP') + number(byte_index) + byte_suffix
    code += asm('OP_NIP')
    if not step_counts:
        code += number(2 * N * (W - 1)) + asm('OP_SWAP OP_SUB')
    return bytes(code)


def _packed_digest_checksum(*, fold_by_division=False):
    # Sum complemented nibbles without carries into neighboring bytes.
    # Preserve the digest below the working copy for the countdown flags.
    double = asm('OP_DUP OP_CAT')
    nibble_mask = asm('OP_15') + double * 5
    even_mask = push(b'\xff\x00') + double * 4
    code = asm('OP_INVERT OP_DUP') + nibble_mask
    code += asm('OP_2DUP OP_AND OP_BIN2NUM OP_ROT OP_4 OP_RSHIFT OP_ROT OP_AND OP_BIN2NUM OP_ADD')
    # Pair adjacent byte sums into 16-bit lanes. The total is at most 960,
    # and each power of 2**16 is congruent to one modulo 0xffff.
    if fold_by_division:
        # Dividing the little-endian number by 256 shifts each odd byte into
        # its adjacent even byte. No byte sum can carry into its neighbor.
        code += asm('OP_DUP 256 OP_DIV OP_ADD') + number(N) + asm('OP_NUM2BIN') + even_mask
        code += asm('OP_AND OP_BIN2NUM')
    else:
        code += number(N) + asm('OP_NUM2BIN') + even_mask
        code += asm('OP_2DUP OP_AND OP_BIN2NUM OP_ROT OP_8 OP_LSHIFT OP_ROT OP_AND OP_BIN2NUM OP_ADD')
    return code + number(0xffff) + asm('OP_MOD OP_SWAP')


def _packed_message_digits():
    code = _packed_digest_checksum()
    code += MESSAGE_WIDE_SPLIT * MESSAGE_WIDE_SPLITS
    for index in reversed(range(1, N - MESSAGE_WIDE_SPLITS)):
        code += number(index) + asm('OP_SPLIT') + MESSAGE_RAW_NIBBLES
    return code + MESSAGE_RAW_NIBBLES


def _buffered_message_digits(profile):
    if profile in LAZY_MESSAGE_PROFILES:
        return _packed_digest_checksum(fold_by_division=True) + asm('OP_TOALTSTACK')
    if profile == 'compact-v9':
        return _packed_message_digits()
    return _message_digits(step_counts=True, byte_suffix=NIBBLE_SUFFIXES.get(profile, MESSAGE_BYTE_SUFFIX))


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
def _compact_builder():
    from fourthgraph.compiler.script_builder import ScriptBuilder

    return ScriptBuilder.from_file(Path(__file__).with_name('compact.fth'))


@cache
def _compact_chain(profile='compact'):
    if profile in ('compact-v9', 'compact-v10'):
        return _compact_chain('compact-v8')

    builder = _compact_builder()
    # Open gates from step 14 to 0. The hashes run in order as the gates close.
    frame = 'compact-v8' if profile == 'compact-v11' else profile
    start = 'compact-v6-chain-start' if frame == 'compact-v7' else f'{frame}-chain-start'
    code = builder.emit(start, b'')
    hash_step = f'{frame}-hash-step'
    if profile != 'compact':
        # The counter starts at 15 minus the signed digit. The first false
        # gate consumes zero, and the innermost gate consumes the final flag.
        code += builder.emit('compact-countdown-gate', b'') * (W - 2) + asm('OP_IF')
        table_depth = 9
        local_hash_depths = {'compact-v4': 12, 'compact-v5': 10, 'compact-v6': 7, 'compact-v7': 7, 'compact-v8': 6}
        if frame in local_hash_depths:
            hash_step = 'compact-local-hash-step'
            table_depth = local_hash_depths[frame]
    else:
        for limit in reversed(range(2, W)):
            code = builder.emit('compact-if-digit-below', code, limit)
        code += asm('OP_OVER OP_NOTIF')
        table_depth = 11
    for step in range(W - 1):
        # The packed table pushes the highest step first, reversing the stack order.
        position = W - 2 - step if profile == 'compact-v11' else step
        depth = table_depth + W - 2 - position
        if frame == 'compact-v8' and position < DELTA_TABLE_OFFSET:
            depth += 1
        code = builder.emit(hash_step, code, depth)
        code += asm('OP_ENDIF')
    return builder.emit(f'{frame}-chain-end', code)


def _first_address_offset(chain, profile):
    suffix = 'compact-v8-chain-tail' if profile in MAIN_BUFFER_PROFILES else 'compact-address-increment'
    offset = len(chain) - len(_compact_builder().emit(suffix, b''))
    if profile in LAZY_MESSAGE_PROFILES:
        offset += len(MESSAGE_PAIR_DECODE)
    return offset


def _message_pair_decode_offset():
    return len(_compact_builder().emit('compact-buffer-read', b''))


def _message_chains(chain, profile):
    unit = chain
    count = 2 * N
    if profile in LAZY_MESSAGE_PROFILES:
        offset = _message_pair_decode_offset()
        unit = chain[:offset] + MESSAGE_PAIR_DECODE + chain[offset:] + chain
        count = N
    if profile in FIRST_ADDRESS_NORMALIZED_PROFILES:
        offset = _first_address_offset(chain, profile)
        first = unit[:offset] + asm('OP_BIN2NUM') + unit[offset:]
        return first + unit * (count - 1)
    return unit * count


def _checksum_digits(depth, *, step_counts=False):
    # Three checksum nibbles, most significant first when popped from altstack.
    code = number(depth) + asm('OP_PICK')
    if step_counts:
        # Subtract from 0xfff to complement each of the three checksum digits.
        code += number(W ** (CHAINS - 2 * N) - 1) + asm('OP_SWAP OP_SUB')
    return code + asm('OP_DUP OP_16 OP_MOD OP_TOALTSTACK OP_16 OP_DIV'
                      ' OP_DUP OP_16 OP_MOD OP_TOALTSTACK OP_16 OP_DIV OP_TOALTSTACK')


def _step_suffixes(*, synthesize, address_delta=b''):
    if not synthesize:
        return b''.join(push(step.to_bytes(4, 'big') + bytes(4)) for step in range(W - 1))
    # Build each suffix as zero[3] || step || zero[4].
    code = bytearray(asm('OP_0 OP_3 OP_NUM2BIN'))
    for step in range(W - 1):
        if step == DELTA_TABLE_OFFSET and address_delta:
            code += address_delta + asm('OP_SWAP')
        code += asm('OP_DUP') + number(step) + asm('OP_5 OP_NUM2BIN OP_CAT OP_SWAP')
    return bytes(code) + asm('OP_DROP')


def _zero_bytes(size):
    return asm('OP_0') + number(size) + asm('OP_NUM2BIN')


def _padded_one(zero_bytes):
    return _zero_bytes(zero_bytes) + asm('OP_1 OP_CAT')


def _packed_step_suffixes(address_delta):
    # For q = 2**64, floor(2**24 * q**15 / (q - 1)**2) packs 14 down to 1
    # at byte three of successive little-endian lanes. The fractional tail
    # is smaller than one, and NUM2BIN appends the zero lane for step zero.
    size = (W - 1) * STEP_SUFFIX_BYTES
    code = _padded_one(size + 3) + _padded_one(STEP_SUFFIX_BYTES)
    code += asm('OP_1SUB OP_DUP OP_MUL OP_DIV') + number(size) + asm('OP_NUM2BIN')
    code += STEP_TABLE_SPLIT * DELTA_TABLE_OFFSET + address_delta + asm('OP_SWAP')
    return code + STEP_TABLE_SPLIT * (W - 2 - DELTA_TABLE_OFFSET)


def _compact_constants(public_seed, *, synthesize, carry_prefixes=False):
    # The chain appends its one-byte index to the first 23 address bytes.
    prf_base = push((3).to_bytes(N, 'big') + public_seed + bytes(23))
    suffixes = _step_suffixes(synthesize=synthesize)
    if synthesize:
        selector_bit = _padded_one(3 * N - 1)
        zero_prefix = _zero_bytes(N)
    else:
        selector_bit = push(bytes(3 * N - 1) + b'\x01')
        zero_prefix = push(bytes(N))
    if carry_prefixes:
        return suffixes + prf_base + zero_prefix + selector_bit
    return suffixes + selector_bit + zero_prefix + prf_base


def _buffered_verifier(public_seed, commitment, *, profile):
    # The buffer starts as the signature and ends as the endpoints in chain order.
    main_buffer = profile in MAIN_BUFFER_PROFILES
    compact = profile in FIRST_ADDRESS_NORMALIZED_PROFILES
    prefix = _buffered_message_digits(profile)
    if not main_buffer:
        prefix += asm('OP_SWAP OP_TOALTSTACK')
    prf_base = (3).to_bytes(N, 'big') + public_seed + bytes(24)
    # As a little-endian Script number, the increment has a one at the chain
    # index position. That byte remains below 128 through the last increment.
    delta = _padded_one(len(prf_base) - 1)
    if profile == 'compact-v11':
        prefix += _packed_step_suffixes(delta)
    else:
        prefix += _step_suffixes(synthesize=True, address_delta=delta if main_buffer else b'')
        if not main_buffer:
            prefix += delta
    prefix += _zero_bytes(N)
    if compact:
        prefix += (_zero_bytes(N - 1) + asm('OP_3 OP_CAT') + push(public_seed)
                   + asm('OP_CAT') + _zero_bytes(24) + asm('OP_CAT'))
    else:
        prefix += push(prf_base)
    prefix += _padded_one(3 * N - 1)
    chain = _compact_chain(profile)
    if main_buffer:
        prefix += number(W + 4) + asm('OP_ROLL')
    checksum = _checksum_digits(W + 4, step_counts=True)
    if profile in LAZY_MESSAGE_PROFILES:
        # The paired chains have consumed the digest. Drop its empty tail.
        checksum = asm('OP_FROMALTSTACK OP_DROP') + checksum
    elif not main_buffer:
        checksum = asm('OP_FROMALTSTACK') + checksum + asm('OP_TOALTSTACK')
    finish = asm('OP_SIZE' if main_buffer else 'OP_FROMALTSTACK OP_SIZE') + number(SIGNATURE_BYTES)
    finish += asm('OP_NUMEQUALVERIFY OP_SHA256') + push(commitment) + asm('OP_EQUALVERIFY')
    return (prefix + _message_chains(chain, profile) + checksum + chain * (CHAINS - 2 * N)
            + finish + asm('OP_2DROP') * ((W + 4) // 2))


def _compact_verifier(public_seed, commitment, *, profile):
    if profile in BUFFERED_PROFILES:
        return _buffered_verifier(public_seed, commitment, profile=profile)
    synthesize = profile in ('compact-v3', 'compact-v4', 'compact-v5')
    carry_prefixes = profile == 'compact-v5'
    constants = _compact_constants(public_seed, synthesize=synthesize, carry_prefixes=carry_prefixes)
    roll = number(W + 3) + asm('OP_ROLL')
    finish = asm('OP_DROP')
    if carry_prefixes:
        # The frame ends with the signature, the one-byte index and endpoints.
        prefix = _message_digits(step_counts=True) + constants + roll + push(b'\0') + asm('OP_0')
        checksum_depth = W + 5
        finish = asm('OP_SWAP OP_DROP OP_SWAP')
    elif profile != 'compact':
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
            + _checksum_digits(checksum_depth, step_counts=carry_prefixes) + chain * (CHAINS - 2 * N)
            + finish + asm('OP_0 OP_EQUALVERIFY OP_SHA256') + push(commitment)
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
    compact = cached_constants in ('compact-v3', 'compact-v4', 'compact-v5', *BUFFERED_PROFILES)
    shape = authorization_checks(
        ORDINARY_CODE, COMPANION_CODE, compact=compact,
        compact_shape=cached_constants in FIRST_ADDRESS_NORMALIZED_PROFILES,
    )
    shape += asm('OP_SIZE') + number(SIGNATURE_BYTES) + asm('OP_NUMEQUALVERIFY')
    shape += asm('OP_SWAP OP_HASH256 OP_DUP OP_TOALTSTACK')
    binding = check_binding(
        COMPANION_CODE, compact=compact,
        reuse_r=cached_constants in ('compact-v4', 'compact-v5', *BUFFERED_PROFILES),
        compact_companion=cached_constants in BUFFERED_PROFILES,
    )
    return (shape + verifier(key, cached_constants=cached_constants)
            + asm('OP_FROMALTSTACK') + binding)
