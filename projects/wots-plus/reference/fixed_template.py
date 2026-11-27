"""Build or load fixed WOTS+ outputs and their OTDA reconstruction programs."""
from functools import cache
from hashlib import sha256
import json
from pathlib import Path

from fourthgraph.bsv.otda_reconstruction import Reconstruction
from fourthgraph.bsv.script import asm, number, push
from wots import CHAINS, KEY_BYTES, N, W

TEMPLATE_DIRECTORY = Path(__file__).resolve().parents[1] / "versions/v0.1.0"


def _read_bytes(artifact):
    data = bytes.fromhex((TEMPLATE_DIRECTORY / artifact["file"]).read_text(encoding="ascii"))
    if len(data) != artifact["bytes"] or sha256(data).hexdigest() != artifact["sha256"]:
        raise ValueError(f"WOTS+ fixed artifact differs from manifest: {artifact['file']}")
    return data


@cache
def fixed_pattern():
    layout = json.loads((TEMPLATE_DIRECTORY / "cached-steps-layout.json").read_text(encoding="ascii"))
    script = _read_bytes(layout["script"])
    program = _read_bytes(layout["reconstruction"])
    seed, commitment = layout["key_offsets"]
    if not 0 <= seed < seed + N <= commitment < commitment + N <= len(script):
        raise ValueError("invalid WOTS+ key offsets")
    if script[seed:seed + N] != bytes(N) or script[commitment:commitment + N] != bytes(N):
        raise ValueError("WOTS+ template must have zero key fields")
    parts = script[:seed], script[seed + N:commitment], script[commitment + N:]
    return Reconstruction(program, parts, (N, N))


def _encode_repeated(raw, fragment, constructor=None):
    """Leave one byte string assembled from literal gaps and a cached fragment."""
    first, *gaps = raw.split(fragment)
    load = push(fragment) if constructor is None else constructor
    program = bytearray(load + push(first))
    for gap in gaps:
        program += asm("OP_OVER OP_CAT")
        if gap:
            program += push(gap) + asm("OP_CAT")
    program += asm("OP_NIP")
    return min((push(raw), bytes(program)), key=len)


def _repeat_bytes(fragment, count, *, trim=False):
    """Emit a positive number of copies using binary doubling."""
    literal = push(fragment)
    program = literal
    for bit in bin(count)[3:]:
        program += asm("OP_DUP OP_CAT")
        if bit == "1":
            program += literal + asm("OP_CAT")
    if not trim:
        return program
    exponent = (count - 1).bit_length()
    extra = ((1 << exponent) - count) * len(fragment)
    rounded = literal + asm("OP_DUP OP_CAT") * exponent
    if extra:
        rounded += number(extra) + asm("OP_SPLIT OP_NIP")
    return min(program, rounded, key=len)


def _encode_with_run(raw, suffix, fragment, count):
    program = _encode_repeated(raw, suffix)
    before, run, after = raw.partition(fragment * count)
    if run:
        packed = (push(before) + _repeat_bytes(fragment, count, trim=True) + asm("OP_CAT")
                  + _encode_repeated(after, suffix) + asm("OP_CAT"))
        return min(program, packed, key=len)
    return program


def _compact_fragment_programs(first, chain, last, *, profile):
    from fourthgraph.bsv.pushtx import REVERSE32_ON_STACK
    from script import (
        MESSAGE_BYTE_SUFFIX, MESSAGE_WIDE_SPLIT, MESSAGE_WIDE_SPLITS, NIBBLE_SUFFIXES, _compact_builder,
    )

    builder = _compact_builder()
    trim = profile in NIBBLE_SUFFIXES
    digit_suffix = NIBBLE_SUFFIXES.get(profile, MESSAGE_BYTE_SUFFIX)
    hash_suffix = builder.emit("compact-local-hash-pair", b"") + asm("OP_ENDIF")
    reversal = (_repeat_bytes(asm("OP_1 OP_SPLIT"), N - 1, trim=trim)
                + _repeat_bytes(asm("OP_SWAP OP_CAT"), N - 1, trim=trim) + asm("OP_CAT"))
    if profile == "compact-v9":
        first_program = _encode_with_run(first, digit_suffix, MESSAGE_WIDE_SPLIT, MESSAGE_WIDE_SPLITS)
    else:
        first_program = _encode_repeated(first, digit_suffix)
    if trim:
        gate = builder.emit("compact-countdown-gate", b"")
        chain_program = _encode_with_run(chain, hash_suffix, gate, W - 2)
    else:
        chain_program = _encode_repeated(chain, hash_suffix)
    return first_program, chain_program, _encode_repeated(last, REVERSE32_ON_STACK, reversal)


@cache
def compact_pattern(profile="compact"):
    from script import (
        BUFFERED_PROFILES, NIBBLE_SUFFIXES, _compact_chain, _first_address_offset, _message_chains, _payment_script,
    )

    marker = bytes(range(KEY_BYTES))
    raw = _payment_script(marker, cached_constants=profile)
    first, tail = raw.split(marker[:N], 1)
    middle, last = tail.split(marker[N:], 1)
    chain = _compact_chain(profile)
    lead, tail = middle.split(_message_chains(chain, profile), 1)
    gap, end = tail.split(chain * (CHAINS - 2 * N), 1)

    # WOTSP-SHA2_256 uses 64 message chains and three checksum chains.
    # Keep one copy for the checksum and double the other six times.
    if profile in ("compact-v5", *BUFFERED_PROFILES):
        first_program, chain_program, last_program = _compact_fragment_programs(first, chain, last, profile=profile)
    else:
        first_program, chain_program, last_program = map(push, (first, chain, last))
    program = first_program + push(lead) + chain_program + asm("OP_DUP")
    program += asm("OP_DUP OP_CAT") * 6
    if profile in NIBBLE_SUFFIXES:
        # OP_1NEGATE pushes 0x81, the byte encoding of BIN2NUM in the lock.
        program += number(_first_address_offset(chain, profile)) + asm("OP_SPLIT OP_1NEGATE OP_SWAP OP_CAT OP_CAT")
    program += asm("OP_ROT OP_SWAP OP_CAT")
    program += push(gap) + asm("OP_CAT OP_SWAP OP_DUP OP_DUP OP_CAT OP_CAT OP_CAT")
    program += push(end) + asm("OP_CAT") + last_program
    return Reconstruction(program, (first, middle, last), (N, N))


def lock_for_key(key, *, profile="steps"):
    if not isinstance(key, bytes) or len(key) != KEY_BYTES:
        raise ValueError("WOTS+ public key must be 64 bytes")
    pattern = fixed_pattern() if profile == "steps" else compact_pattern(profile)
    first, middle, last = pattern.fixed_parts
    return first + key[:N] + middle + key[N:] + last
