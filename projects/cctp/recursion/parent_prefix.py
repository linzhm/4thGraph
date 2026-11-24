"""SHA-256 continuation for an output-bearing suffix of a legacy BSV transaction.

The checkpoint and processed length must be authenticated by the caller's
proof. Computing a txid from supplied values does not establish that the
checkpoint came from the hidden prefix or that an output is at the claimed
position. This module only checks local wire data and computes hashes.
"""

from dataclasses import dataclass
from hashlib import sha256
from struct import Struct

from shared.transaction import amount, compact


BLOCK_BYTES = 64
MAX_MESSAGE_BYTES = (1 << 61) - 1
MASK = (1 << 32) - 1
STATE_WORDS = Struct(">8I")
BLOCK_WORDS = Struct(">16I")
INITIAL = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
ROUND = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


def _rotate(value, bits):
    return ((value >> bits) | (value << (32 - bits))) & MASK


def _compress(state, raw, start, end):
    for offset in range(start, end, BLOCK_BYTES):
        schedule = list(BLOCK_WORDS.unpack_from(raw, offset))
        for i in range(16, 64):
            x, y = schedule[i - 15], schedule[i - 2]
            s0 = _rotate(x, 7) ^ _rotate(x, 18) ^ (x >> 3)
            s1 = _rotate(y, 17) ^ _rotate(y, 19) ^ (y >> 10)
            schedule.append((schedule[i - 16] + s0 + schedule[i - 7] + s1) & MASK)
        a, b, c, d, e, f, g, h = state
        for constant, word in zip(ROUND, schedule):
            s1 = _rotate(e, 6) ^ _rotate(e, 11) ^ _rotate(e, 25)
            choose = (e & f) ^ (~e & g)
            t1 = h + s1 + choose + constant + word
            s0 = _rotate(a, 2) ^ _rotate(a, 13) ^ _rotate(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)
            a, b, c, d, e, f, g, h = (t1 + s0 + majority) & MASK, a, b, c, (d + t1) & MASK, e, f, g
        state = tuple((old + new) & MASK for old, new in zip(state, (a, b, c, d, e, f, g, h)))
    return state


def sha256_checkpoint(prefix: bytes) -> bytes:
    """Return the eight big-endian chaining words after complete, unpadded blocks."""
    if not isinstance(prefix, bytes) or len(prefix) > MAX_MESSAGE_BYTES or len(prefix) % BLOCK_BYTES:
        raise ValueError("SHA-256 checkpoint requires complete unpadded blocks")
    return STATE_WORDS.pack(*_compress(INITIAL, prefix, 0, len(prefix)))


def sha256_continue(state: bytes, processed_bytes: int, suffix: bytes) -> bytes:
    """Continue from supplied chaining words using the total message bit length."""
    if not isinstance(state, bytes) or len(state) != STATE_WORDS.size:
        raise ValueError("expected a 32-byte SHA-256 checkpoint")
    if (type(processed_bytes) is not int or processed_bytes < 0 or processed_bytes % BLOCK_BYTES
            or not isinstance(suffix, bytes) or processed_bytes + len(suffix) > MAX_MESSAGE_BYTES):
        raise ValueError("invalid SHA-256 processed byte count or suffix")
    full_suffix = len(suffix) - len(suffix) % BLOCK_BYTES
    chaining = _compress(STATE_WORDS.unpack(state), suffix, 0, full_suffix)
    length = processed_bytes + len(suffix)
    tail = suffix[full_suffix:] + b"\x80" + bytes((55 - length) % BLOCK_BYTES) + (length * 8).to_bytes(8, "big")
    return STATE_WORDS.pack(*_compress(chaining, tail, 0, len(tail)))


def _read_compact(raw, cursor, end):
    if cursor >= end:
        raise ValueError("truncated CompactSize")
    lead = raw[cursor]
    if lead < 253:
        return lead, cursor + 1
    stop = cursor + 1 + {253: 2, 254: 4, 255: 8}[lead]
    if stop > end:
        raise ValueError("truncated CompactSize")
    value = int.from_bytes(raw[cursor + 1:stop], "little")
    if compact(value) != raw[cursor:stop]:
        raise ValueError("noncanonical CompactSize")
    return value, stop


def output_offsets(raw: bytes) -> tuple[int, tuple[int, ...]]:
    """Return the offsets of the output count and of each serialized TxOut."""
    if not isinstance(raw, bytes) or len(raw) < 10:
        raise ValueError("truncated legacy transaction")
    end = len(raw) - 4  # Locktime follows the last output.
    inputs, cursor = _read_compact(raw, 4, end)
    if not 1 <= inputs <= (end - cursor - 1) // 41:
        raise ValueError("invalid legacy input count")
    for _ in range(inputs):
        size, cursor = _read_compact(raw, cursor + 36, end)
        cursor += size + 4
        if cursor >= end:
            raise ValueError("truncated input script or sequence")
    count_offset = cursor
    outputs, cursor = _read_compact(raw, cursor, end)
    if not 1 <= outputs <= (end - cursor) // 9:
        raise ValueError("invalid legacy output count")
    positions = []
    for _ in range(outputs):
        if cursor + 8 >= end:
            raise ValueError("truncated output value")
        positions.append(cursor)
        amount(int.from_bytes(raw[cursor:cursor + 8], "little"))
        size, cursor = _read_compact(raw, cursor + 8, end)
        cursor += size
        if cursor > end:
            raise ValueError("truncated output script")
    if cursor != end:
        raise ValueError("trailing bytes after output region")
    return count_offset, tuple(positions)


@dataclass(frozen=True)
class ParentPrefix:
    output_count_offset: int
    processed_bytes: int
    state: bytes
    suffix: bytes

    def continued_txid_wire(self) -> bytes:
        """Compute the candidate little-endian txid bytes from this disclosure."""
        return sha256(sha256_continue(self.state, self.processed_bytes, self.suffix)).digest()


def parent_prefix(raw: bytes) -> ParentPrefix:
    """Generate a checkpoint at the last block boundary before the output count."""
    count_offset, _ = output_offsets(raw)
    return _prefix_at(raw, count_offset)


def _prefix_at(raw: bytes, count_offset: int) -> ParentPrefix:
    processed = count_offset - count_offset % BLOCK_BYTES
    return ParentPrefix(count_offset, processed, sha256_checkpoint(raw[:processed]), raw[processed:])


def checkpoint_record(raw: bytes) -> dict:
    """Return the checkpoint disclosure and check it against the raw txid."""
    count_offset, positions = output_offsets(raw)
    checkpoint = _prefix_at(raw, count_offset)
    txid_wire = sha256(sha256(raw).digest()).digest()
    if checkpoint.continued_txid_wire() != txid_wire:
        raise ValueError("SHA-256 continuation disagrees with the full transaction")
    outputs = raw[positions[0]:-4]
    return {
        "format": "BSV parent SHA256 checkpoint v1",
        "txid": txid_wire[::-1].hex(),
        "txid_wire": txid_wire.hex(),
        "raw_bytes": len(raw),
        "processed_bytes": checkpoint.processed_bytes,
        "midstate": checkpoint.state.hex(),
        "suffix": checkpoint.suffix.hex(),
        "suffix_bytes": len(checkpoint.suffix),
        "output_count_offset": count_offset,
        "output_count": len(positions),
        "output_offsets": list(positions),
        "suffix_sha256d": sha256(sha256(checkpoint.suffix).digest()).hexdigest(),
        "hash_outputs": sha256(sha256(outputs).digest()).hexdigest(),
    }


def main():
    import argparse
    import json
    from pathlib import Path
    import sys

    parser = argparse.ArgumentParser(description="Generate a SHA-256 checkpoint from a serialized BSV parent.")
    parser.add_argument("parent", help="hex or binary transaction file, or - for stdin")
    parser.add_argument("--input-format", choices=("hex", "raw"), default="hex")
    parser.add_argument("--out", type=Path, help="new JSON file, otherwise stdout")
    args = parser.parse_args()
    try:
        raw = sys.stdin.buffer.read() if args.parent == "-" else Path(args.parent).read_bytes()
        if args.input_format == "hex":
            raw = bytes.fromhex(raw.decode("ascii"))
        output = json.dumps(checkpoint_record(raw), indent=2) + "\n"
        if args.out is None:
            sys.stdout.write(output)
        else:
            with args.out.open("x") as stream:
                stream.write(output)
    except (ValueError, OSError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
