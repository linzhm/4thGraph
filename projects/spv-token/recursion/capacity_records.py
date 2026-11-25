"""Lossless byte records for capacity witnesses.

Each record starts with an unsigned byte count (1–16), followed by that
many segments. Tag 0 carries a uint32 CompactSize-prefixed literal. Tags
1 and 2 expand the corresponding nonempty dictionary entries. The consumer
must still authenticate the reconstructed transaction bytes by txid.
"""

from parent_preimage import _compact_size
from shared.script import asm, push
from shared.transaction import compact


MAX_SEGMENTS = 16
MAX_LITERAL_SIZE = (1 << 32) - 1


def _dictionary(dictionary):
    if len(dictionary) != 2 or any(not isinstance(entry, bytes) for entry in dictionary):
        raise ValueError("expected two byte-string dictionary entries")
    return dictionary


def _literal(raw):
    return b"\x00" + compact(len(raw)) + raw


def encode_capacity_record(raw: bytes, dictionary: tuple[bytes, bytes]) -> bytes:
    """Encode with earliest matches, preferring longer then earlier entries."""
    dictionary = _dictionary(dictionary)
    if not isinstance(raw, bytes) or len(raw) > MAX_LITERAL_SIZE:
        raise ValueError("expected up to uint32 bytes")
    cursor = 0
    segments = []
    while cursor < len(raw):
        matches = []
        for index, entry in enumerate(dictionary):
            start = raw.find(entry, cursor) if entry else -1
            if start >= 0:
                matches.append((start, -len(entry), index))
        if not matches:
            segments.append(_literal(raw[cursor:]))
            break
        start, neg_size, index = min(matches)
        if start > cursor:
            segments.append(_literal(raw[cursor:start]))
        segments.append(bytes([index + 1]))
        if len(segments) > MAX_SEGMENTS:
            break
        cursor = start - neg_size
    literal_size = 2 + len(compact(len(raw))) + len(raw)
    if 1 <= len(segments) <= MAX_SEGMENTS and 1 + sum(map(len, segments)) < literal_size:
        return bytes([len(segments)]) + b"".join(segments)
    return b"\x01" + _literal(raw)


def decode_capacity_record(record: bytes, dictionary: tuple[bytes, bytes]) -> bytes:
    """Expand one complete record and reject invalid or nonminimal lengths."""
    dictionary = _dictionary(dictionary)
    if not isinstance(record, bytes) or not record or not 1 <= record[0] <= MAX_SEGMENTS:
        raise ValueError("invalid capacity record segment count")
    cursor = 1
    segments = []
    for _ in range(record[0]):
        if cursor == len(record):
            raise ValueError("missing capacity record segment tag")
        tag = record[cursor]
        cursor += 1
        if tag in (1, 2):
            entry = dictionary[tag - 1]
            if not entry:
                raise ValueError("capacity record references an empty dictionary entry")
            segments.append(entry)
            continue
        if tag != 0:
            raise ValueError("unknown capacity record segment tag")
        if cursor == len(record):
            raise ValueError("missing capacity record literal length")
        start = cursor
        lead = record[cursor]
        cursor += 1
        if lead == 255:
            raise ValueError("capacity record literal length exceeds uint32 encoding")
        width = {253: 2, 254: 4}.get(lead, 0)
        if cursor + width > len(record):
            raise ValueError("truncated capacity record literal length")
        size = int.from_bytes(record[cursor:cursor + width], "little") if width else lead
        cursor += width
        if compact(size) != record[start:cursor]:
            raise ValueError("noncanonical capacity record literal length")
        end = cursor + size
        if end > len(record):
            raise ValueError("truncated capacity record literal")
        segments.append(record[cursor:end])
        cursor = end
    if cursor != len(record):
        raise ValueError("trailing capacity record bytes")
    return b"".join(segments)


def capacity_record_script() -> bytes:
    """Consume [record, dict0, dict1], leaving [reconstructed raw bytes]."""
    unsigned = push(b"\x00") + asm("OP_CAT OP_BIN2NUM")
    initialize = (
        asm("OP_ROT OP_1 OP_SPLIT OP_SWAP") + unsigned
        + asm(f"OP_DUP OP_1 {MAX_SEGMENTS + 1} OP_WITHIN OP_VERIFY OP_SWAP OP_0 OP_SWAP")
    )
    segment = (
        # Stack [dict0, dict1, remaining count, accumulated raw, remaining record].
        asm("OP_2 OP_PICK OP_0NOTEQUAL OP_IF OP_1 OP_SPLIT OP_SWAP") + unsigned
        + asm("OP_DUP OP_0 OP_NUMEQUAL OP_IF OP_DROP")
        + _compact_size() + asm("OP_SPLIT OP_SWAP OP_ELSE")
        + asm("OP_DUP OP_1 OP_NUMEQUAL OP_IF OP_DROP OP_4 OP_PICK"
              " OP_ELSE OP_2 OP_NUMEQUALVERIFY OP_3 OP_PICK OP_ENDIF"
              " OP_SIZE OP_0NOTEQUAL OP_VERIFY OP_ENDIF")
        # The tag is now a byte fragment above the updated record cursor.
        + asm("OP_ROT OP_SWAP OP_CAT OP_SWAP OP_2 OP_ROLL OP_1SUB OP_ROT OP_ROT OP_ENDIF")
    )
    cleanup = asm("OP_SIZE OP_0 OP_NUMEQUALVERIFY OP_DROP OP_SWAP OP_0 OP_NUMEQUALVERIFY"
                  " OP_ROT OP_DROP OP_NIP")
    return initialize + segment * MAX_SEGMENTS + cleanup
