"""Assemble literal BSV opcodes, data, named blocks and fixed repetition."""
from dataclasses import dataclass
from functools import cache
from pathlib import Path
import re

from tx_engine import Script

SOURCES = {1: Path(__file__).with_name("payment-v1.asm"), 2: Path(__file__).with_name("payment.asm")}
FLAGS = {0x41: "ALL", 0xC1: "ALL_ACP", 0x42: "NONE", 0xC2: "NONE_ACP", 0x43: "SINGLE", 0xC3: "SINGLE_ACP"}


def push(data: bytes) -> bytes:
    script = Script()
    script.append_pushdata(data)
    return script.raw_serialize()


@dataclass(frozen=True)
class PaymentLock:
    version: int
    owner_hash160: bytes
    allowed_types: tuple[int, ...]


@cache
def _template(version):
    """Build a canonical skeleton and record parameter locations at assembly time."""
    if version not in SOURCES:
        raise ValueError("unknown payment lock version")
    values = {}
    blocks = {}
    current = None
    for lineno, line in enumerate(SOURCES[version].read_text(encoding="utf-8").splitlines(), 1):
        tokens = line.partition("#")[0].split()
        if not tokens:
            continue
        kind, *args = tokens
        if current is not None:
            if tokens == ["end"]:
                current = None
            else:
                blocks[current].append(tokens)
        elif kind == "block" and len(args) == 1 and args[0] not in blocks:
            current = args[0]
            blocks[current] = []
        elif kind in {"number", "bytes"} and len(args) == 2 and args[0] not in values:
            name, value = args
            if kind == "bytes":
                values[name] = push(bytes.fromhex(value))
            else:
                script = Script()
                script.append_big_integer(int(value, 16))
                values[name] = script.raw_serialize()
        else:
            raise ValueError(f"invalid declaration on line {lineno}")
    if current is not None:
        raise ValueError(f"unterminated block {current}")

    @cache
    def expand(name):
        if name in values:
            return values[name]
        chunks = []
        for tokens in blocks[name]:
            if tokens[0] == "repeat":
                _, count, block = tokens
                chunks.append(expand(block) * int(count))
                continue
            for token in tokens:
                chunks.append(expand(token[1:]) if token.startswith("@") else opcode(token))
        return b"".join(chunks)

    @cache
    def opcode(token):
        return Script.parse_string(token).raw_serialize()

    # All seven template parameters occur directly in LOCK. The 20-byte hash
    # payload follows a fixed direct push. Each policy bit is exactly one opcode.
    skeleton = bytearray()
    owner_offset = None
    flag_offsets = {}
    flag_for_token = {"@ALLOW_" + name: flag for flag, name in FLAGS.items()}
    for tokens in blocks["LOCK"]:
        if tokens[0] == "repeat":
            _, count, block = tokens
            skeleton.extend(expand(block) * int(count))
            continue
        for token in tokens:
            if token == "@OWNER":
                if owner_offset is not None:
                    raise ValueError("duplicate owner slot")
                owner_offset = len(skeleton) + 1
                skeleton.extend(push(bytes(20)))
            elif token in flag_for_token:
                flag = flag_for_token[token]
                if flag in flag_offsets:
                    raise ValueError("duplicate flag slot")
                flag_offsets[flag] = len(skeleton)
                skeleton.append(0)
            else:
                skeleton.extend(expand(token[1:]) if token.startswith("@") else opcode(token))
    if owner_offset is None or flag_offsets.keys() != FLAGS.keys():
        raise ValueError("incomplete payment template")
    return bytes(skeleton), owner_offset, flag_offsets


def _locking_bytes(owner_hash160, allowed, version):
    skeleton, owner_offset, flag_offsets = _template(version)
    result = bytearray(skeleton)
    result[owner_offset:owner_offset + 20] = owner_hash160
    for flag in allowed:
        result[flag_offsets[flag]] = 0x51  # OP_1
    return bytes(result)


def locking_script(owner_hash160: bytes, allowed_types=(0x41,), *, version=2) -> Script:
    allowed = set(allowed_types)
    if len(owner_hash160) != 20 or not allowed or not allowed.issubset(FLAGS):
        raise ValueError("expected a 20-byte owner hash and supported ForkID types")
    out = Script()
    out.append_data(_locking_bytes(owner_hash160, allowed, version))
    return out


@cache
def _matcher(version):
    skeleton, owner_offset, flag_offsets = _template(version)
    slots = [(owner_offset, 20, rb"(?P<owner>.{20})")]
    for flag, offset in flag_offsets.items():
        slots.append((offset, 1, f"(?P<f{flag:02x}>[\\x00\\x51])".encode("ascii")))
    pieces = []
    start = 0
    for offset, width, capture in sorted(slots):
        pieces.extend((re.escape(skeleton[start:offset]), capture))
        start = offset + width
    return len(skeleton), re.compile(b"".join(pieces), re.DOTALL), start, skeleton[start:]


def match_locking_script(raw: bytes) -> PaymentLock | None:
    """Match a raw scriptPubKey (no CompactSize prefix) against a known version."""
    for version in (2, 1):
        size, header, end, suffix = _matcher(version)
        if len(raw) != size:
            continue
        match = header.fullmatch(raw, 0, end)
        if match is None or not raw.endswith(suffix):
            continue
        allowed = tuple(flag for flag in FLAGS if match[f"f{flag:02x}"] == bytes([0x51]))
        if allowed:
            return PaymentLock(version, match["owner"], allowed)
    return None


def replace_owner_hash160(raw: bytes, new_owner: bytes) -> bytes:
    """Construct a new script with the same template version and sighash permissions."""
    parsed = match_locking_script(raw)
    if parsed is None:
        raise ValueError("unrecognized P-256 payment lock")
    if len(new_owner) != 20:
        raise ValueError("expected a 20-byte owner hash")
    return _locking_bytes(new_owner, parsed.allowed_types, parsed.version)


def unlocking_script(parent: bytes, preimage: bytes, pubkey: bytes, signature: bytes) -> Script:
    if not parent or len(preimage) != 158 or len(pubkey) != 65 or pubkey[0] != 4 or len(signature) != 64:
        raise ValueError("expected parent, ForkID preimage, X9.63 public key and raw r||s")
    out = Script()
    for field in (parent, preimage, pubkey, signature):
        out.append_pushdata(field)
    return out
