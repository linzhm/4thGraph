"""Assemble literal BSV opcodes, data, named blocks and fixed repetition."""
from dataclasses import dataclass
from functools import cache
from pathlib import Path
import re

from tx_engine import Script

SOURCES = {
    1: ("payment-v1.asm",),
    2: ("payment.asm", "tagged-lock.asm", "window-1.asm"),
    3: ("payment.asm", "tagged-lock.asm", "window-2.asm"),
    4: ("payment.asm", "tagged-lock.asm", "window-4.asm"),
    5: ("payment.asm", "native-lock.asm", "bip143.asm", "window-4.asm"),
    6: ("payment.asm", "native-lock.asm", "otda.asm", "window-4.asm"),
    7: ("payment.asm", "universal.asm", "window-4.asm"),
}
FLAGS = {0x41: "ALL", 0xC1: "ALL_ACP", 0x42: "NONE", 0xC2: "NONE_ACP", 0x43: "SINGLE", 0xC3: "SINGLE_ACP"}


OTDA_FLAGS = {flag | 0x20: name for flag, name in FLAGS.items()}
UNIVERSAL_FLAGS = {**FLAGS, **{flag: "OTDA_" + name for flag, name in OTDA_FLAGS.items()}}
GROUP_ORDER_R1 = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551


def flags_for(version):
    if version == 7:
        return UNIVERSAL_FLAGS
    return OTDA_FLAGS if version == 6 else FLAGS


def push(data: bytes) -> bytes:
    script = Script()
    script.append_pushdata(data)
    return script.raw_serialize()


@dataclass(frozen=True)
class PaymentLock:
    template_name = "P2PKH-R1"
    version: int
    owner_hash160: bytes
    allowed_types: tuple[int, ...]


@cache
def _assembly(version):
    """Read the literal blocks and assemble only the blocks referenced by this profile."""
    if version not in SOURCES:
        raise ValueError("unknown payment lock version")
    values = {}
    blocks = {}
    current = None
    source = "\n".join(Path(__file__).with_name(name).read_text(encoding="utf-8") for name in SOURCES[version])
    for lineno, line in enumerate(source.splitlines(), 1):
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

    def emit(token):
        return expand(token[1:]) if token.startswith("@") else opcode(token)

    return blocks, emit


@cache
def _template(version):
    blocks, emit = _assembly(version)
    # Template parameters occur directly in LOCK. The 20-byte hash
    # payload follows a fixed direct push. Each policy bit is exactly one opcode.
    skeleton = bytearray()
    owner_offset = None
    flag_offsets = {}
    flag_for_token = {"@ALLOW_" + name: flag for flag, name in flags_for(version).items()}
    for tokens in blocks["LOCK"]:
        if tokens[0] == "repeat":
            _, count, block = tokens
            skeleton.extend(emit("@" + block) * int(count))
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
                skeleton.extend(emit(token))
    if owner_offset is None or flag_offsets.keys() != flags_for(version).keys():
        raise ValueError("incomplete payment template")
    return bytes(skeleton), owner_offset, flag_offsets


def _locking_bytes(owner_hash160, allowed, version):
    skeleton, owner_offset, flag_offsets = _template(version)
    result = bytearray(skeleton)
    result[owner_offset:owner_offset + 20] = owner_hash160
    for flag in allowed:
        result[flag_offsets[flag]] = 0x51  # OP_1
    return bytes(result)


def locking_script(owner_hash160: bytes, allowed_types=None, *, version=2) -> Script:
    default = {0x41, 0x61} if version == 7 else {0x61 if version == 6 else 0x41}
    allowed = default if allowed_types is None else set(allowed_types)
    if len(owner_hash160) != 20 or not allowed or not allowed.issubset(flags_for(version)):
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
    for version in (7, 2, 3, 4, 5, 6, 1):
        size, header, end, suffix = _matcher(version)
        if len(raw) != size:
            continue
        match = header.fullmatch(raw, 0, end)
        if match is None or not raw.endswith(suffix):
            continue
        allowed = tuple(flag for flag in flags_for(version) if match[f"f{flag:02x}"] == bytes([0x51]))
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


def native_unlocking_script(parent: bytes, preimage: bytes, pubkey: bytes, signature: bytes,
                            *, version: int, input_index: int) -> Script:
    """Use v5 for BIP143, v6 for OTDA. The wallet signs SHA256d(preimage) as a digest."""
    if (version not in (5, 6) or not parent or len(signature) != 64
            or len(pubkey) != 65 or pubkey[0] != 4 or not 0 <= input_index <= 0xffffffff):
        raise ValueError("invalid native payment witness")
    flag = int.from_bytes(preimage[-4:], "little")
    if flag not in flags_for(version) or (version == 5 and len(preimage) != 158):
        raise ValueError("preimage does not match the selected template")
    s = int.from_bytes(signature[32:], "big")
    if not 1 <= s < GROUP_ORDER_R1:
        raise ValueError("invalid P-256 signature scalar")
    fields = [parent, preimage, pubkey, signature]
    if version == 6:
        ordinal = 0 if flag & 0x80 else input_index
        fields.append(ordinal.to_bytes(4, "little"))
    fields.append(pow(s, -1, GROUP_ORDER_R1).to_bytes(32, "little"))
    script = Script()
    for field in fields:
        script.append_pushdata(field)
    return script
