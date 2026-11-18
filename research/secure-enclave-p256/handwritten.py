"""Assemble literal BSV opcodes, data, named blocks and fixed repetition."""
from functools import cache
from pathlib import Path

from tx_engine import Script

SOURCE = Path(__file__).with_name("payment.asm")
FLAGS = {0x41: "ALL", 0xC1: "ALL_ACP", 0x42: "NONE", 0xC2: "NONE_ACP", 0x43: "SINGLE", 0xC3: "SINGLE_ACP"}


def push(data: bytes) -> bytes:
    script = Script()
    script.append_pushdata(data)
    return script.raw_serialize()


def locking_script(owner_hash160: bytes, allowed_types=(0x41,)) -> Script:
    allowed = set(allowed_types)
    if len(owner_hash160) != 20 or not allowed or not allowed.issubset(FLAGS):
        raise ValueError("expected a 20-byte owner hash and supported ForkID types")
    values = {"OWNER": push(owner_hash160)}
    for flag, name in FLAGS.items():
        values["ALLOW_" + name] = bytes([0x51 if flag in allowed else 0])
    blocks = {}
    current = None
    for lineno, line in enumerate(SOURCE.read_text(encoding="utf-8").splitlines(), 1):
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

    out = Script()
    out.append_data(expand("LOCK"))
    return out


def unlocking_script(parent: bytes, preimage: bytes, pubkey: bytes, signature: bytes) -> Script:
    if not parent or len(preimage) != 158 or len(pubkey) != 65 or pubkey[0] != 4 or len(signature) != 64:
        raise ValueError("expected parent, ForkID preimage, X9.63 public key and raw r||s")
    out = Script()
    for field in (parent, preimage, pubkey, signature):
        out.append_pushdata(field)
    return out
