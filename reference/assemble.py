"""Assemble the literal opcode blocks for one canonical P2PKH-R1 output."""
from functools import cache
from pathlib import Path

from tx_engine import Script


def assemble(owner: bytes) -> bytes:
    if len(owner) != 20:
        raise ValueError("expected a 20-byte owner hash")
    constants = {}
    blocks = {}
    for path in sorted(Path(__file__).with_name("asm").glob("*.asm")):
        current = None
        for line in path.read_text().splitlines():
            tokens = line.partition("#")[0].split()
            if not tokens:
                continue
            if current is not None:
                if tokens == ["end"]:
                    current = None
                else:
                    blocks[current].append(tokens)
                continue
            kind, name, *args = tokens
            if name in blocks or name in constants:
                raise ValueError(f"duplicate definition: {name}")
            if kind == "block":
                current = name
                blocks[name] = []
            else:
                script = Script()
                if kind == "bytes":
                    script.append_pushdata(bytes.fromhex(args[0]))
                elif kind == "number":
                    script.append_big_integer(int(args[0], 16))
                else:
                    raise ValueError(f"unknown declaration: {kind}")
                constants[name] = script.raw_serialize()
        if current is not None:
            raise ValueError(f"unterminated block: {current}")
    data = Script()
    data.append_pushdata(owner)
    constants["OWNER"] = data.raw_serialize()

    @cache
    def emit(token):
        if not token.startswith("@"):
            return Script.parse_string(token).raw_serialize()
        name = token[1:]
        if name in constants:
            return constants[name]
        parts = []
        for line in blocks[name]:
            if line[0] == "repeat":
                parts.append(emit("@" + line[2]) * int(line[1]))
            else:
                parts.extend(emit(t) for t in line)
        return b"".join(parts)

    return emit("@LOCK")
