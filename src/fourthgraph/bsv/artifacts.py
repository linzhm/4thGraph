"""Byte-addressed Script listing. Push payloads are opaque to opcode decoding."""

from hashlib import sha256

from .script import OPS

NAMES = {value: key for key, value in OPS.items()}
ANCHORS = {"OP_CODESEPARATOR", "OP_CHECKSIG", "OP_CHECKSIGVERIFY", "OP_CHECKMULTISIG", "OP_CHECKMULTISIGVERIFY"}


def script_listing(script):
    offset = 0
    while offset < len(script):
        start = offset
        opcode = script[offset]
        offset += 1
        if 1 <= opcode <= 78:
            length = opcode
            if opcode >= 76:
                width = 1 << (opcode - 76)
                if offset + width > len(script):
                    raise ValueError("truncated Script push length")
                length = int.from_bytes(script[offset:offset + width], "little")
                offset += width
            end = offset + length
            if end > len(script):
                raise ValueError("truncated Script push data")
            yield {"offset": start, "op": "PUSH", "bytes": end-start, "data_hex": script[offset:end].hex()}
            offset = end
        else:
            yield {"offset": start, "op": NAMES.get(opcode, f"0x{opcode:02x}"), "bytes": 1}


def describe_script(script, *, parameters=(), listing=True):
    instructions = list(script_listing(script))
    result = {"sha256": sha256(script).hexdigest(), "hex": script.hex(), "bytes": len(script),
              "parameters": list(parameters), "anchors": [row for row in instructions if row["op"] in ANCHORS]}
    if listing:
        result["instructions"] = instructions
    return result
