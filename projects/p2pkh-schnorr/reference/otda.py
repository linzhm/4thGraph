"""Rebuild the signed OTDA preimage from repeated Schnorr output script bytes."""

from functools import cache
from hashlib import sha256
import json

from schnorr_script import TEMPLATE_DIR, TEMPLATE_VERSION, _canonical, _contract
from fourthgraph.bsv.otda_reconstruction import Reconstruction
from fourthgraph.bsv.script import asm, push
from fourthgraph.bsv.transaction import CHRONICLE, SIGHASH_ALL, SIGHASH_SINGLE


def compile_constructor(template, owner_offset):
    """Emit a program that leaves the two fixed script parts around the owner slot."""
    prefix, suffix = template[:owner_offset], template[owner_offset + 20:]
    window = _contract().emit("bip340-joint-window-step", b"")
    start = suffix.find(window * 2)
    if start < 0:
        raise ValueError("Schnorr template has no consecutive window steps")
    end = start
    while suffix.startswith(window, end):
        end += len(window)
    count = (end - start) // len(window)

    # Keep the original window below an accumulator. Append each bit of the
    # repetition count by doubling the accumulator and adding the seed if set.
    program = bytearray(push(prefix) + push(suffix[:start]) + push(window) + asm("OP_DUP"))
    for bit in f"{count:b}"[1:]:
        program.extend(asm("OP_DUP OP_CAT"))
        if bit == "1":
            program.extend(asm("OP_OVER OP_CAT"))
    program.extend(asm("OP_NIP OP_CAT") + push(suffix[end:]) + asm("OP_CAT"))
    return bytes(program)


@cache
def _reconstruction():
    template, offset = _canonical(TEMPLATE_VERSION)
    layout = json.loads((TEMPLATE_DIR / "layout.json").read_text(encoding="utf-8"))
    constructor = bytes.fromhex((TEMPLATE_DIR / "otda-constructor.hex").read_text(encoding="ascii"))
    expected = layout["otda_constructor"]
    if len(constructor) != expected["bytes"] or sha256(constructor).hexdigest() != expected["sha256"]:
        raise ValueError("Schnorr OTDA constructor differs from its manifest")
    return Reconstruction(constructor, (template[:offset], template[offset + 20:]), (20,))


def compressed_preimage(tx, index, auth):
    """Return the shorter version-2 Chronicle unlock prefix when it can be reconstructed."""
    if tx.version != 2 or auth.companion or not auth.requested_type & CHRONICLE:
        return None
    mode = auth.requested_type & 31
    if mode == SIGHASH_ALL:
        outputs = tx.outputs
    elif mode == SIGHASH_SINGLE:
        outputs = (tx.outputs[index],)
    else:
        return None
    pattern = _reconstruction()
    program = pattern.build(auth.preimage, outputs)
    return program if program is not None and len(program) < len(push(auth.preimage)) else None
