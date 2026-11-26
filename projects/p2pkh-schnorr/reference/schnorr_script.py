"""Compile a BIP340 verifier and a HASH160-owned payment lock."""

from functools import cache
from hashlib import new, sha256
import json
from pathlib import Path

from bip340 import CHALLENGE_TAG, FIELD, GENERATOR, ORDER
from shared.pushtx import REVERSE32, authorization_checks, check_binding
from shared.script import asm, number, push

# Different scriptCode suffixes separate payments from the other Script Lab schemes.
_TAG = asm("OP_NOP OP_NOP OP_NOP OP_NOP OP_NOP")
ORDINARY_CODE = _TAG + asm("OP_ENDIF OP_CHECKSIG")
COMPANION_CODE = _TAG + asm("OP_IF OP_CHECKSIGVERIFY OP_ELSE OP_CODESEPARATOR") + ORDINARY_CODE

# The modulus is the bottom item inside the verifier. Signed residues are
# sufficient during point arithmetic. The endpoint checks use congruences.
_FIELD_MOD = asm("OP_DEPTH OP_1SUB OP_PICK OP_MOD")
_BE32 = REVERSE32 + push(b"\0") + asm("OP_CAT OP_BIN2NUM")
_PACKED_BYTES = 32 + 32 + 64 + 32
TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "template"
TEMPLATE_VERSION = "v0.1.0"


class _Program:
    """Build a short straight-line block while tracking its local stack slots."""

    def __init__(self, slots):
        self.slots = list(slots.split())
        self.code = bytearray()

    def copy(self, operand):
        if isinstance(operand, int):
            self.code.extend(number(operand))
        else:
            depth = len(self.slots) - self.slots.index(operand) - 1
            self.code.extend(number(depth) + asm("OP_PICK"))
        self.slots.append(None)

    def emit(self, code, count, *results):
        self.code.extend(code)
        if count:
            del self.slots[-count:]
        self.slots.extend(results)

    def op(self, result, opcode, *operands):
        for operand in operands:
            self.copy(operand)
        self.emit(asm(opcode), len(operands), result)
        return result

    def keep(self, *names):
        for name in reversed(names):
            self.copy(name)
            self.emit(asm("OP_TOALTSTACK"), 1)
        self.code.extend(asm("OP_2DROP") * (len(self.slots) // 2))
        if len(self.slots) % 2:
            self.code.extend(asm("OP_DROP"))
        self.code.extend(asm("OP_FROMALTSTACK") * len(names))
        self.slots = list(names)

    def field_value(self, name, value):
        self.copy(value)
        self.emit(_FIELD_MOD, 1, name)


@cache
def _point_sum():
    """Complete homogeneous secp256k1 addition, including infinity and doubling."""
    p = _Program("x1 y1 z1 x2 y2 z2")
    op = p.op
    for result, first, second in (("xx", "x1", "x2"), ("yy", "y1", "y2"), ("zz", "z1", "z2")):
        op(result, "OP_MUL", first, second)
    for first, second in (("x", "y"), ("x", "z"), ("y", "z")):
        pair = first + second
        left = op(pair + "_left", "OP_ADD", first + "1", second + "1")
        right = op(pair + "_right", "OP_ADD", first + "2", second + "2")
        cross = op(pair + "_cross", "OP_MUL", left, right)
        diagonal = op(pair + "_diagonal", "OP_ADD", first * 2, second * 2)
        op(pair, "OP_SUB", cross, diagonal)
    # Complete addition on a = 0, b = 7, so 3b = 21.
    op("h", "OP_MUL", 21, "zz")
    op("minus", "OP_SUB", "yy", "h")
    op("plus", "OP_ADD", "yy", "h")
    op("t", "OP_MUL", 3, "xx")
    op("k", "OP_MUL", 21, "xz")
    p.field_value("X", op("raw_x", "OP_SUB", op("x_left", "OP_MUL", "xy", "minus"),
                         op("x_right", "OP_MUL", "yz", "k")))
    p.field_value("Y", op("raw_y", "OP_ADD", op("y_left", "OP_MUL", "minus", "plus"),
                         op("y_right", "OP_MUL", "t", "k")))
    p.field_value("Z", op("raw_z", "OP_ADD", op("z_left", "OP_MUL", "yz", "plus"),
                         op("z_right", "OP_MUL", "xy", "t")))
    p.keep("X", "Y", "Z")
    return bytes(p.code)


def _prepare():
    """Validate encodings and compute the challenge before point arithmetic."""
    p = _Program("message px_bytes py_bytes signature ry_bytes")
    for name, size in (("px_bytes", 32), ("py_bytes", 32), ("signature", 64), ("ry_bytes", 32)):
        p.copy(name)
        p.emit(asm("OP_SIZE") + number(size) + asm("OP_NUMEQUALVERIFY OP_DROP"), 1)
    p.copy("signature")
    p.emit(asm("32 OP_SPLIT"), 1, "r_bytes", "s_bytes")

    for name, bound in (("px", FIELD), ("py", FIELD), ("r", FIELD), ("ry", FIELD), ("s", ORDER)):
        p.copy(name + "_bytes")
        p.emit(_BE32, 1, name)
        p.op("in_range", "OP_LESSTHAN", name, bound)
        p.emit(asm("OP_VERIFY"), 1)
    for name in ("py", "ry"):
        p.op("parity", "OP_MOD", name, 2)
        p.emit(asm("OP_0 OP_NUMEQUALVERIFY"), 1)

    p.op("y2", "OP_MUL", "py", "py")
    p.op("x2", "OP_MUL", "px", "px")
    p.op("x3", "OP_MUL", "x2", "px")
    p.op("rhs", "OP_ADD", "x3", 7)
    p.op("curve_delta", "OP_SUB", "y2", "rhs")
    p.op("curve_residue", "OP_MOD", "curve_delta", FIELD)
    p.emit(asm("OP_0 OP_NUMEQUALVERIFY"), 1)

    p.emit(push(CHALLENGE_TAG), 0, "tag")
    p.op("tag_r", "OP_CAT", "tag", "r_bytes")
    p.op("tag_rx", "OP_CAT", "tag_r", "px_bytes")
    p.op("transcript", "OP_CAT", "tag_rx", "message")
    p.emit(asm("OP_SHA256") + _BE32, 1, "challenge")
    p.op("e", "OP_MOD", "challenge", ORDER)
    p.op("k", "OP_SUB", ORDER, "e")
    p.copy(FIELD)
    p.slots[-1] = "field"
    p.keep("field", "r", "ry", "px", "py", "s", "k")
    return bytes(p.code)


def _joint_multiply():
    """Evaluate sG + kP with a two-bit selector for each scalar bit position."""
    p = _Program("field r ry px py s k")
    p.emit(asm("OP_1") + number(GENERATOR[0]) + number(GENERATOR[1]) + asm("OP_1"),
           0, "pz", "gx", "gy", "gz")
    for name in ("px", "py", "pz", "gx", "gy", "gz"):
        p.copy(name)
    p.emit(_point_sum(), 6, "hx", "hy", "hz")
    p.copy(1 << 255)
    p.slots[-1] = "mask"
    p.emit(asm("OP_0 OP_1 OP_0"), 0, "X", "Y", "Z")
    p.keep("field", "r", "ry", "px", "py", "pz", "gx", "gy", "gz", "hx", "hy", "hz",
           "s", "k", "mask", "X", "Y", "Z")

    # From the top, s, k and mask sit at depths 5, 4 and 3. The selected
    # point is P, G or G+P with x at depth 17 - 3*selector.
    step = asm("OP_3DUP") + _point_sum()
    step += asm("5 OP_PICK 4 OP_PICK OP_DIV 2 OP_MOD 2 OP_MUL "
                "5 OP_PICK 5 OP_PICK OP_DIV 2 OP_MOD OP_ADD OP_DUP OP_IF "
                "3 OP_MUL 17 OP_SWAP OP_SUB OP_DUP OP_TOALTSTACK OP_PICK "
                "OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_PICK OP_FROMALTSTACK OP_PICK")
    step += _point_sum() + asm("OP_ELSE OP_DROP OP_ENDIF "
                               "3 OP_ROLL 2 OP_DIV 3 OP_ROLL 3 OP_ROLL 3 OP_ROLL")
    p.code.extend(step * 256)

    # Reject infinity, then compare to the proposed finite, even-y R without
    # inversion. Projective coordinates here represent (X/Z, Y/Z).
    p.copy("Z")
    p.emit(asm("OP_0NOTEQUAL OP_VERIFY"), 1)
    for axis, coordinate in (("X", "r"), ("Y", "ry")):
        rhs = p.op("target_" + axis, "OP_MUL", coordinate, "Z")
        delta = p.op("delta_" + axis, "OP_SUB", axis, rhs)
        p.field_value("result_" + axis, delta)
        p.emit(asm("OP_0 OP_NUMEQUALVERIFY"), 1)
    p.emit(asm("OP_1"), 0, "valid")
    p.keep("valid")
    return bytes(p.code)


@cache
def verifier():
    """Consume message, public x, public y, BIP340 signature, and nonce y."""
    return asm("OP_DEPTH 5 OP_NUMEQUALVERIFY") + _prepare() + _joint_multiply()


def owner_hash(public_key):
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ValueError("expected a 32-byte BIP340 public key")
    return new("ripemd160", sha256(public_key).digest()).digest()


@cache
def _lock_parts():
    before = authorization_checks(ORDINARY_CODE, COMPANION_CODE)
    before += asm("OP_SWAP OP_HASH256 OP_DUP OP_TOALTSTACK OP_SWAP OP_SIZE")
    before += number(_PACKED_BYTES) + asm("OP_NUMEQUALVERIFY 32 OP_SPLIT 32 OP_SPLIT 64 OP_SPLIT "
                                          "3 OP_PICK OP_HASH160")
    after = asm("OP_EQUALVERIFY") + verifier() + asm("OP_VERIFY OP_FROMALTSTACK") + check_binding(COMPANION_CODE)
    return before, after


def compiled_template():
    """Return the base template and byte offset of its 20-byte owner slot."""
    before, after = _lock_parts()
    return before + push(bytes(20)) + after, len(before) + 1


@cache
def _canonical():
    raw = bytes.fromhex((TEMPLATE_DIR / "template.hex").read_text(encoding="ascii"))
    layout = json.loads((TEMPLATE_DIR / "layout.json").read_text(encoding="utf-8"))
    start = layout["owner_hash160"]["offset"]
    if (layout["version"] != TEMPLATE_VERSION or layout["owner_hash160"]["length"] != 20
            or len(raw) != layout["script_bytes"] or sha256(raw).hexdigest() != layout["base_script_sha256"]
            or not 0 < start <= len(raw) - 20 or raw[start - 1:start + 20] != b"\x14" + bytes(20)):
        raise ValueError("Schnorr locking template differs from its manifest")
    return raw, start


def lock_for_owner(owner):
    if not isinstance(owner, bytes) or len(owner) != 20:
        raise ValueError("expected a 20-byte owner hash")
    raw, start = _canonical()
    return raw[:start] + owner + raw[start + 20:]


def recognize(script):
    """Return the committed owner only after comparing all fixed bytes."""
    raw, start = _canonical()
    if (isinstance(script, bytes) and len(script) == len(raw)
            and script[:start] == raw[:start] and script[start + 20:] == raw[start + 20:]):
        return script[start:start + 20]
    return None
