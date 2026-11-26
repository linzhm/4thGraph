"""Forth 2012 word-set catalog and the typed BSV word library."""

from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
import re

from shared.script import asm, number, push

CELL_BITS = 64
CELL_MODULUS = 1 << CELL_BITS
CELL_SIGN = CELL_MODULUS // 2
U32 = 1 << 32
TYPES = {"cell", "u32", "route", "bytes", "script", "transaction", "outpoint", "utxo", "request"}


def push_value(value):
    if len(value) == 1 and 1 <= value[0] <= 16:
        return number(value[0])
    if value == b"\x81":
        return number(-1)
    return push(value)


@dataclass(frozen=True)
class Literal:
    kind: str
    value: int | bytes

    def lower(self):
        if isinstance(self.value, bytes):
            return push_value(self.value)
        return number(self.value)


@dataclass(frozen=True)
class Primitive:
    takes: tuple[str, ...]
    gives: tuple[str, ...]
    code: bytes | None
    run: Callable[..., tuple]
    evidence: str
    comparison: bool = False

    @property
    def location(self):
        return "host" if self.code is None else "script"


def script_word(takes, gives, code, run):
    return Primitive(tuple(takes.split()), (gives,), code, lambda *values: (run(*values),), "script execution")


def wrap_cell(value):
    return (value + CELL_SIGN) % CELL_MODULUS - CELL_SIGN


def add_modulus_if_negative(modulus):
    return (asm("OP_DUP OP_0 OP_LESSTHAN OP_IF") + number(modulus)
            + asm("OP_ADD OP_ENDIF"))


def residue(modulus):
    return number(modulus) + asm("OP_MOD") + add_modulus_if_negative(modulus)


WRAP_U32 = number(U32) + asm("OP_MOD")  # The u32+ operands are statically nonnegative.
WRAP_CELL = number(CELL_SIGN) + asm("OP_ADD") + residue(CELL_MODULUS) + number(CELL_SIGN) + asm("OP_SUB")


def cell_arithmetic(takes, opcode, operation):
    return script_word(takes, "cell", asm(opcode) + WRAP_CELL, lambda *values: wrap_cell(operation(*values)))


def cell_comparison(takes, code, compare):
    # Forth true flags have every bit set. Our canonical ScriptNum for that cell is -1.
    return Primitive(tuple(takes.split()), ("cell",), code + asm("OP_NEGATE"),
                     lambda *values: (-int(compare(*values)),), "script execution", comparison=True)


UNSIGNED_CELL = add_modulus_if_negative(CELL_MODULUS)
CORE_PRIMITIVES = {
    "+": cell_arithmetic("cell cell", "OP_ADD", lambda x, y: x + y),
    "-": cell_arithmetic("cell cell", "OP_SUB", lambda x, y: x - y),
    "*": cell_arithmetic("cell cell", "OP_MUL", lambda x, y: x * y),
    "1+": cell_arithmetic("cell", "OP_1ADD", lambda x: x + 1),
    "1-": cell_arithmetic("cell", "OP_1SUB", lambda x: x - 1),
    "negate": cell_arithmetic("cell", "OP_NEGATE", lambda x: -x),
    "=": cell_comparison("cell cell", asm("OP_NUMEQUAL"), lambda x, y: x == y),
    "<": cell_comparison("cell cell", asm("OP_LESSTHAN"), lambda x, y: x < y),
    ">": cell_comparison("cell cell", asm("OP_GREATERTHAN"), lambda x, y: x > y),
    "0=": cell_comparison("cell", asm("OP_NOT"), lambda x: x == 0),
    "0<": cell_comparison("cell", asm("OP_0 OP_LESSTHAN"), lambda x: x < 0),
    "u<": cell_comparison("cell cell", UNSIGNED_CELL + asm("OP_SWAP") + UNSIGNED_CELL
                          + asm("OP_SWAP OP_LESSTHAN"), lambda x, y: x % CELL_MODULUS < y % CELL_MODULUS),
    "min": script_word("cell cell", "cell", asm("OP_MIN"), min),
    "max": script_word("cell cell", "cell", asm("OP_MAX"), max),
}
CORE_EXT_PRIMITIVES = {
    "0<>": cell_comparison("cell", asm("OP_0NOTEQUAL"), lambda x: x != 0),
    "0>": cell_comparison("cell", asm("OP_0 OP_GREATERTHAN"), lambda x: x > 0),
    "<>": cell_comparison("cell cell", asm("OP_NUMEQUAL OP_NOT"), lambda x, y: x != y),
}
BSV_PRIMITIVES = {
    "u32+": script_word("u32 u32", "u32", asm("OP_ADD") + WRAP_U32, lambda x, y: (x + y) % U32),
    "u32<": cell_comparison("u32 u32", asm("OP_LESSTHAN"), lambda x, y: x < y),
    "cell>u32": script_word("cell", "u32", residue(U32), lambda x: x % U32),
    "u32>cell": script_word("u32", "cell", b"", lambda x: x),
    "bytes-cat": script_word("bytes bytes", "bytes", asm("OP_CAT"), lambda x, y: x + y),
    "bytes-sha256": script_word("bytes", "bytes", asm("OP_SHA256"), lambda x: sha256(x).digest()),
    "bytes=": cell_comparison("bytes bytes", asm("OP_EQUAL"), lambda x, y: x == y),
}
PRIMITIVES = CORE_PRIMITIVES | CORE_EXT_PRIMITIVES | BSV_PRIMITIVES

CORE_SHUFFLES = {
    "dup": (1, (0, 0), "OP_DUP"),
    "drop": (1, (), "OP_DROP"),
    "swap": (2, (1, 0), "OP_SWAP"),
    "over": (2, (0, 1, 0), "OP_OVER"),
    "rot": (3, (1, 2, 0), "OP_ROT"),
    "2dup": (2, (0, 1, 0, 1), "OP_2DUP"),
    "2drop": (2, (), "OP_2DROP"),
    "2swap": (4, (2, 3, 0, 1), "OP_2SWAP"),
    "2over": (4, (0, 1, 2, 3, 0, 1), "OP_3 OP_PICK OP_3 OP_PICK"),
}
CORE_EXT_SHUFFLES = {
    "nip": (2, (1,), "OP_NIP"),
    "tuck": (2, (1, 0, 1), "OP_TUCK"),
}
SHUFFLES = CORE_SHUFFLES | CORE_EXT_SHUFFLES

CORE_EXT_LITERALS = {"true": Literal("cell", -1), "false": Literal("cell", 0)}
ROUTES = {"route-review": Literal("route", 0), "route-settle": Literal("route", 1)}
NAMED_LITERALS = CORE_EXT_LITERALS | ROUTES


def host_word(takes, gives, method, evidence):
    return Primitive((takes,), (gives,), None,
                     lambda context, value: (getattr(context, method)(value),), evidence)


HOST_WORDS = {
    "bsv-lookup-utxo": host_word("outpoint", "utxo", "lookup", "live UTXO provider"),
    "bsv-sign": host_word("request", "bytes", "sign", "external signer and native CHECKSIG"),
    "bsv-submit": host_word("transaction", "bytes", "submit", "node transaction admission"),
    "utxo>outpoint": host_word("utxo", "outpoint", "outpoint", "bound parent transaction bytes"),
    "utxo>script": host_word("utxo", "script", "script", "bound output script"),
}

# Forth 2012 §§6.1–6.2. Keep the full inventory so known unsupported words
# get a different build diagnostic from misspelled or missing definitions.
CORE_WORDS = set("""
! # #> #S ' ( * */ */MOD + +! +LOOP , - . ." / /MOD 0< 0= 1+ 1- 2! 2* 2/ 2@ 2DROP 2DUP
2OVER 2SWAP : ; < <# = > >BODY >IN >NUMBER >R ?DUP @ ABORT ABORT" ABS ACCEPT ALIGN ALIGNED
ALLOT AND BASE BEGIN BL C! C, C@ CELL+ CELLS CHAR CHAR+ CHARS CONSTANT COUNT CR CREATE
DECIMAL DEPTH DO DOES> DROP DUP ELSE EMIT ENVIRONMENT? EVALUATE EXECUTE EXIT FILL FIND
FM/MOD HERE HOLD I IF IMMEDIATE INVERT J KEY LEAVE LITERAL LOOP LSHIFT M* MAX MIN MOD
MOVE NEGATE OR OVER POSTPONE QUIT R> R@ RECURSE REPEAT ROT RSHIFT S" S>D SIGN SM/REM
SOURCE SPACE SPACES STATE SWAP THEN TYPE U. U< UM* UM/MOD UNLOOP UNTIL VARIABLE WHILE
WORD XOR [ ['] [CHAR]
""".lower().split())
CORE_EXT_WORDS = set(r"""
.( .R 0<> 0> 2>R 2R> 2R@ :NONAME <> ?DO ACTION-OF AGAIN BUFFER: C" CASE COMPILE,
DEFER DEFER! DEFER@ ENDCASE ENDOF ERASE FALSE HEX HOLDS IS MARKER NIP OF PAD PARSE
PARSE-NAME PICK REFILL RESTORE-INPUT ROLL S\" SAVE-INPUT SOURCE-ID TO TRUE TUCK U.R U>
UNUSED VALUE WITHIN [COMPILE] \
""".lower().split())
CORE_SOURCE = {":", ";", "("}
CORE_EXT_SOURCE = {"\\"}
CORE_SCRIPT = CORE_PRIMITIVES.keys() | CORE_SHUFFLES.keys() | {"if", "else", "then"}
CORE_EXT_SCRIPT = CORE_EXT_PRIMITIVES.keys() | CORE_EXT_SHUFFLES.keys() | CORE_EXT_LITERALS.keys()
BSV_SOURCE = {"bsv-use", "bsv-effect:", "work:", "join:", "gate:", "split-authority:", "independent-submit"}
BSV_SCRIPT = BSV_PRIMITIVES.keys() | ROUTES.keys() | {"bytes-hex"}
OPTIONAL_WORDSETS = {"core-ext"}


def capabilities():
    def wordset(words, source, script, enabled):
        return {"enabled_by_default": enabled, "source": sorted(source), "script": sorted(script),
                "unsupported": sorted(words - source - script)}

    return {
        "baseline": "Forth 2012 Core",
        "cell": {"bits": CELL_BITS, "encoding": "signed canonical ScriptNum", "overflow": "wrap"},
        "wordsets": {
            "core": wordset(CORE_WORDS, CORE_SOURCE, CORE_SCRIPT, True),
            "core-ext": wordset(CORE_EXT_WORDS, CORE_EXT_SOURCE, CORE_EXT_SCRIPT, False),
        },
        "bsv": {"source": sorted(BSV_SOURCE), "script": sorted(BSV_SCRIPT),
                "host": {name: {"takes": word.takes, "gives": word.gives, "evidence": word.evidence}
                         for name, word in HOST_WORDS.items()}},
    }


def cell_literal(token):
    prefixes = {"#": (10, r"[0-9]+"), "$": (16, r"[0-9a-fA-F]+"), "%": (2, r"[01]+")}
    if len(token) == 3 and token[0] == token[-1] == "'" and token[1].isprintable():
        return Literal("cell", ord(token[1]))
    marked = token[0] in prefixes
    base, digits = prefixes.get(token[0], (10, r"[0-9]+"))
    entry = token[1:] if marked else token
    if re.fullmatch("-?" + digits, entry):
        value = int(entry, base)
        if not -CELL_SIGN <= value < CELL_MODULUS:
            raise ValueError("literal is out of range for a 64-bit cell")
        return Literal("cell", wrap_cell(value))
    return None
