"""Compile the typed Deferred lock with 4thGraph and bind its public fields."""
from dataclasses import dataclass
from functools import cache
from hashlib import sha256
import json
from pathlib import Path

from fourthgraph.bsv.script import asm, decode_num, encode_num, push
from fourthgraph.compiler.lowering import CompiledWord, compile_word
from fourthgraph.compiler.source import SourceCompiler
from fourthgraph.compiler.wordsets import Literal, Primitive, script_word

SOURCE = Path(__file__).with_name("deferred-activation.fth")
DEFERRED_TEMPLATE_VERSION = "0.3.0"
RELEASE_OPTIMIZATION = "stack"
RELEASE_TEMPLATE = SOURCE.parents[1] / "versions" / f"v{DEFERRED_TEMPLATE_VERSION}"
FIELD_MARKERS = {
    "funding-owner": b"\xf1" * 20,
    "target-script-hash": b"\xf2" * 32,
    "input-value": b"\xf3" * 8,
    "target-txout-hash": b"\xf4" * 32,
}


def runtime_only(takes, gives, opcodes):
    def run(*_):
        raise ValueError("this word must run in a Bitcoin Script interpreter")

    # Guards and stack/transaction effects must stay in program order.
    return Primitive(tuple(takes.split()), tuple(gives.split()), asm(opcodes), run,
                     "Script runtime", may_fail=True)


def within(kind):
    return Primitive((kind, "cell", "cell"), ("cell",), asm("OP_WITHIN OP_NEGATE"),
                     lambda x, lo, hi: (-int(lo <= x < hi),), "Script numeric comparison", comparison=True)


SCRIPT_WORDS = {
    "bytes-split": runtime_only("bytes cell", "bytes bytes", "OP_SPLIT"),
    "bytes-and": runtime_only("bytes bytes", "bytes", "OP_AND"),
    "bytes-verify=": runtime_only("bytes bytes", "", "OP_EQUALVERIFY"),
    "bytes-length": Primitive(("bytes",), ("cell",), asm("OP_SIZE OP_NIP"),
                              lambda data: (len(data),), "Script element length",
                              checked_bounds=(0, (1 << 63) - 1)),
    "bytes>int": script_word("bytes", "script-int", asm("OP_BIN2NUM"), decode_num),
    "int>bytes": script_word("script-int", "bytes", b"", encode_num),
    "int>bin": runtime_only("script-int cell", "bytes", "OP_NUM2BIN"),
    "bytes-hash256": runtime_only("bytes", "bytes", "OP_HASH256"),
    "cell-within?": within("cell"),
    "int-within?": within("script-int"),
    "int-min": script_word("script-int script-int", "script-int", asm("OP_MIN"), min),
    "verify": runtime_only("cell", "", "OP_VERIFY"),
    "int-verify": runtime_only("script-int", "", "OP_VERIFY"),
    "witness-depth": runtime_only("", "cell", "OP_DEPTH"),
    "flag>alt": runtime_only("cell", "", "OP_TOALTSTACK"),
    "alt>flag": runtime_only("", "cell", "OP_FROMALTSTACK"),
    "bytes>alt": runtime_only("bytes", "", "OP_TOALTSTACK"),
    # The depth check established that the auxiliary item is below the two
    # typed items on this path. ROT brings it into the typed suffix.
    "reveal-auxiliary": runtime_only("bytes bytes", "bytes bytes bytes", "OP_ROT"),
    # The optional binding signature is on altstack. Both CODESEPARATOR
    # suffixes are part of the published preimage format.
    "check-activation-signatures": runtime_only(
        "bytes bytes cell", "cell",
        "OP_IF OP_FROMALTSTACK OP_OVER OP_CODESEPARATOR OP_CHECKSIGVERIFY OP_ENDIF "
        "OP_CODESEPARATOR OP_CHECKSIG",
    ),
}


def field_offset(script, name):
    marker = FIELD_MARKERS[name]
    encoded = push(marker)
    if script.count(encoded) != 1:
        raise ValueError(f"expected exactly one compiled push for {name}")
    return script.index(encoded) + len(encoded) - len(marker)


@dataclass(frozen=True)
class DeferredTemplate:
    metadata: bytes
    activation: CompiledWord
    fields: tuple[int, int]

    def bind(self, owner, script_hash, value, output_hash):
        # The metadata prefix contains two direct pushes followed by 2DROP.
        # A legacy full-key owner replaces only the first push.
        if len(owner) not in (20, 65) or (len(script_hash), len(value), len(output_hash)) != (32, 8, 32):
            raise ValueError("invalid Deferred commitment widths")
        body = bytearray(self.activation.script)
        for offset, field in zip(self.fields, (value, output_hash), strict=True):
            body[offset:offset + len(field)] = field
        return push(owner) + push(script_hash) + self.metadata[-1:] + body


@cache
def released_template():
    """Load immutable v0.3.0 bytes without running the compiler."""
    layout = json.loads((RELEASE_TEMPLATE / "layout.json").read_text(encoding="ascii"))
    script = bytes.fromhex((RELEASE_TEMPLATE / "template.hex").read_text(encoding="ascii"))
    if (layout["template_version"] != DEFERRED_TEMPLATE_VERSION
            or layout["optimization"] != RELEASE_OPTIMIZATION
            or layout["script_bytes"] != len(script)
            or layout["base_script_sha256"] != sha256(script).hexdigest()):
        raise ValueError("Deferred release template differs from its layout")
    metadata_end = 55  # Direct 20-byte and 32-byte pushes followed by 2DROP.
    fields = []
    for name, length in (("input_value_le64", 8), ("target_txout_hash256", 32)):
        field = layout["fields"][name]
        offset = field["offset"]
        if (field["length"] != length or not metadata_end < offset <= len(script) - length
                or script[offset - 1] != length):
            raise ValueError(f"invalid Deferred release template field {name}")
        fields.append(offset - metadata_end)
    return DeferredTemplate(script[:metadata_end], CompiledWord(script[metadata_end:]), tuple(fields))


@cache
def compile_template(optimization):
    vocabulary = {**SCRIPT_WORDS, **{name: Literal("bytes", value) for name, value in FIELD_MARKERS.items()}}
    source = SourceCompiler(SOURCE.read_text(encoding="ascii"), vocabulary=vocabulary, source_path=SOURCE)
    metadata = compile_word(source.words["deferred-metadata"]).script
    metadata_prefix = push(FIELD_MARKERS["funding-owner"]) + push(FIELD_MARKERS["target-script-hash"])
    if metadata != metadata_prefix + asm("OP_2DROP"):
        raise ValueError("unexpected compiled Deferred metadata layout")
    activation = compile_word(source.words["deferred-activation"], optimization)
    fields = tuple(field_offset(activation.script, name) for name in ("input-value", "target-txout-hash"))
    return DeferredTemplate(metadata, activation, fields)
