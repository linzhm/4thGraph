"""Lower ForkID and Chronicle OTDA contexts from transaction commitments."""

from dataclasses import dataclass

from shared.script import asm, number, push
from shared.transaction import CHRONICLE, FORKID, SIGHASH_ALL, blob, compact, hash256


ALL = FORKID | SIGHASH_ALL
OTDA_ALL = ALL | CHRONICLE
ALL_BYTES = ALL.to_bytes(4, "little")
OUTPOINT_OFFSET = 68
SCRIPT_CODE_OFFSET = 104
PREIMAGE_FIXED_BYTES = SCRIPT_CODE_OFFSET + 52  # All fields apart from the scriptCode blob.
CONTEXT_SUFFIX_BYTES = 40  # hashOutputs, nLockTime, sighash
RECONSTRUCTED_FIELDS = ("hashPrevouts", "hashSequence", "hashOutputs", "sighash")
PACKED_SCRIPT_OFFSET = 4 + SCRIPT_CODE_OFFSET - OUTPOINT_OFFSET
LINKED_OUTPOINT_OFFSET = 4
LINKED_CONTEXT_BYTES = 56  # Version, outpoint, previous amount, sequence, locktime.


@dataclass(frozen=True)
class LinkedContext:
    """A context whose assertions determine every output and the input count."""

    script_code: bytes
    sighash: int
    output_count: int

    @classmethod
    def for_template(cls, template, sighash, script_code, constructed_outputs, *, requires_previous_amount=True):
        if sighash == OTDA_ALL and requires_previous_amount:
            return None
        if (sighash in (ALL, OTDA_ALL) and len(template.inputs) == 1 and script_code
                and constructed_outputs and template.outputs == constructed_outputs):
            return cls(script_code, sighash, len(constructed_outputs))
        return None

    @property
    def packed_bytes(self):
        return LINKED_CONTEXT_BYTES if self.sighash == ALL else LINKED_CONTEXT_BYTES - 8

    def check_size(self):
        return asm("OP_SIZE") + number(self.packed_bytes) + asm("OP_NUMEQUALVERIFY")

    def pack(self, preimage):
        script_code = blob(self.script_code)
        if self.sighash == OTDA_ALL:
            script_offset = 41  # Version, one-byte input count, then the sole outpoint.
            script_end = script_offset + len(script_code)
            if (len(preimage) < script_end + 4 + 1 + 8 or preimage[4] != 1
                    or preimage[script_offset:script_end] != script_code
                    or preimage[-4:] != OTDA_ALL.to_bytes(4, "little")):
                raise ValueError("expected an OTDA ALL preimage for one input and the linked scriptCode")
            return preimage[:4] + preimage[5:script_offset] + preimage[script_end:script_end + 4] + preimage[-8:-4]
        check_single_input(preimage)
        script_end = SCRIPT_CODE_OFFSET + len(script_code)
        if (len(preimage) != PREIMAGE_FIXED_BYTES + len(script_code)
                or preimage[SCRIPT_CODE_OFFSET:script_end] != script_code):
            raise ValueError("preimage does not match the linked scriptCode")
        return (preimage[:4] + preimage[OUTPOINT_OFFSET:SCRIPT_CODE_OFFSET]
                + preimage[script_end:-CONTEXT_SUFFIX_BYTES] + preimage[-8:-4])

    def _complete_forkid(self):
        # Main: exact hashOutputs. Alt: packed context. Leave complete preimage on Alt.
        version_and_prevouts = (asm("OP_FROMALTSTACK OP_4 OP_SPLIT") + number(36)
                                + asm("OP_SPLIT OP_TOALTSTACK OP_DUP OP_HASH256 OP_ROT OP_SWAP OP_CAT"))
        sequence = asm("OP_FROMALTSTACK OP_DUP OP_8 OP_SPLIT OP_NIP OP_4 OP_SPLIT OP_DROP OP_HASH256")
        prefix = asm("OP_ROT OP_SWAP OP_CAT OP_ROT OP_CAT") + push(blob(self.script_code)) + asm("OP_CAT")
        # The 16-byte tail is amount || sequence || locktime. Insert the output hash before locktime.
        outputs = number(12) + asm("OP_SPLIT OP_TOALTSTACK OP_CAT OP_SWAP OP_CAT OP_FROMALTSTACK OP_CAT")
        return version_and_prevouts + sequence + prefix + asm("OP_SWAP") + outputs + push(ALL_BYTES) + asm("OP_CAT OP_TOALTSTACK")

    def bind_outputs(self):
        # Main: concatenated output serializations. Alt: packed context.
        if self.sighash == ALL:
            return asm("OP_HASH256") + self._complete_forkid()

        prefix = (asm("OP_FROMALTSTACK OP_4 OP_SPLIT OP_SWAP OP_1 OP_CAT OP_SWAP")
                  + number(36) + asm("OP_SPLIT OP_TOALTSTACK OP_CAT")
                  + push(blob(self.script_code)) + asm("OP_CAT OP_FROMALTSTACK OP_4 OP_SPLIT OP_TOALTSTACK OP_CAT"))
        count = number(self.output_count) if self.output_count <= 16 else push(compact(self.output_count))
        return (prefix + count + asm("OP_CAT OP_SWAP OP_CAT OP_FROMALTSTACK OP_CAT")
                + push(OTDA_ALL.to_bytes(4, "little")) + asm("OP_CAT OP_TOALTSTACK"))


@dataclass(frozen=True)
class ScriptCodeReuse:
    source: int
    repeated: int
    size: int

    def after_prefix(self, prefix_size):
        return ScriptCodeReuse(prefix_size + self.source, prefix_size + self.repeated, self.size)

    def decoder(self):
        source = number(PACKED_SCRIPT_OFFSET + self.source)
        repeated = number(PACKED_SCRIPT_OFFSET + self.repeated)
        return (asm("OP_DUP") + source + asm("OP_SPLIT OP_NIP") + number(self.size)
                + asm("OP_SPLIT OP_DROP OP_SWAP") + repeated + asm("OP_SPLIT OP_ROT OP_SWAP OP_CAT OP_CAT"))

    def pack(self, packed):
        source = PACKED_SCRIPT_OFFSET + self.source
        repeated = PACKED_SCRIPT_OFFSET + self.repeated
        if packed[source:source + self.size] != packed[repeated:repeated + self.size]:
            raise ValueError("scriptCode does not contain the same emitted fragment at both linked offsets")
        return packed[:repeated] + packed[repeated + self.size:]


def repeated_fragment(parts):
    """Find the largest duplicate among the compiler's emitted code fragments."""
    first = {}
    best = None
    offset = 0
    for part in parts:
        size = len(part)
        if size and part in first and (best is None or size > best.size):
            best = ScriptCodeReuse(first[part], offset, size)
        first.setdefault(part, offset)
        offset += size
    return best


def reconstructed_context(template, sighash, hash_outputs, *, script_size=None):
    """Emit an authenticated preimage from packed fields, if the shape permits it.

    hash_outputs consumes (scriptCode, previous-amount) plus any application
    values below them. It hashes the complete exact output vector. The code
    includes its CompactSize unless a linked script_size supplies that field.
    The caller authenticates the resulting preimage with PUSHTX.
    """
    if sighash != ALL or len(template.inputs) != 1 or len(template.outputs) != 1 or not hash_outputs:
        return None

    # Packed context: version, outpoint, scriptCode, amount, sequence, locktime.
    if script_size is None:
        split_locktime = asm("OP_SIZE OP_4 OP_SUB OP_SPLIT")
    else:
        # Version, outpoint, amount and sequence occupy 52 bytes before locktime.
        split_locktime = number(script_size + 52) + asm("OP_SPLIT OP_SIZE OP_4 OP_NUMEQUALVERIFY")
    suffix = split_locktime + push(ALL_BYTES) + asm("OP_CAT OP_TOALTSTACK")
    sequence_hash = asm("OP_DUP OP_SIZE OP_4 OP_SUB OP_SPLIT OP_NIP OP_HASH256 OP_TOALTSTACK")
    # Form version || hashPrevouts || hashSequence || outpoint || scriptCode || amount || sequence.
    prefix = (asm("OP_4 OP_SPLIT") + number(36) + asm("OP_SPLIT OP_TOALTSTACK OP_DUP OP_HASH256")
              + asm("OP_ROT OP_SWAP OP_CAT OP_FROMALTSTACK OP_FROMALTSTACK OP_ROT OP_SWAP OP_CAT")
              + asm("OP_ROT OP_CAT"))
    if script_size is None:
        code_size = asm("OP_SIZE") + number(12) + asm("OP_SUB")
    else:
        prefix += push(compact(script_size)) + asm("OP_CAT")
        code_size = number(script_size)
    return (suffix + sequence_hash + prefix + asm("OP_OVER OP_CAT OP_TOALTSTACK")
            + code_size + asm("OP_SPLIT OP_8 OP_SPLIT OP_DROP") + hash_outputs
            + asm("OP_FROMALTSTACK OP_SWAP OP_CAT OP_FROMALTSTACK OP_CAT"))


def check_single_input(preimage):
    if len(preimage) <= PREIMAGE_FIXED_BYTES or preimage[-4:] != ALL_BYTES:
        raise ValueError("expected a ForkID ALL preimage")
    if (hash256(preimage[OUTPOINT_OFFSET:OUTPOINT_OFFSET + 36]) != preimage[4:36]
            or hash256(preimage[-44:-40]) != preimage[36:68]):
        raise ValueError("preimage does not commit to a single input")


def pack_context(preimage, *, script_size=None, reuse=None):
    """Encode the witness for the single-input ForkID ALL reconstruction."""
    check_single_input(preimage)
    script_offset = SCRIPT_CODE_OFFSET
    if script_size is not None:
        header = compact(script_size)
        script_offset += len(header)
        if (preimage[SCRIPT_CODE_OFFSET:script_offset] != header
                or len(preimage) != PREIMAGE_FIXED_BYTES + len(header) + script_size):
            raise ValueError("preimage does not match the linked scriptCode size")
    packed = (preimage[:4] + preimage[OUTPOINT_OFFSET:SCRIPT_CODE_OFFSET]
              + preimage[script_offset:-CONTEXT_SUFFIX_BYTES] + preimage[-8:-4])
    if reuse is None:
        return packed
    if script_size is None or reuse.source < 0 or reuse.size <= 0 or reuse.source + reuse.size > reuse.repeated:
        raise ValueError("scriptCode reuse requires linked non-overlapping fragments")
    if reuse.repeated + reuse.size > script_size:
        raise ValueError("scriptCode reuse extends beyond the linked scriptCode")
    return reuse.pack(packed)
