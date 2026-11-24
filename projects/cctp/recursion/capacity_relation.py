"""Transaction material for a capacity verifier, independent of its proof system."""

from dataclasses import dataclass

from continuity_preimage import CURRENT_OUTPOINT
from continuity_statement import OUTPUT_SIZE
from mimo_verifier import _compact_size, _parse_active_token, _pick, _split, _take_output_script, _unsigned
from operational_token import TokenPolicy
from recursive_mimo import _assert_u64
from shared.script import asm, number, push
from shared.transaction import blob, compact
from statement import fixed
from transaction_relation import TokenState
from transfer import COMPACT_SCRIPTCODE

MAX_TOKENS = 256
NARROW_PARENT_OUTPUTS = 4
PREIMAGE_SIZE = 157 + len(COMPACT_SCRIPTCODE)
TOKEN_INPUT_START = 2
OUTPOINT_SIZE = 36


def _roll(depth):
    return number(depth) + asm("OP_ROLL")


def _slice(offset, size):
    return _split(offset) + asm("OP_NIP") + _split(size) + asm("OP_DROP")


def _require_empty():
    return asm("OP_SIZE OP_0 OP_NUMEQUALVERIFY OP_DROP")


def _insert_below(depth):
    # Move the top element underneath its existing neighbors in order.
    return _roll(depth) * depth


def _repeated_capacity_bytes(unit):
    return push(unit) + asm("OP_DUP OP_CAT") * (MAX_TOKENS.bit_length() - 1)


def ordered_parent_groups(tx, pairs):
    """Choose one supporting/verifier funding and one token parent per actual txid.

    The candidate orders token vin2+ first by txid (wire bytes as an unsigned
    little-endian integer), then by strictly increasing vout within each txid.
    """
    groups = {}
    for supporting, parent in pairs:
        parent_id = parent.txid_wire()
        if parent_id in groups:
            raise ValueError("duplicate parent material")
        groups[parent_id] = (supporting, parent)
    ordered = []
    last = (-1, -1)
    last_hash = None
    for txin in tx.inputs[TOKEN_INPUT_START:]:
        position = (int.from_bytes(fixed(txin.txid, 32), "little"), txin.vout)
        if position <= last:
            raise ValueError("token inputs are not in strictly increasing outpoint order")
        last = position
        if txin.txid != last_hash:
            if txin.txid not in groups:
                raise ValueError("missing actual token parent")
            ordered.append(groups.pop(txin.txid))
            last_hash = txin.txid
    if groups:
        raise ValueError("unused token parent material")
    return tuple(ordered)


def wide_group_stream(tx, pairs, *, encode_record=None):
    result = bytearray()
    for pair in ordered_parent_groups(tx, pairs):
        for material in pair:
            raw = material.serialize()
            result.extend(blob(raw if encode_record is None else encode_record(raw)))
    return bytes(result)


def _check_candidate(incoming):
    # Preserve all material while checking the compact ALL commitments and the
    # executing vin-zero outpoint. The enclosing verifier authenticates the
    # preimage signature, funding guard hash and companion vin-one output.
    return (
        asm("OP_SIZE 32 OP_NUMEQUALVERIFY OP_OVER OP_SIZE")
        + number(PREIMAGE_SIZE) + asm("OP_NUMEQUALVERIFY")
        + _slice(CURRENT_OUTPOINT + OUTPOINT_SIZE, len(blob(COMPACT_SCRIPTCODE)))
        + push(blob(COMPACT_SCRIPTCODE)) + asm("OP_EQUALVERIFY OP_OVER")
        + _split(PREIMAGE_SIZE - 4) + asm("OP_NIP") + push(b"\x41\0\0\0")
        + asm("OP_EQUALVERIFY OP_OVER")
        + _slice(4, 32) + _pick(3) + asm("OP_HASH256 OP_EQUALVERIFY OP_OVER")
        + _slice(PREIMAGE_SIZE - 40, 32) + _pick(4) + asm("OP_HASH256 OP_EQUALVERIFY")
        + _pick(2) + asm("OP_SIZE") + number(OUTPOINT_SIZE * (TOKEN_INPUT_START + incoming))
        + asm("OP_NUMEQUALVERIFY") + _split(OUTPOINT_SIZE) + asm("OP_DROP")
        + _pick(2) + _slice(CURRENT_OUTPOINT, OUTPOINT_SIZE) + asm("OP_EQUALVERIFY")
    )


def _wide_output_layout(token_script_size):
    if type(token_script_size) is not int or not 1 <= token_script_size <= 65535:
        raise ValueError("invalid canonical token script size")
    length = compact(token_script_size)
    stride = 8 + len(length) + token_script_size
    mask = bytes(8) + b"\xff" * len(length) + bytes(token_script_size)
    pattern = bytes(8) + length + bytes(token_script_size)
    return stride, _repeated_capacity_bytes(mask) + _repeated_capacity_bytes(pattern)


def _check_wide_output_headers(stride, tail_size, *, mask_depth):
    # Given [count, raw], verify all carrier CompactSize fields in one pass.
    # The exact byte length and matching fields prove the fixed-width offsets.
    # The last output is reserved for the capacity receipt.
    return (
        asm("OP_OVER OP_1SUB") + number(stride) + asm("OP_MUL OP_OVER OP_SIZE OP_NIP OP_OVER")
        + number(tail_size) + asm("OP_ADD OP_NUMEQUALVERIFY OP_2DUP OP_SPLIT OP_DROP")
        + _pick(mask_depth) + asm("OP_2 OP_PICK OP_SPLIT OP_DROP OP_AND")
        + _pick(mask_depth - 1) + asm("OP_2 OP_PICK OP_SPLIT OP_DROP OP_EQUALVERIFY OP_DROP")
    )


def _output_count(minimum):
    return asm("OP_OVER") + number(minimum) + number(MAX_TOKENS + 2) + asm("OP_WITHIN OP_VERIFY")


def _prepare_parent_outputs(stride, tail_size):
    """Validate actual parent output count and, for wide parents, all positions."""
    # Under [count, raw] the active state is [outputs, preimage, guard, mask,
    # pattern, sum, txid]. Smaller outputs are walked by their actual lengths.
    return (
        _output_count(1)
        + asm("OP_OVER") + number(NARROW_PARENT_OUTPUTS) + asm("OP_GREATERTHAN OP_IF")
        + _check_wide_output_headers(stride, tail_size, mask_depth=7) + asm("OP_ENDIF")
    )


def _fixed_width_parent_script(stride):
    """Consume [output count, actual bytes, vout]; leave the chosen carrier lock."""
    return (
        asm("OP_DUP OP_0 OP_4 OP_PICK OP_1SUB OP_WITHIN OP_VERIFY")
        + number(stride) + asm("OP_MUL OP_SPLIT OP_NIP")
        + _take_output_script() + asm("OP_DROP OP_NIP")
    )


def select_wide_token_output_script(token_script_size, tail_size):
    """Consume [vout, actual count, actual outputs]; leave the active carrier's script.

    The caller must parse actual output count and start from the real parent raw
    transaction. The complete width check here rules out malformed prior fields
    before the selected position. The caller checks the returned lock and state.
    """
    if type(tail_size) is not int or tail_size <= 0:
        raise ValueError("expected a positive capacity receipt size")
    stride, masks = _wide_output_layout(token_script_size)
    return (
        masks + _roll(4) * 3 + _output_count(2)
        + _check_wide_output_headers(stride, tail_size, mask_depth=6)
        + asm("OP_ROT") + _fixed_width_parent_script(stride)
        + asm("OP_TOALTSTACK OP_2DROP OP_FROMALTSTACK")
    )


def _actual_parent_script(stride):
    """Consume [actual output count, actual bytes, vout]; leave actual script."""
    skip = (
        asm("OP_DUP OP_0NOTEQUAL OP_IF OP_SWAP") + _take_output_script()
        + asm("OP_NIP OP_SWAP OP_1SUB OP_ENDIF")
    )
    return (
        _pick(2) + number(NARROW_PARENT_OUTPUTS) + asm("OP_GREATERTHAN OP_IF")
        + _fixed_width_parent_script(stride)
        + asm("OP_ELSE OP_DUP OP_3 OP_PICK OP_LESSTHAN OP_VERIFY OP_ROT OP_DROP")
        + skip * (NARROW_PARENT_OUTPUTS - 1)
        + asm("OP_0 OP_NUMEQUALVERIFY") + _take_output_script() + asm("OP_DROP OP_ENDIF")
    )


def _new_group(parent_outputs, parent_digest, stride, tail_size, *, first, record_decoder):
    # A new actual txid consumes exactly one pair of length-prefixed raws.
    # Replace [last txid, last vout, last count, last outputs, group stream,
    # current txid] with [current txid, -1, count, outputs, remaining stream].
    order = (
        asm("OP_NIP") if first else
        asm("OP_TUCK") + _unsigned() + asm("OP_SWAP") + _unsigned()
        + asm("OP_SWAP OP_LESSTHAN OP_VERIFY")
    )
    read_material = _compact_size() + asm("OP_SPLIT")
    reconstruct = b""
    if record_decoder is not None:
        decompress = _pick(11) + _pick(11) + record_decoder
        reconstruct = decompress + asm("OP_SWAP") + decompress + asm("OP_SWAP")
    return (
        asm("OP_SWAP OP_TOALTSTACK OP_TOALTSTACK OP_2DROP OP_DROP OP_FROMALTSTACK")
        + order + asm("OP_FROMALTSTACK")
        + read_material * 2 + asm("OP_TOALTSTACK") + reconstruct
        + asm("OP_DUP OP_HASH256 OP_3 OP_PICK OP_EQUALVERIFY")
        + asm("OP_2DUP OP_SWAP") + _pick(9) + parent_digest
        + asm("OP_SIZE 32 OP_NUMEQUALVERIFY OP_TOALTSTACK OP_4 OP_ROLL OP_FROMALTSTACK OP_CAT OP_TOALTSTACK")
        + asm("OP_NIP") + parent_outputs + _prepare_parent_outputs(stride, tail_size)
        + asm("OP_FROMALTSTACK") + _insert_below(4)
        + asm("OP_1NEGATE OP_ROT OP_ROT OP_FROMALTSTACK")
    )


def _positive_quantity():
    return _unsigned() + asm("OP_DUP OP_0NOTEQUAL OP_VERIFY")


def _input_step(new_group, parse_token, stride, *, first):
    # Invariant on the main stack (bottom to top):
    # [outputs, preimage, guard, mask, pattern, packed digests, sum, last txid,
    # last vout, parent output count, parent outputs, group stream, prevouts].
    same_or_new = (
        new_group if first else
        asm("OP_DUP OP_6 OP_PICK OP_EQUAL OP_IF OP_DROP OP_ELSE")
        + new_group + asm("OP_ENDIF")
    )
    return (
        _split(OUTPOINT_SIZE) + asm("OP_SWAP 32 OP_SPLIT") + _unsigned()
        + asm("OP_TOALTSTACK OP_SWAP OP_TOALTSTACK") + same_or_new
        + asm("OP_FROMALTSTACK OP_FROMALTSTACK OP_DUP OP_6 OP_PICK OP_GREATERTHAN OP_VERIFY")
        + asm("OP_SWAP OP_TOALTSTACK OP_SWAP OP_TOALTSTACK OP_3 OP_ROLL OP_DROP OP_ROT OP_ROT")
        + asm("OP_3DUP OP_ROT") + _actual_parent_script(stride)
        + parse_token + _pick(10) + asm("OP_EQUALVERIFY")
        + _positive_quantity() + asm("OP_5 OP_ROLL OP_ADD") + _assert_u64()
        + _insert_below(4) + asm("OP_FROMALTSTACK OP_FROMALTSTACK")
    )


@dataclass(frozen=True)
class WideProfile:
    """Fixed token vin/vout counts with a variable number of actual parents."""

    incoming: int
    outgoing: int
    tail_size: int = OUTPUT_SIZE

    def __post_init__(self):
        if any(type(count) is not int or not 1 <= count <= MAX_TOKENS for count in (self.incoming, self.outgoing)):
            raise ValueError("expected 1 to 256 token inputs and outputs")
        if type(self.tail_size) is not int or self.tail_size <= 0:
            raise ValueError("expected a positive capacity receipt size")

    def relation(self, asset_id, freeze_key, *, parent_outputs, parent_digest, parse_token=None, token_script_size=None,
                 record_decoder=None):
        """Consume [group stream, outputs, prevouts, preimage, actual guard].

        Return [packed unique parent digests, serialized output tail, preimage].
        With a record decoder, also consume [dict0, dict1] immediately below
        the group stream to reconstruct each raw before checking its txid.
        Bytes below this material and the altstack are preserved. The
        `parent_outputs` fragment consumes [parent raw] to [actual output count,
        actual outputs without count or locktime]. The `parent_digest` fragment
        consumes [parent raw, supporting verifier funding raw, actual guard] to
        one digest. Both fragments preserve everything underneath those fields.
        """
        fixed(asset_id, 32)
        fixed(freeze_key, 33)
        if token_script_size is None:
            policy = TokenPolicy((b"capacity template",), freeze_key,
                                 certified_admin=True, shared_ordinary_guard=True)
            token_script_size = len(policy.lock(TokenState(asset_id, 1, freeze_key)))
        stride, masks = _wide_output_layout(token_script_size)
        if parse_token is None:
            parse_token = _parse_active_token(asset_id, freeze_key, 1, certified_admin=True, shared_ordinary_guard=True)

        initial_state = (
            _check_candidate(self.incoming)
            + _pick(2) + _split(OUTPOINT_SIZE * TOKEN_INPUT_START) + asm("OP_NIP OP_TOALTSTACK")
            + asm("OP_2 OP_ROLL OP_DROP OP_3 OP_ROLL OP_TOALTSTACK")
            + masks + asm("OP_0 OP_0 OP_0 OP_0 OP_0 OP_0 OP_FROMALTSTACK OP_FROMALTSTACK")
        )
        first_group = _new_group(parent_outputs, parent_digest, stride, self.tail_size,
                                 first=True, record_decoder=record_decoder)
        next_group = _new_group(parent_outputs, parent_digest, stride, self.tail_size,
                                first=False, record_decoder=record_decoder)
        vin = (
            _input_step(first_group, parse_token, stride, first=True)
            + _input_step(next_group, parse_token, stride, first=False) * (self.incoming - 1)
        )
        start_outputs = (
            _require_empty() * 2 + asm("OP_2DROP OP_2DROP OP_TOALTSTACK OP_TOALTSTACK OP_2DROP")
            + asm("OP_2 OP_ROLL OP_0 OP_SWAP")
        )
        vout = (
            _take_output_script() + asm("OP_TOALTSTACK") + parse_token
            + asm("OP_3 OP_PICK OP_EQUALVERIFY") + _positive_quantity() + asm("OP_ADD")
            + _assert_u64() + asm("OP_FROMALTSTACK")
        )
        finish = (
            asm("OP_SIZE") + number(self.tail_size) + asm("OP_NUMEQUALVERIFY OP_TOALTSTACK OP_SWAP OP_DROP")
            + asm("OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_3 OP_ROLL OP_NUMEQUALVERIFY OP_SWAP OP_ROT")
        )
        cleanup = b"" if record_decoder is None else asm("OP_3 OP_ROLL OP_DROP OP_3 OP_ROLL OP_DROP")
        return initial_state + vin + start_outputs + vout * self.outgoing + finish + cleanup
