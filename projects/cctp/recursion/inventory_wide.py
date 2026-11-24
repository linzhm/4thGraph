"""Transfer of 64 outputs selected from an approved 128-leaf inventory, using ForkID or Chronicle."""

from inventory_multipath import multipath_script
from inventory_payment import TOKEN_TAG, _slice, _take_tx_context, _validate_state
from inventory_tree import multi_path
from chronicle_context_script import bind_all_context
from chronicle_preimage import CHRONICLE_ALL
from mimo_verifier import _pick, _split, _unsigned
from shared.script import asm, number, push
from shared.transaction import compact, preimage_all, preimage_otda
from statement import fixed
from transfer import COMPACT_SCRIPTCODE, compact_preimage_digest_script, compact_verifier_binding


WIDTH = 128
COUNT = 64
EMPTY = asm("OP_SIZE OP_0 OP_NUMEQUALVERIFY OP_DROP")


def _add_state():
    # [quantity total, satoshi total, state] -> [new quantity total, new satoshi total].
    return (asm("OP_DUP") + _slice(8, 8) + _unsigned() + asm("OP_ROT OP_ADD OP_TOALTSTACK")
            + _slice(0, 8) + _unsigned() + asm("OP_ADD OP_FROMALTSTACK"))


def _output_totals(parts):
    prefix, body = parts
    header = compact(len(prefix) + 50 + len(body)) + prefix
    # Keep one copy of the approved token header/body below both running totals.
    # Invariant [header, body, total quantity, total sats, remaining serialized outputs].
    start = push(header) + push(body) + asm("OP_0 OP_0 OP_4 OP_ROLL")
    step = (
        _split(8) + _split(len(header)) + asm("OP_SWAP") + _pick(6) + asm("OP_EQUALVERIFY")
        + _split(50) + _split(len(body)) + asm("OP_TOALTSTACK") + _pick(5)
        + asm("OP_EQUALVERIFY") + _validate_state()
        + asm("OP_DUP") + _slice(8, 8) + asm("OP_ROT OP_EQUALVERIFY")
        + _add_state() + asm("OP_FROMALTSTACK")
    )
    return start + step * COUNT + EMPTY + asm("OP_2SWAP OP_2DROP")


def _input_totals_and_records(scope):
    # [remaining siblings, rows, token outpoints] ->
    # [remaining siblings, scope prefix, quantity total, satoshi total, packed selected records].
    start = push(b"\x00" + scope) + asm("OP_0 OP_0 OP_0 5 OP_ROLL 5 OP_ROLL")
    # [prefix,q,s,records,remaining index+state rows,remaining actual outpoints].
    step = (
        _split(36) + asm("OP_TOALTSTACK OP_SWAP") + _split(1) + _split(50) + asm("OP_TOALTSTACK")
        + _validate_state() + asm("OP_DUP OP_TOALTSTACK")
        # [prefix,q,s,records,outpoint,index,state] -> append index || H(00 || scope || outpoint || state).
        + _pick(6) + _pick(3) + asm("OP_CAT OP_SWAP OP_CAT OP_HASH256 OP_CAT OP_NIP OP_CAT")
        + asm("OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK") + _add_state()
        + asm("OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK")
    )
    return start + step * COUNT + EMPTY * 2


def _compact_context_and_output_totals(parts):
    # [input rows, output states, actual prevouts, candidate preimage].
    # Save the digest for the final CODESEPARATOR/CHECKSIG, authenticate vin 0
    # and all 66 outpoints, and save the ordered prevouts for the input scanner.
    preimage_bytes = 157 + len(COMPACT_SCRIPTCODE)
    context = (
        asm("OP_DUP") + compact_preimage_digest_script() + asm("OP_DROP OP_DUP")
        + _slice(4, 32) + _pick(2) + asm("OP_SIZE") + number(36 * (COUNT + 2))
        + asm("OP_NUMEQUALVERIFY OP_HASH256 OP_EQUALVERIFY OP_DUP")
        + _slice(68, 36) + _pick(2) + _slice(0, 36) + asm("OP_EQUALVERIFY")
        + _slice(preimage_bytes - 40, 32) + asm("OP_SWAP OP_TOALTSTACK OP_SWAP")
    )
    prefix, body = parts
    header = compact(len(prefix) + 50 + len(body)) + prefix
    # [expected hashOutputs, header, body, total quantity, total sats,
    #  rebuilt output vector, remaining states]. The known template is pushed once.
    start = push(header) + push(body) + asm("OP_0 OP_0 OP_0 5 OP_ROLL")
    step = (
        _split(50) + asm("OP_TOALTSTACK") + _validate_state() + asm("OP_DUP OP_TOALTSTACK OP_DUP")
        + _slice(8, 8) + _pick(6) + asm("OP_CAT OP_SWAP OP_CAT") + _pick(4)
        + asm("OP_CAT OP_CAT OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK") + _add_state()
        + asm("OP_FROMALTSTACK OP_FROMALTSTACK")
    )
    return (context + start + step * COUNT + EMPTY
            + asm("OP_HASH256 5 OP_ROLL OP_EQUALVERIFY OP_2SWAP OP_2DROP"))


def wide_rules(scope, parts, root, *, compact_outputs=False):
    """Return the membership/conservation result with the binding digest on altstack."""
    fixed(scope, 32)
    fixed(root, 32)
    context = (_compact_context_and_output_totals(parts) if compact_outputs else
               _take_tx_context(COUNT + 2, COUNT) + asm("OP_TOALTSTACK") + _output_totals(parts))
    return (
        context + asm("OP_FROMALTSTACK 72 OP_SPLIT OP_NIP OP_ROT OP_TOALTSTACK OP_SWAP OP_TOALTSTACK")
        + _input_totals_and_records(scope)
        + asm("OP_SWAP OP_FROMALTSTACK OP_NUMEQUALVERIFY OP_SWAP OP_DUP OP_0") + number(1 << 64)
        + asm("OP_WITHIN OP_VERIFY OP_FROMALTSTACK OP_NUMEQUALVERIFY OP_NIP")
        + multipath_script(WIDTH, COUNT) + push(root) + asm("OP_EQUALVERIFY OP_DEPTH OP_0 OP_NUMEQUAL")
    )


def wide_verifier_lock(scope, parts, root, *, compact_outputs=False):
    binding = compact_verifier_binding() if compact_outputs else bind_all_context()
    return wide_rules(scope, parts, root, compact_outputs=compact_outputs) + binding


def wide_witness(tx, scope, leaves, positions, output_states, *, compact_outputs=False, verifier_sats=None):
    """Indices follow token vin order; states of actual outputs are disclosed by their locks."""
    leaves, positions, output_states = tuple(leaves), tuple(positions), tuple(output_states)
    if len(leaves) != WIDTH or len(positions) != COUNT or len(tx.inputs) != COUNT + 2 or len(tx.outputs) != COUNT:
        raise ValueError("expected 64 token inputs, 64 successor outputs and 128 inventory leaves")
    if any(leaf.scope != scope for leaf in leaves) or len(output_states) != COUNT:
        raise ValueError("incorrect inventory scope or recipient state count")
    prefix = push(TOKEN_TAG + fixed(scope, 32)) + bytes([50])
    for txout, state in zip(tx.outputs, output_states, strict=True):
        if txout.value != state.sats or not txout.script.startswith(prefix + state.encode()):
            raise ValueError("wallet successor state differs from its actual transaction output")
    siblings = multi_path(leaves, positions)
    rows = b"".join(bytes([i]) + leaves[i].state.encode() for i in positions)
    witness = b"".join(push(item) for item in reversed(siblings)) + push(rows)
    if compact_outputs:
        if type(verifier_sats) is not int or not 0 <= verifier_sats < 2**64:
            raise ValueError("expected the satoshi amount of verifier vin 0")
        states = b"".join(state.encode() for state in output_states)
        prevouts = b"".join(txin.outpoint() for txin in tx.inputs)
        preimage = preimage_all(tx, 0, verifier_sats, COMPACT_SCRIPTCODE)
        return witness + push(states) + push(prevouts) + push(preimage)
    return witness + push(preimage_otda(tx, 0, COMPACT_SCRIPTCODE, CHRONICLE_ALL))
