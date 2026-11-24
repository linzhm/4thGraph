"""Bounded two-input inventory payment on Chronicle, with reusable origin proofs."""

from functools import lru_cache

from chronicle_context_script import bind_all_context
from chronicle_preimage import CHRONICLE_ALL
from chronicle_preimage_script import otda_all_fields
from mimo_verifier import _pick, _split, _unsigned
from shared.script import asm, number, push
from shared.transaction import Input, Output, blob, compact, hash256, preimage_all, preimage_otda
from transfer import (COMPACT_SCRIPTCODE, COMPACT_SUFFIX, authenticate_forkid_preimage, compact_preimage_digest_script,
                      compact_verifier_binding, digest_limbs_script, verifier_input_outpoint_guard)
from verifier import locking_script

TOKEN_TAG = b"BSV/CCTP/inventory-token/v1\x00"


def _slice(offset, size):
    return _split(offset) + asm("OP_NIP") + _split(size) + asm("OP_DROP")


def _check_width(size):
    return asm("OP_SIZE") + number(size) + asm("OP_NUMEQUALVERIFY")


def _one_of(values):
    return (asm("OP_0") + b"".join(asm("OP_OVER") + push(item) + asm("OP_EQUAL OP_BOOLOR")
                                    for item in values) + asm("OP_NIP OP_VERIFY"))


def token_parts(scope, coupons, *, input_count=4, compact_holder=False):
    """Coupons authorize the test issuer to create a one-use verifier companion."""
    if len(scope) != 32 or not coupons or any(len(item) != 36 for item in coupons):
        raise ValueError("invalid scope or issuer coupons")
    if type(input_count) is not int or input_count < 3:
        raise ValueError("expected a verifier, companion and token inputs")
    prefix = push(TOKEN_TAG + scope) + bytes([50])
    if compact_holder:
        # Save the compact binding digest first, then the owner above it. The
        # owner's CHECKSIG runs before CODESEPARATOR and signs the full token lock.
        context = (asm("OP_SWAP OP_DUP") + compact_preimage_digest_script()
                   + asm("OP_DROP OP_SWAP OP_TOALTSTACK"))
    else:
        context = asm("OP_TOALTSTACK OP_DUP") + authenticate_forkid_preimage() + asm("OP_DROP")
    body = (
        # sig, companion raw, prevouts, candidate preimage, tag, state
        asm("OP_NIP OP_DUP") + _slice(49, 1) + push(b"\x00") + asm("OP_EQUALVERIFY")
        + _slice(16, 33) + context + _slice(4, 32) + asm("OP_OVER") + _check_width(36 * input_count)
        + asm("OP_HASH256 OP_EQUALVERIFY") + _slice(36, 36)
        + asm("OP_OVER OP_HASH256") + push(bytes(4)) + asm("OP_CAT OP_EQUALVERIFY")
        + _split(4) + asm("OP_NIP OP_1 OP_SPLIT OP_SWAP") + push(b"\x01")
        + asm("OP_EQUALVERIFY 36 OP_SPLIT OP_DROP") + _one_of(coupons)
        + asm("OP_DEPTH OP_1 OP_NUMEQUALVERIFY OP_DUP OP_SIZE OP_1SUB OP_SPLIT OP_NIP")
        + push(b"\x41") + asm("OP_EQUALVERIFY OP_FROMALTSTACK OP_CHECKSIG")
    )
    if compact_holder:
        body += compact_verifier_binding()
    return prefix, body


def token_output(state, parts):
    prefix, body = parts
    return Output(state.sats, prefix + state.encode() + body)


def token_witness(tx, vin, previous, companion, signer, *, compact_holder=False):
    """Request the original full-lock owner signature; select only the PUSHTX material."""
    raw = preimage_all(tx, vin, previous.value, previous.script)
    if compact_holder and not previous.script.endswith(COMPACT_SUFFIX):
        raise ValueError("expected a token lock with a compact verifier suffix")
    binding = preimage_all(tx, vin, previous.value, COMPACT_SCRIPTCODE) if compact_holder else raw
    return b"".join(map(push, (signer(hash256(raw)) + b"\x41", companion.serialize(),
                               b"".join(i.outpoint() for i in tx.inputs), binding)))


def companion_lock(funding, *, input_count=4):
    ticket = Input(funding.txid_wire(), 0).outpoint()
    return (asm("OP_DEPTH OP_2 OP_NUMEQUALVERIFY")
            + verifier_input_outpoint_guard((ticket,), input_count=input_count, input_index=0) + asm("OP_1"))


def companion_witness(tx, companion):
    output = companion.outputs[0]
    return (push(b"".join(i.outpoint() for i in tx.inputs))
            + push(preimage_all(tx, 1, output.value, output.script)))


def _validate_state():
    # Positive uint64 quantity and carrier amount, compressed holder prefix, active state.
    return (_check_width(50) + asm("OP_DUP") + _slice(0, 8) + _unsigned() + asm("OP_0 OP_GREATERTHAN OP_VERIFY")
            + asm("OP_DUP") + _slice(8, 8) + _unsigned() + asm("OP_0 OP_GREATERTHAN OP_VERIFY OP_DUP")
            + _slice(16, 1) + _unsigned() + asm("OP_2 OP_4 OP_WITHIN OP_VERIFY OP_DUP")
            + _slice(49, 1) + push(b"\x00") + asm("OP_EQUALVERIFY"))


def _build_output(parts):
    prefix, body = parts
    return (
        _validate_state() + asm("OP_DUP") + _slice(8, 8) + push(compact(len(prefix) + 50 + len(body)) + prefix)
        + asm("OP_CAT OP_SWAP OP_CAT") + push(body) + asm("OP_CAT")
    )


def _branch(bit):
    # digest, sibling, index -> parent digest
    return (
        (asm("OP_2 OP_DIV") if bit else b"") + asm("OP_2 OP_MOD OP_IF OP_SWAP OP_ENDIF OP_CAT")
        + push(b"\x01") + asm("OP_SWAP OP_CAT OP_HASH256")
    )


def _membership(scope, depths):
    """Frame has root, then [index, sib0, sib1, state] twice, outputs, prevouts."""
    index, sib0, sib1, state, outpoint_offset = depths
    return (
        _pick(0) + _slice(outpoint_offset, 36) + push(b"\x00" + scope) + asm("OP_SWAP OP_CAT")
        + _pick(state + 1) + _validate_state() + asm("OP_CAT OP_HASH256")
        + _pick(sib0 + 1) + _check_width(32) + _pick(index + 2)
        + asm("OP_DUP OP_0 OP_4 OP_WITHIN OP_VERIFY") + _branch(0)
        + _pick(sib1 + 1) + _check_width(32) + _pick(index + 2) + _branch(1)
        + _pick(12) + asm("OP_EQUALVERIFY")
    )


def _take_tx_context(input_count=4, output_count=2):
    # Save type and digest for CHECKSIG after the proof verifier(s). Leave actual outputs below prevouts.
    return (push(bytes([CHRONICLE_ALL])) + asm("OP_TOALTSTACK OP_DUP OP_HASH256 OP_TOALTSTACK")
            + otda_all_fields(input_count, output_count, 0)
            + asm("OP_DROP OP_TOALTSTACK OP_2DROP OP_DROP OP_NIP OP_FROMALTSTACK OP_SWAP"))


def _origin_digest(anchor):
    return push(b"\x03" + anchor) + asm("OP_SWAP OP_CAT OP_HASH256")


def _sum_column(depth_a, depth_b, offset):
    return (_pick(depth_a) + _slice(offset, 8) + _unsigned()
            + _pick(depth_b + 1) + _slice(offset, 8) + _unsigned() + asm("OP_ADD"))


def payment_rules(scope, parts, *, private_membership):
    """Return source root and optional payment digest, with CHECKSIG context saved."""
    # B suffix [root, idx0,s00,s01,in0, idx1,s10,s11,in1, out0,out1, preimage].
    # C suffix [root,out0,out1,preimage]; Groth16 constrains private members and sums.
    script = _take_tx_context()
    # ... out0,out1, actualOutputs, prevouts. Check *all* serialized outputs.
    script += (_pick(3) + _build_output(parts) + _pick(3) + _build_output(parts)
               + asm("OP_CAT OP_2 OP_ROLL OP_EQUALVERIFY"))
    # ... out0,out1,prevouts. The two token outpoints must differ.
    script += asm("OP_DUP") + _slice(72, 36) + _pick(1) + _slice(108, 36) + asm("OP_EQUAL OP_NOT OP_VERIFY")
    if private_membership:
        # Derive H(02 || scope || root || vin2 || vin3 || out0 || out1).
        script += (asm("72 OP_SPLIT OP_NIP OP_3 OP_PICK") + push(b"\x02" + scope)
                   + asm("OP_SWAP OP_CAT OP_SWAP OP_CAT OP_2 OP_ROLL OP_CAT OP_SWAP OP_CAT OP_HASH256"))
    else:
        script += (_membership(scope, (10, 9, 8, 7, 72)) + _membership(scope, (6, 5, 4, 3, 108)))
        for offset in (0, 8):
            script += _sum_column(7, 3, offset)
            if offset == 0:
                script += asm("OP_DUP") + number(1 << 64) + asm("OP_LESSTHAN OP_VERIFY")
            script += _sum_column(3, 2, offset) + asm("OP_NUMEQUALVERIFY")
        script += asm("OP_DROP") + asm("OP_2DROP") * 5
    return script


@lru_cache(maxsize=4)
def proof_lock(key):
    return locking_script(key, None, projective_g1=True, projective_g2=True, reuse_constants=True)[0]


def verifier_lock(scope, parts, anchor, origin_key, *, payment_key=None):
    if len(anchor) != 32:
        raise ValueError("expected an approved inventory anchor")
    code = payment_rules(scope, parts, private_membership=payment_key is not None)
    if payment_key is not None:
        # Proof fields for payment are above origin fields. Preserve root while verifying payment.
        # The generic verifier checks exact main-stack depth at entry. Keep all
        # 22 origin witness fields below the payment frame on the alternate stack.
        fields = 22  # two IC coordinates, A/B/C (8), and the Fp12 residue (12)
        code += (asm("OP_SWAP OP_TOALTSTACK")
                 + (number(fields + 1) + asm("OP_ROLL OP_TOALTSTACK")) * fields
                 + digest_limbs_script() + proof_lock(payment_key) + asm("OP_VERIFY")
                 + asm("OP_FROMALTSTACK") * (fields + 1))
    return code + _origin_digest(anchor) + digest_limbs_script() + proof_lock(origin_key) + bind_all_context()


def verifier_witness(tx, root, origin_witness, outputs, *, openings=(), payment_witness=None):
    if len(openings) != (0 if payment_witness is not None else 2):
        raise ValueError("provide exactly two public openings or one payment proof")
    frame = push(root)
    for index, siblings, state in openings:
        frame += number(index) + b"".join(map(push, siblings)) + push(state.encode())
    frame += b"".join(push(state.encode()) for state in outputs)
    return origin_witness + (payment_witness or b"") + frame + push(preimage_otda(tx, 0, COMPACT_SCRIPTCODE, CHRONICLE_ALL))
