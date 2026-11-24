"""One-use inventory ticket carrying the authorized verifier outpoint.

The authorized coupon funds one ticket output. Each holder authenticates this
funding transaction through actual vin 1, then checks its metadata against
actual vin 0. The wallet controls the ticket with an ordinary P2PK signature.
"""

from os.path import commonprefix

from inventory_payment import _check_width, _one_of, _slice, bound_token_parts, holder_authorization, token_witness
from mimo_verifier import _match_prefix, _split, _unsigned
from shared.script import asm, number, push
from shared.transaction import Input, hash256, preimage_all


def ticket_lock(verifier, ticket_key, *, verifier_vout=0):
    if len(ticket_key) != 33 or ticket_key[0] not in (2, 3):
        raise ValueError("expected a compressed ticket key")
    if not 0 <= verifier_vout < len(verifier.outputs):
        raise ValueError("verifier vout is outside the funding transaction")
    approved = Input(verifier.txid_wire(), verifier_vout).outpoint()
    return push(approved) + asm("OP_DROP") + push(ticket_key) + asm("OP_CHECKSIG")


def ticket_witness(tx, ticket_funding, signer):
    if (len(tx.inputs) < 2 or len(ticket_funding.outputs) != 1 or
            tx.inputs[1].outpoint() != Input(ticket_funding.txid_wire(), 0).outpoint()):
        raise ValueError("ticket funding differs from the actual vin 1")
    ticket = ticket_funding.outputs[0]
    digest = hash256(preimage_all(tx, 1, ticket.value, ticket.script))
    return push(signer(digest) + b"\x41")


def _funding_fields(coupons, *, return_verifier):
    # The test funding has one input with a one-byte CompactSize for the
    # issuer's scriptSig. Follow that length to the actual output count.
    funding = (
        _split(4) + asm("OP_NIP") + _match_prefix(b"\x01") + _split(36) + asm("OP_SWAP") + _one_of(coupons)
        + asm("OP_1 OP_SPLIT OP_SWAP") + _unsigned()
        + asm("OP_DUP 253 OP_LESSTHAN OP_VERIFY OP_SPLIT OP_NIP")
        + _split(4) + asm("OP_NIP") + _match_prefix(b"\x01") + _split(8) + asm("OP_NIP")
    )
    # output script length, canonical direct W push, actual W, DROP, key
    # push, compressed key, CHECKSIG and exactly four transaction locktime bytes.
    # In the full-vector path compare with the actual W already on altstack.
    # The compact path returns W after validating the remainder of the output.
    select = asm("OP_SWAP OP_TOALTSTACK") if return_verifier else asm("OP_SWAP OP_FROMALTSTACK OP_EQUALVERIFY")
    output = (
        _match_prefix(bytes([73, 36])) + _split(36) + select
        + _match_prefix(asm("OP_DROP") + bytes([33])) + _split(33)
        + asm("OP_SWAP OP_1 OP_SPLIT OP_DROP") + _unsigned() + asm("OP_2 OP_4 OP_WITHIN OP_VERIFY")
        + _match_prefix(asm("OP_CHECKSIG")) + _check_width(4) + asm("OP_DROP")
    )
    return funding + output + (asm("OP_FROMALTSTACK") if return_verifier else b"")


def _open_ticket(coupons):
    # [owner signature, ticket funding raw, authenticated prevouts]. Save W,
    # then tie the funding bytes to the real ticket at vin 1, vout zero.
    return (
        asm("OP_DUP") + _split(36) + asm("OP_DROP OP_TOALTSTACK")
        + _slice(36, 36) + asm("OP_OVER OP_HASH256") + push(bytes(4)) + asm("OP_CAT OP_EQUALVERIFY")
        + _funding_fields(coupons, return_verifier=False)
    )


def ticket_token_parts(scope, coupons, *, input_count=66, derive_prevouts=False):
    if not coupons or any(len(item) != 36 for item in coupons):
        raise ValueError("expected a nonempty list of issuer coupon outpoints")
    if not derive_prevouts:
        return bound_token_parts(scope, input_count, _open_ticket(coupons), compact_holder=True)
    # [sig, ticket raw, token outpoints] -> [sig, W || ticket:0 || token outpoints].
    # The common holder script authenticates this exact byte string by length
    # and hashPrevouts before checking either native signature.
    restore = (
        asm("OP_TOALTSTACK OP_DUP OP_HASH256") + push(bytes(4)) + asm("OP_CAT OP_SWAP")
        + _funding_fields(coupons, return_verifier=True)
        + asm("OP_SWAP OP_CAT OP_FROMALTSTACK OP_CAT")
    )
    return bound_token_parts(scope, input_count, asm("OP_DROP"), compact_holder=True, restore_prevouts=restore)


def ticket_token_witness(tx, vin, previous, companion, signer, *, derive_prevouts=False):
    return token_witness(tx, vin, previous, companion, signer, compact_holder=True,
                         prevout_start=2 if derive_prevouts else 0)


def _ticket_input_prefix(coupons):
    """Select an approved outpoint by index, emitting the common prefix once."""
    if not coupons or any(type(item) is not bytes or len(item) != 36 for item in coupons):
        raise ValueError("expected a nonempty list of issuer coupon outpoints")
    if len(set(coupons)) != len(coupons):
        raise ValueError("issuer coupon outpoints must be distinct")
    prefix = b"\x02\x00\x00\x00\x01"
    if len(coupons) == 1:
        return asm("OP_0 OP_NUMEQUALVERIFY") + push(prefix + coupons[0])
    common = commonprefix(coupons)
    suffix_size = 36 - len(common)
    suffixes = b"".join(coupon[len(common):] for coupon in coupons)
    return (
        asm("OP_DUP OP_0") + number(len(coupons)) + asm("OP_WITHIN OP_VERIFY")
        + number(suffix_size) + asm("OP_MUL") + push(suffixes) + asm("OP_SWAP OP_SPLIT OP_NIP")
        + _split(suffix_size) + asm("OP_DROP") + push(prefix + common) + asm("OP_SWAP OP_CAT")
    )


def template_ticket_token_parts(scope, coupons, *, input_count=66):
    """Rebuild the actual 1x1 coupon spend from its variable fields.

    V2, max sequence, zero locktime, canonical bare P2PK coupon signature and
    ticket output format are fixed. The coupon identity, W, destination key,
    carrier amount and issuer DER signature are selected per ticket.
    """
    # [holder sig, key, W, sats, issuer DER, coupon index, token outpoints].
    # The DER byte length is 8..72. Within this range NUM2BIN is unnecessary
    # for the two consecutive single-byte wire lengths of the direct push.
    restore = (
        asm("OP_TOALTSTACK") + _ticket_input_prefix(tuple(coupons))
        + asm("OP_SWAP OP_SIZE OP_DUP OP_8 73 OP_WITHIN OP_VERIFY"
              " OP_1ADD OP_DUP OP_1ADD OP_SWAP OP_CAT OP_SWAP OP_CAT OP_CAT")
        + push(b"\x41" + b"\xff" * 4 + b"\x01") + asm("OP_CAT OP_SWAP OP_8 OP_NUM2BIN OP_CAT")
        + push(bytes([73, 36])) + asm("OP_CAT OP_OVER") + _check_width(36) + asm("OP_CAT")
        + push(asm("OP_DROP") + bytes([33])) + asm("OP_CAT OP_2 OP_PICK") + _check_width(33)
        + asm("OP_DUP OP_1 OP_SPLIT OP_DROP") + _unsigned() + asm("OP_2 OP_4 OP_WITHIN OP_VERIFY OP_CAT")
        + push(asm("OP_CHECKSIG") + bytes(4)) + asm("OP_CAT OP_HASH256")
        + push(bytes(4)) + asm("OP_CAT OP_CAT OP_NIP OP_FROMALTSTACK OP_CAT")
    )
    return bound_token_parts(scope, input_count, asm("OP_DROP"), compact_holder=True, restore_prevouts=restore)


def template_ticket_token_witness(tx, vin, previous, companion, signer, coupons):
    """Sign the actual tx and disclose the nominated ticket's variable fields.

    The holder lock checks both the verifier and the ticket against the real
    hashPrevouts, including when a candidate nominates a different ticket.
    """
    if (companion.version != 2 or companion.locktime != 0 or len(companion.inputs) != 1
            or len(companion.outputs) != 1 or companion.inputs[0].sequence != 0xffffffff):
        raise ValueError("expected the v2 ticket profile with final sequence and zero locktime")
    issue_input = companion.inputs[0]
    coupon_index = tuple(coupons).index(issue_input.outpoint())
    issuer_der = issue_input.script[1:-1]
    if not 8 <= len(issuer_der) <= 72 or issue_input.script != push(issuer_der + b"\x41"):
        raise ValueError("expected the coupon's canonical single ForkID ALL signature")
    ticket = companion.outputs[0]
    key = ticket.script[39:72]
    verifier = ticket.script[1:37]
    if (len(key) != 33 or key[0] not in (2, 3) or
            ticket.script != push(verifier) + asm("OP_DROP") + push(key) + asm("OP_CHECKSIG")):
        raise ValueError("expected the canonical ticket locking script")
    signature, binding = holder_authorization(tx, vin, previous, signer, compact_holder=True)
    tail = b"".join(i.outpoint() for i in tx.inputs[2:])
    return (push(signature) + push(key) + push(verifier) + number(ticket.value) + push(issuer_der)
            + number(coupon_index) + push(tail) + push(binding))
