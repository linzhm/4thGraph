"""Bounded 2→2 experiment with a public Groth16 gate and Script backtrace."""

from dataclasses import dataclass
from functools import cached_property

from mimo_verifier import _split
from public_inputs import verification_key_point
from shared.script import asm, number, push
from shared.transaction import Output, amount, compact, hash256, preimage_all
from transfer import (COMPACT_SCRIPTCODE, compact_preimage_digest_script,
                      compact_verifier_binding, digest_limbs_script)
from verifier import VerificationKey, locking_script, unlocking_fields


DOMAIN = b"BSV/CCTP/parent-openings/v1\0"
ISSUANCE_AMOUNTS = (300, 200, 150)
TOKEN_SATS = 1_000
PROOF_FIELDS = 22
PROOF_BYTES = 48
MINT_BYTES = 903
PAYMENT_BYTES = 4075


def _slice(offset, size):
    return _split(offset) + asm("OP_NIP") + _split(size) + asm("OP_DROP")


def _unsigned():
    return push(b"\0") + asm("OP_CAT OP_BIN2NUM")


def _positive_quantity():
    return _unsigned() + asm("OP_DUP OP_0 OP_GREATERTHAN OP_VERIFY")


def _prevouts(tx):
    return b"".join(item.outpoint() for item in tx.inputs)


def parent_layout(raw):
    if len(raw) == MINT_BYTES:
        return 0
    if len(raw) == PAYMENT_BYTES:
        return 1
    raise ValueError("unsupported parent wire size")


def _current_prevouts():
    """Authenticate [prevouts, compact preimage]; defer native CHECKSIG."""
    return (
        asm("OP_DUP") + compact_preimage_digest_script() + asm("OP_DROP")
        + asm("OP_OVER OP_SIZE 108 OP_NUMEQUALVERIFY OP_HASH256 OP_OVER")
        + _slice(4, 32) + asm("OP_EQUALVERIFY")
    )


TOKEN_PREFIX = push(b"BSV/CCTP/covenant-token/v1\0") + asm("OP_DROP") + b"\x08"
TOKEN_QUANTITY_OFFSET = len(TOKEN_PREFIX)
TOKEN_OWNER_PREFIX = (
    asm("OP_DROP OP_DEPTH OP_3 OP_NUMEQUALVERIFY OP_ROT OP_SIZE 71 OP_NUMEQUALVERIFY "
        "OP_DUP OP_SIZE OP_1SUB OP_SPLIT OP_NIP")
    + push(b"\x41") + asm("OP_EQUALVERIFY") + b"\x21"
)
TOKEN_OWNER_OFFSET = TOKEN_QUANTITY_OFFSET + 8 + len(TOKEN_OWNER_PREFIX)
TOKEN_FUNDING_PREFIX = (
    asm("OP_CHECKSIGVERIFY") + _current_prevouts() + asm("OP_DROP") + _slice(0, 36) + _split(32)
    + _unsigned() + asm("OP_0 OP_2 OP_WITHIN OP_VERIFY") + b"\x20"
)
TOKEN_FUNDING_OFFSET = TOKEN_OWNER_OFFSET + 33 + len(TOKEN_FUNDING_PREFIX)
TOKEN_END = asm("OP_EQUAL") + compact_verifier_binding()
TOKEN_TEMPLATE = (TOKEN_PREFIX + bytes(8) + TOKEN_OWNER_PREFIX + bytes(33)
                  + TOKEN_FUNDING_PREFIX + bytes(32) + TOKEN_END)


def token_output(funding_txid, quantity, owner):
    if not 0 < quantity < 2**64 or len(owner) != 33 or owner[0] not in (2, 3) or len(funding_txid) != 32:
        raise ValueError("invalid token state")
    return Output(TOKEN_SATS, TOKEN_PREFIX + quantity.to_bytes(8, "little") + TOKEN_OWNER_PREFIX
                  + owner + TOKEN_FUNDING_PREFIX + funding_txid + TOKEN_END)


def token_state(output, funding_txid):
    script = output.script
    quantity = int.from_bytes(script[TOKEN_QUANTITY_OFFSET:TOKEN_QUANTITY_OFFSET + 8], "little")
    owner = script[TOKEN_OWNER_OFFSET:TOKEN_OWNER_OFFSET + 33]
    if token_output(funding_txid, quantity, owner) != output:
        raise ValueError("wrong token policy or output")
    return quantity, owner


def _state_bytes(output, funding_txid):
    quantity, owner = token_state(output, funding_txid)
    return quantity.to_bytes(8, "little") + owner


def _require_source(root_txid):
    """Consume one 78-byte claim, check its actual creation input and return units."""
    cases = b""
    for vout, quantity in enumerate(ISSUANCE_AMOUNTS[:-1]):
        cases += (
            asm("OP_DUP") + number(vout) + asm("OP_NUMEQUAL OP_IF OP_DROP OP_DUP")
            + push(quantity.to_bytes(8, "little")) + asm("OP_EQUALVERIFY OP_ELSE")
        )
    cases += (number(len(ISSUANCE_AMOUNTS) - 1) + asm("OP_NUMEQUALVERIFY OP_DUP")
              + push(ISSUANCE_AMOUNTS[-1].to_bytes(8, "little")) + asm("OP_EQUALVERIFY"))
    cases += asm("OP_ENDIF") * (len(ISSUANCE_AMOUNTS) - 1)
    return (
        asm("OP_DUP") + _slice(0, 1) + asm("OP_TOALTSTACK OP_DUP")
        + _slice(37, 8) + asm("OP_SWAP") + _slice(1, 36) + _split(32)
        + asm("OP_OVER") + push(root_txid) + asm("OP_EQUAL OP_IF OP_NIP")
        + asm("OP_FROMALTSTACK") + push(b"\0") + asm("OP_EQUALVERIFY")
        + _unsigned() + cases
        + asm("OP_ELSE OP_FROMALTSTACK OP_1 OP_EQUALVERIFY")
        + _unsigned() + asm("OP_0 OP_2 OP_WITHIN OP_VERIFY "
                            "OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_EQUALVERIFY OP_ENDIF")
        + _positive_quantity()
    )


def _build_output():
    """Rebuild a full ordered TxOut from [quantity8 || owner33]."""
    return (
        asm("OP_SIZE 41 OP_NUMEQUALVERIFY OP_DUP")
        + _slice(8, 1) + _unsigned() + asm("OP_2 OP_4 OP_WITHIN OP_VERIFY")
        + push(amount(TOKEN_SATS) + compact(len(TOKEN_TEMPLATE)) + TOKEN_PREFIX)
        + asm("OP_SWAP") + _split(8) + asm("OP_TOALTSTACK OP_CAT")
        + push(TOKEN_OWNER_PREFIX) + asm("OP_CAT OP_FROMALTSTACK OP_CAT")
        + push(TOKEN_FUNDING_PREFIX) + asm("OP_CAT OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CAT")
        + push(TOKEN_END) + asm("OP_CAT")
    )


def guard_script(root_txid):
    """Bind actual ordered slots, enforce backtrace and conservation, leave proof limbs."""
    return (
        _current_prevouts()
        # This executing verifier must be actual vin0. It exposes the funding txid
        # shared by the preceding and following canonical token outputs.
        + asm("OP_OVER") + _slice(0, 36) + asm("OP_OVER") + _slice(68, 36) + asm("OP_EQUALVERIFY OP_DUP")
        + _slice(152, 32) + asm("OP_TOALTSTACK") + _slice(68, 32) + asm("OP_TOALTSTACK")
        # [successors, claims, prevouts] -> [proof digest, successors, claims].
        + _slice(36, 72) + asm("OP_OVER OP_CAT OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_SWAP OP_CAT")
        + push(DOMAIN) + asm("OP_SWAP OP_CAT OP_HASH256 OP_ROT OP_ROT")
        + _split(78) + _require_source(root_txid) + asm("OP_SWAP") + _require_source(root_txid)
        + asm("OP_ADD OP_SWAP") + _split(41) + asm("OP_2DUP") + _slice(0, 8) + _positive_quantity()
        + asm("OP_SWAP") + _slice(0, 8) + _positive_quantity()
        + asm("OP_ADD OP_3 OP_ROLL OP_NUMEQUALVERIFY")
        + _build_output() + asm("OP_SWAP") + _build_output()
        + asm("OP_SWAP OP_CAT OP_HASH256 OP_FROMALTSTACK OP_DROP OP_FROMALTSTACK OP_EQUALVERIFY")
        + digest_limbs_script()
    )


def _fixed_proof_script():
    return (
        asm("OP_TOALTSTACK OP_TOALTSTACK")
        + (number(PROOF_FIELDS - 1) + asm("OP_ROLL OP_SIZE") + number(PROOF_BYTES)
           + asm("OP_NUMEQUALVERIFY OP_BIN2NUM")) * PROOF_FIELDS
        + asm("OP_FROMALTSTACK OP_FROMALTSTACK")
    )


@dataclass(frozen=True)
class Policy:
    root_txid: bytes
    key: VerificationKey

    @cached_property
    def lock(self):
        verification = locking_script(self.key, None, projective_g1=True, projective_g2=True,
                                      reuse_constants=True)[0]
        return guard_script(self.root_txid) + _fixed_proof_script() + verification + compact_verifier_binding()

    def claim(self, parent, vout, funding_txid):
        mode = parent_layout(parent.serialize())
        if type(vout) is not int or not 0 <= vout < len(parent.outputs) or (mode == 0 and vout != 0):
            raise ValueError("ineligible parent vout")
        return bytes([mode]) + parent.inputs[0].outpoint() + _state_bytes(parent.outputs[vout], funding_txid)

    def statement(self, funding_txid, parents):
        points = b"".join(parent.txid_wire() + vout.to_bytes(4, "little") for parent, vout in parents)
        claims = b"".join(self.claim(parent, vout, funding_txid) for parent, vout in parents)
        return DOMAIN + funding_txid + points + claims

    def material(self, tx, funding, parents):
        statement = self.statement(funding.txid_wire(), parents)
        if statement[len(DOMAIN) + 32:len(DOMAIN) + 104] != _prevouts(tx)[36:]:
            raise ValueError("opening outpoints differ from the actual token inputs")
        previous = funding.outputs[tx.inputs[0].vout]
        states = b"".join(_state_bytes(o, funding.txid_wire()) for o in tx.outputs)
        material = (states, statement[-156:], _prevouts(tx), preimage_all(tx, 0, previous.value, COMPACT_SCRIPTCODE))
        return statement, b"".join(map(push, material))

    def verifier_witness(self, tx, funding, parents, proof):
        statement, material = self.material(tx, funding, parents)
        digest = hash256(statement)
        public = int.from_bytes(digest[:16], "big"), int.from_bytes(digest[16:], "big")
        point = verification_key_point(self.key.ic, public) or (0, 0)
        fields = (*point, *unlocking_fields(self.key, public, proof, projective_g1=True, projective_g2=True))
        if len(fields) != PROOF_FIELDS:
            raise ValueError("expected the compact plain Groth16 layout")
        proof_wire = b"".join(push(value.to_bytes(PROOF_BYTES, "little")) for value in reversed(fields))
        return proof_wire + material


def holder_witness(tx, vin, previous, signer):
    digest = hash256(preimage_all(tx, vin, previous.value, previous.script))
    signature = signer(digest) + b"\x41"
    if len(signature) != 71:
        raise ValueError("fixture holder requires 70-byte DER")
    return push(signature) + push(_prevouts(tx)) + push(preimage_all(tx, vin, previous.value, COMPACT_SCRIPTCODE))
