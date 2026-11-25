"""One Two-Slot Lifecycle verifier for mint, ordinary transfer, freeze, unfreeze and burn."""

from dataclasses import dataclass
from functools import cached_property
from hashlib import sha256

from burn_receipt import BurnReceipt, SCRIPT_SIZE as BURN_SCRIPT_SIZE, burn_prefix
from checkpoint_verifier import _size
from covenant_backtrace import PROOF_FIELDS, _prevouts, _fixed_proof_script, _slice, fixed_proof_witness
from mimo_verifier import _pick, _split
from mint_events import compressed_key
from prepared_lifecycle_wire import (
    AUTH_BYTES, BODY_BYTES, BURN, CLAIM_BYTES, COMPACT_CODE, CONTEXT_BYTES, DOMAIN,
    HOLDER_BYTES, ISSUANCE, NO_BURN, NULL_OUTPUT, REMAINDER, STATE_BYTES, SUFFIX_BYTES,
    TOKEN_BYTES, TOKEN_END, TOKEN_GUARD, TOKEN_HEAD, State, event_output, read_state,
)
from public_inputs import verification_key_point
from route_a_funding import reconstruction_script
from regtest_support import approve
from settlement_checkpoint import (COMPANION_BYTES, FUNDING_HEAD, G_CONTEXT, MAX_PROGRAM, MIN_PROGRAM,
                                   META_BYTES, PREFIX_OVERHEAD, Opening, _funding_unlock, _padding, _prefix, _script_slot)
from shared.pushtx import binding_der
from shared.script import asm, number, push
from shared.transaction import Input, Transaction, amount, blob, compact, hash256, preimage_all
from spv_payment import verify_receipt
from statement import AssetDescriptor, fixed, uint
from transfer import _forkid_digest, digest_limbs_script, verifier_input_guard
from verifier import VerificationKey, locking_script, unlocking_fields


LIFECYCLE_LAYOUTS = ("literal", "templated", "shared", "prefix")
MAX_LITERAL_PROGRAM = 2 * MAX_PROGRAM


def _inactive_slot():
    return (
        asm("OP_DUP") + push(bytes(CLAIM_BYTES)) + asm("OP_EQUAL OP_IF OP_DROP") + push(bytes(META_BYTES))
        + asm("OP_ELSE") + push(b"\x02" + bytes(CLAIM_BYTES - 1)) + asm("OP_EQUALVERIFY")
        + push(b"\x02" + bytes(META_BYTES - 1)) + asm("OP_ENDIF")
    )


def _state_txout():
    return (
        asm("OP_OVER") + _slice(0, 1) + push(b"\0") + asm("OP_EQUAL OP_IF OP_2DROP")
        + push(NULL_OUTPUT.serialize()) + asm("OP_ELSE OP_SWAP")
        + push(amount(1000) + compact(TOKEN_BYTES) + TOKEN_HEAD) + asm("OP_SWAP OP_CAT")
        + push(TOKEN_GUARD) + asm("OP_CAT OP_SWAP OP_CAT") + push(TOKEN_END) + asm("OP_CAT OP_ENDIF")
    )


def _templated_state_txouts():
    """Expand both ordered state outputs using one set of constant script fields."""
    null = NULL_OUTPUT.serialize()
    zeros = TOKEN_BYTES - 5
    prefix = amount(1000) + compact(TOKEN_BYTES) + TOKEN_HEAD
    # The three fixed fields remain beneath each [state, policy] pair.
    one = (asm("OP_OVER") + _slice(0, 1) + push(b"\0") + asm("OP_EQUAL OP_IF OP_2DROP OP_2 OP_PICK")
           + asm("OP_ELSE OP_SWAP OP_3 OP_PICK OP_SWAP OP_CAT OP_2 OP_PICK OP_CAT OP_SWAP OP_CAT")
           + push(TOKEN_END) + asm("OP_CAT OP_ENDIF"))
    return (
        push(null[:-zeros]) + asm("OP_0") + number(zeros) + asm("OP_NUM2BIN OP_CAT")
        + push(prefix) + push(TOKEN_GUARD)
        + _pick(4) + _slice(2, STATE_BYTES) + _pick(4) + one + asm("OP_TOALTSTACK")
        + _pick(4) + _slice(2 + STATE_BYTES, STATE_BYTES) + _pick(4) + one
        + asm("OP_FROMALTSTACK OP_SWAP OP_CAT OP_NIP OP_NIP OP_NIP")
    )


def _burn_txout(asset):
    prefix = amount(0) + compact(BURN_SCRIPT_SIZE) + burn_prefix(asset.asset_id(), asset.reserve_domain)
    return (asm("OP_DUP") + _slice(0, 1) + push(bytes([BURN])) + asm("OP_EQUAL OP_IF")
            + _slice(168, 36) + push(prefix) + asm("OP_SWAP OP_CAT OP_ELSE OP_DROP")
            + push(NO_BURN.serialize()) + asm("OP_ENDIF"))


def _authorize_after_proof():
    # Altstack is [preimage digest, sigA||pubA||sigB||pubB].
    return (
        asm("OP_VERIFY OP_FROMALTSTACK OP_FROMALTSTACK") + binding_der() + push(b"\x41") + asm("OP_CAT OP_TOALTSTACK")
        + _split(104) + asm("OP_SWAP") + _split(71) + asm("OP_2 OP_ROLL") + _split(71)
        + asm("OP_CODESEPARATOR") + COMPACT_CODE
    )


def lifecycle_relation(asset, issuer, manager, *, max_program=MAX_PROGRAM, template_outputs=False):
    opening = _script_slot(REMAINDER, _inactive_slot(), max_program=max_program)
    state_txouts = (_templated_state_txouts() if template_outputs else
                    asm("OP_OVER") + _slice(2, STATE_BYTES) + asm("OP_OVER") + _state_txout()
                    + _pick(2) + _slice(2 + STATE_BYTES, STATE_BYTES) + _pick(2) + _state_txout() + asm("OP_CAT"))
    return (
        asm("OP_DUP") + _size(CONTEXT_BYTES) + _forkid_digest() + asm("OP_TOALTSTACK OP_OVER")
        + _size(144) + asm("OP_HASH256 OP_OVER") + _slice(4, 32) + asm("OP_EQUALVERIFY OP_OVER")
        + _slice(36, 36) + asm("OP_OVER") + _slice(68, 36) + asm("OP_EQUALVERIFY")
        + _slice(CONTEXT_BYTES - 40, 32) + asm("OP_TOALTSTACK") + _slice(72, 72)
        # [program, proof, auth, body, claims, policy, token outpoints]
        + _pick(2) + _size(2 * CLAIM_BYTES) + _split(CLAIM_BYTES)
        + _pick(PROOF_FIELDS + 7) + opening + asm("OP_SWAP")
        + _pick(PROOF_FIELDS + 7) + opening + asm("OP_SWAP OP_CAT OP_CAT")
        + _pick(3) + _size(BODY_BYTES) + asm("OP_CAT")
        + push(issuer + manager) + asm("OP_SWAP OP_CAT OP_OVER OP_SWAP OP_CAT")
        + push(DOMAIN + asset.issuance_outpoint) + asm("OP_SWAP OP_CAT OP_HASH256 OP_TOALTSTACK OP_NIP")
        # Rebuild both typed slots, the burn record and the issuance event record.
        + state_txouts
        + _pick(2) + _burn_txout(asset) + asm("OP_CAT")
        + _pick(2) + _slice(204, 32) + push(event_output(bytes(32)).serialize()[:-32])
        + asm("OP_SWAP OP_CAT OP_CAT OP_HASH256 OP_FROMALTSTACK OP_SWAP OP_FROMALTSTACK OP_EQUALVERIFY OP_NIP OP_TOALTSTACK")
        # Authenticate the two role signatures in the executing verifier vin.
        + _slice(102, 66) + asm("OP_SWAP") + _size(AUTH_BYTES)
        + asm("OP_DUP") + _slice(70, 1) + push(b"\x41") + asm("OP_EQUALVERIFY OP_DUP")
        + _slice(141, 1) + push(b"\x41") + asm("OP_EQUALVERIFY") + _split(71)
        + _pick(2) + _slice(33, 33) + asm("OP_CAT OP_SWAP")
        + _pick(2) + _slice(0, 33) + asm("OP_CAT OP_SWAP OP_CAT OP_NIP OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK")
        + number(PROOF_FIELDS + 1) + asm("OP_ROLL OP_DROP") + digest_limbs_script()
    )


@dataclass(frozen=True)
class Action:
    kind: int
    outputs: tuple[State, State]
    roles: tuple[bytes, bytes]
    mask: int = 0
    burn: BurnReceipt | None = None
    event: bytes = bytes(32)

    def encode(self):
        receipt = bytes(36) if self.burn is None else self.burn.output().script[-36:]
        return (uint(self.kind, 1) + uint(self.mask, 1) + b"".join(state.encode() for state in self.outputs)
                + b"".join(fixed(key, 33) for key in self.roles) + receipt + fixed(self.event, 32))


@dataclass(frozen=True)
class Previous:
    parent: Transaction
    vout: int
    source: Transaction | None = None

    @property
    def input(self):
        return Input(self.parent.txid_wire(), self.vout)


@dataclass(frozen=True)
class Policy:
    asset: AssetDescriptor
    key: VerificationKey
    issuer: bytes
    manager: bytes
    layout: str = "shared"

    def __post_init__(self):
        compressed_key(self.issuer)
        compressed_key(self.manager)
        if self.issuer == self.manager:
            raise ValueError("issuance and management authorities must be distinct")
        if self.layout not in LIFECYCLE_LAYOUTS:
            raise ValueError("unsupported lifecycle layout")

    @property
    def max_program(self):
        return MAX_LITERAL_PROGRAM if self.layout in ("literal", "templated") else MAX_PROGRAM

    @cached_property
    def verifier(self):
        engine = locking_script(self.key, None, projective_g1=True, projective_g2=True,
                                reuse_constants=True)[0]
        relation = lifecycle_relation(self.asset, self.issuer, self.manager, max_program=self.max_program,
                                      template_outputs=self.layout == "templated")
        return relation + _fixed_proof_script() + engine + _authorize_after_proof()

    @cached_property
    def companion(self):
        return verifier_input_guard(self.verifier, input_index=1) + asm("OP_1")

    @cached_property
    def digest(self):
        return sha256(blob(self.companion)).digest()

    @cached_property
    def program(self):
        field = blob(self.verifier)
        value = (push(field) if self.layout == "literal" else
                 reconstruction_script(field, share_fragments=self.layout != "prefix"))
        if not MIN_PROGRAM <= len(value) <= self.max_program:
            raise ValueError("verifier reconstruction outside lifecycle profile")
        return value

    def state(self, item):
        if item.source is None:
            if item.input.outpoint() == self.asset.issuance_outpoint:
                return State(ISSUANCE)
            return State()
        return read_state(item.parent.outputs[item.vout], self.digest)

    def opening(self, item):
        raw = item.parent.serialize()
        point = item.input.outpoint()
        if item.source is None:
            if point == self.asset.issuance_outpoint:
                return Opening(point, 0, bytes(CLAIM_BYTES), bytes(META_BYTES),
                               bytes(SUFFIX_BYTES + COMPANION_BYTES))
            if (item.vout != 0 or len(raw) != 167 or len(item.parent.inputs) != 1
                    or len(item.parent.outputs) != 1 or len(item.parent.outputs[0].script) != 35):
                raise ValueError("unsupported fee parent")
            return Opening(point, 0, b"\x02" + bytes(CLAIM_BYTES - 1), b"\x02" + bytes(META_BYTES - 1),
                           raw + bytes(SUFFIX_BYTES - len(raw) + COMPANION_BYTES))
        source = item.source
        if (len(item.parent.inputs) != 4 or len(item.parent.outputs) != 4 or item.vout not in (0, 1)
                or len(source.serialize()) != COMPANION_BYTES or source.outputs[0].script != self.companion
                or item.parent.inputs[0].outpoint() != Input(source.txid_wire(), 0).outpoint()):
            raise ValueError("different actual lifecycle companion or vout")
        state = self.state(item)
        script = item.parent.inputs[0].script
        stops = 2 + FUNDING_HEAD + len(self.program)
        source_point = item.parent.inputs[0].outpoint()
        claim = (b"\x01" + source_point + script[2:2 + FUNDING_HEAD]
                 + script[stops:] + item.parent.inputs[1].outpoint())
        prefix, padding = _prefix(claim, self.program, REMAINDER, max_program=self.max_program)
        processed = len(prefix) + len(padding)
        if (raw[:processed] != prefix + padding or len(raw) - processed != SUFFIX_BYTES
                or any(len(vin.script) != HOLDER_BYTES for vin in item.parent.inputs[2:])):
            raise ValueError("unsupported lifecycle parent serialization")
        metadata = b"\x01" + sha256(prefix).digest() + uint(processed, 4) + source_point
        return Opening(point, state.units, claim, metadata, raw[processed:] + source.serialize())

    def statement(self, openings, action):
        return (DOMAIN + self.asset.issuance_outpoint + self.digest + self.issuer + self.manager
                + b"".join(item.point for item in openings) + b"".join(item.meta for item in openings)
                + action.encode())

    def draft(self, companion, verifier, parents, action):
        outputs = tuple(state.output(self.digest) for state in action.outputs)
        record = action.burn.output() if action.burn is not None else NO_BURN
        return Transaction((Input(companion.txid_wire(), 0), Input(verifier.txid_wire(), 0),
                            *(item.input for item in parents)), (*outputs, record, event_output(action.event)))

    def verifier_digest(self, tx, verifier):
        return hash256(preimage_all(tx, 1, verifier.outputs[0].value, COMPACT_CODE))

    def witness(self, tx, companion, verifier, parents, action, proof, openings, role_signatures, input_signers):
        wire = self.statement(openings, action)
        proof_digest = hash256(wire)
        public = int.from_bytes(proof_digest[:16], "big"), int.from_bytes(proof_digest[16:], "big")
        point = verification_key_point(self.key.ic, public) or (0, 0)
        fields = (*point, *unlocking_fields(self.key, public, proof, projective_g1=True, projective_g2=True))
        prevouts = _prevouts(tx)
        authorization = b"".join(fixed(signature, 70) + b"\x41" for signature in role_signatures)
        args = (authorization, action.encode(), b"".join(item.claim for item in openings), self.digest, prevouts,
                preimage_all(tx, 1, verifier.outputs[0].value, COMPACT_CODE))
        remainder = fixed_proof_witness(fields) + b"".join(map(push, args))
        g_context = push(prevouts) + push(preimage_all(tx, 0, companion.outputs[0].value, self.companion))
        raw = verifier.serialize()
        head = raw[:-len(blob(self.verifier)) - 4]
        if len(head) != FUNDING_HEAD or len(g_context) != G_CONTEXT or len(remainder) != REMAINDER:
            raise ValueError("different lifecycle witness width")
        g_witness = _funding_unlock(head, self.program, raw[-4:], g_context)
        padding = _padding(2 * len(self.program) + PREFIX_OVERHEAD)
        full = tx.with_script(0, g_witness).with_script(1, push(self.program) + push(padding) + asm("OP_DROP") + remainder)
        for vin, (item, signer) in enumerate(zip(parents, input_signers, strict=True), 2):
            previous = item.parent.outputs[item.vout]
            if item.source is None:
                signature = approve(tx, vin, previous, signer)
                unlock = push(bytes(HOLDER_BYTES - len(signature) - 4)) + asm("OP_DROP") + signature
            else:
                program = reconstruction_script(companion.serialize())
                tail = push(prevouts) + push(preimage_all(tx, vin, previous.value, previous.script))
                padding = HOLDER_BYTES - len(program) - len(tail)
                if padding < 0:
                    raise ValueError("companion reconstruction exceeds lifecycle input width")
                unlock = program + asm("OP_NOP") * padding + tail
            if len(unlock) != HOLDER_BYTES:
                raise ValueError("noncanonical lifecycle input width")
            full = full.with_script(vin, unlock)
        return full

    def receive(self, chain, payment, parents, txid, vout, expected):
        def authenticate(tx, previous):
            if len(tx.inputs) != 4 or len(tx.outputs) != 4:
                return False
            guard, verifier = tx.inputs[:2]
            companion = previous[guard.txid]
            if (guard.vout != 0 or verifier.vout != 0 or companion.outputs[0].script != self.companion
                    or previous[verifier.txid].outputs[0].script != self.verifier):
                return False
            if vout in (0, 1) and expected != NULL_OUTPUT:
                self.opening(Previous(tx, vout, companion))
            return True

        return verify_receipt(chain, payment, parents, txid_wire=txid, vout=vout, expected_output=expected,
                              authenticate=authenticate, activation_height=2, minimum_confirmations=2)
