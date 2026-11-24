"""Script transaction relation for bounded, guarded CCTP transfers.

The shared verifier derives the circuit's slots from authenticated transaction
bytes. This component validates parent content and transitions. Recursive
provenance must separately establish that each parent issued the selected vout.
"""
from dataclasses import dataclass

from burn_receipt import burn_prefix, read_burn
from public_inputs import verification_key_point
from shared.script import asm, number, push
from shared.transaction import preimage_all
from statement import Slot, fixed, public_inputs, transfer_bytes, uint
from transaction_relation import TokenState
from transaction_verifier import verifier_key_id, verifier_lock
from transfer import COMPACT_SCRIPTCODE
from verifier import unlocking_fields, unlocking_script
from operational_token import TokenPolicy, TOKEN_MARKER

MAX_PARENT_INPUTS = 4
MAX_PARENT_OUTPUTS = 4
QUANTITY_OFFSET = len(TOKEN_MARKER) + 1 + 32


def _split(offset):
    return number(offset) + asm("OP_SPLIT")


def _pick(depth):
    return number(depth) + asm("OP_PICK")


def _unsigned():
    return push(b"\x00") + asm("OP_CAT OP_BIN2NUM")


def _compact_size():
    """Split a canonical CompactSize out of the current cursor; leave rest, n."""
    return (
        asm("OP_1 OP_SPLIT OP_SWAP") + _unsigned() + asm("OP_DUP 253 OP_LESSTHAN OP_NOTIF")
        + asm("OP_DUP 253 OP_NUMEQUAL OP_IF OP_DROP OP_2 OP_SPLIT OP_SWAP") + _unsigned()
        + asm("OP_DUP 252 OP_GREATERTHAN OP_VERIFY OP_ELSE")
        + asm("254 OP_NUMEQUALVERIFY OP_4 OP_SPLIT OP_SWAP") + _unsigned()
        + asm("OP_DUP 65535 OP_GREATERTHAN OP_VERIFY OP_ENDIF OP_ENDIF")
    )


def _take_output_script():
    return _split(8) + asm("OP_NIP") + _compact_size() + asm("OP_SPLIT")


def _select_parent_output():
    # Before parsing: [raw parent, vout]. The actual parent txid was checked.
    skip_input = (
        asm("OP_DUP OP_0NOTEQUAL OP_IF OP_SWAP") + _split(36) + asm("OP_NIP")
        + _compact_size() + asm("OP_SPLIT OP_NIP OP_4 OP_SPLIT OP_NIP OP_SWAP OP_1SUB OP_ENDIF")
    )
    skip_output = (
        asm("OP_DUP OP_0NOTEQUAL OP_IF OP_SWAP") + _take_output_script()
        + asm("OP_NIP OP_SWAP OP_1SUB OP_ENDIF")
    )
    return (
        asm("OP_TOALTSTACK OP_4 OP_SPLIT OP_NIP") + _compact_size()
        + asm(f"OP_DUP 1 {MAX_PARENT_INPUTS + 1} OP_WITHIN OP_VERIFY")
        + skip_input * MAX_PARENT_INPUTS + asm("OP_0 OP_NUMEQUALVERIFY")
        + _compact_size() + asm(f"OP_DUP 1 {MAX_PARENT_OUTPUTS + 1} OP_WITHIN OP_VERIFY")
        + asm("OP_FROMALTSTACK OP_TUCK OP_GREATERTHAN OP_VERIFY")
        + skip_output * (MAX_PARENT_OUTPUTS - 1)
        + asm("OP_0 OP_NUMEQUALVERIFY") + _take_output_script() + asm("OP_DROP")
    )


def _match_prefix(prefix):
    if not prefix:
        return b""
    return _split(len(prefix)) + asm("OP_SWAP") + push(prefix) + asm("OP_EQUALVERIFY")


def _parse_active_token(asset_id, freeze_key, guards):
    """Check the exact v2 script with local owner/amount and inherited guard set."""
    locks = tuple(b"CCTP template placeholder " + bytes([i]) for i in range(guards))
    policy = TokenPolicy(locks, freeze_key)
    owner = b"\x02" + bytes(range(32))
    template = policy.lock(TokenState(asset_id, 1, owner))
    guard_offsets = [template.index(digest) for digest in policy.verifier_hashes()]
    owner_offset = QUANTITY_OFFSET + 8
    # The final 33-byte pubkey push precedes CHECKSIG and ENDIF.
    owner_tail = len(template) - 35
    assert template[owner_tail:owner_tail + 33] == owner
    assert sorted(guard_offsets) == guard_offsets

    check = (
        asm("OP_SIZE") + number(len(template)) + asm("OP_NUMEQUALVERIFY")
        + _match_prefix(template[:QUANTITY_OFFSET])
        + _split(8) + asm("OP_SWAP OP_TOALTSTACK")
        + _split(33) + asm("OP_SWAP OP_DUP OP_1 OP_SPLIT OP_DROP") + _unsigned()
        + asm("2 4 OP_WITHIN OP_VERIFY OP_SWAP")
        + _match_prefix(template[owner_offset + 33:guard_offsets[0]])
        + asm("OP_0 OP_SWAP")
    )
    cursor = guard_offsets[0]
    for offset in guard_offsets:
        check += (
            _match_prefix(template[cursor:offset])
            + _split(32) + asm("OP_ROT OP_ROT OP_CAT OP_SWAP")
        )
        cursor = offset + 32
    return (
        check + _match_prefix(template[cursor:owner_tail])
        + _split(33) + push(template[owner_tail + 33:]) + asm("OP_EQUALVERIFY")
        + asm("OP_ROT OP_EQUALVERIFY OP_FROMALTSTACK OP_SWAP")
    )


def _append_slot(index, *, first=False):
    """Merge [slots, policy, quantity, current policy] for this exact index."""
    policy = asm("OP_ROT OP_DROP") if first else asm("OP_2 OP_PICK OP_EQUALVERIFY OP_SWAP")
    return (policy + asm("OP_TOALTSTACK") + push(uint(index, 4))
            + asm("OP_SWAP OP_CAT OP_CAT OP_FROMALTSTACK"))


@dataclass(frozen=True)
class MimoProfile:
    incoming: int
    outgoing: int
    guards: int
    freeze_key: bytes
    burn: bool = False

    @property
    def flow_outputs(self):
        return self.outgoing + int(self.burn)

    def __post_init__(self):
        if type(self.incoming) is not int or not 1 <= self.incoming <= 2:
            raise ValueError("expected one or two token inputs")
        if type(self.burn) is not bool:
            raise ValueError("expected boolean burn mode")
        if type(self.outgoing) is not int or not (0 if self.burn else 1) <= self.outgoing <= 2:
            raise ValueError("incorrect token output count")
        if type(self.guards) is not int or not 1 <= self.guards <= 8:
            raise ValueError("expected one to eight approved verifier locks")
        fixed(self.freeze_key, 33)

    def relation(self, asset_id, reserve_domain=None, *, keep_parents=False):
        """Derive [slots, preimage] above the proof stack.

        Witness order above proof: parent raws in vin order (excluding vin 0),
        serialized outputs, serialized prevouts, and the compact preimage.
        With keep_parents, leave the authenticated parent raws below the result.
        """
        parse = _parse_active_token(asset_id, self.freeze_key, self.guards)
        code = (
            asm("OP_SIZE 192 OP_NUMEQUALVERIFY OP_DUP OP_TOALTSTACK")
            + asm("OP_DUP OP_4 OP_SPLIT OP_NIP 32 OP_SPLIT OP_DROP")
            + _pick(2) + asm("OP_HASH256 OP_EQUALVERIFY")
            + _split(152) + asm("OP_NIP 32 OP_SPLIT OP_DROP")
            + _pick(2) + asm("OP_HASH256 OP_EQUALVERIFY")
            + asm("OP_SIZE") + number(36 * (self.incoming + 1)) + asm("OP_NUMEQUALVERIFY")
            + asm("OP_FROMALTSTACK OP_DUP OP_TOALTSTACK")
            + _split(68) + asm("OP_NIP 36 OP_SPLIT OP_DROP OP_OVER 36 OP_SPLIT OP_DROP OP_EQUALVERIFY")
            + push(uint(self.incoming, 2)) + asm("OP_0")
        )
        for i in range(self.incoming):
            depth = self.incoming + 3 - i
            code += (
                _pick(depth) + _pick(3) + _split(36 * (i + 1)) + asm("OP_NIP")
                + _split(36) + asm("OP_DROP 32 OP_SPLIT OP_TOALTSTACK OP_OVER OP_HASH256 OP_EQUALVERIFY")
                + asm("OP_FROMALTSTACK") + _unsigned() + _select_parent_output()
                + parse + _append_slot(i + 1, first=i == 0)
            )
        code += (asm("OP_SWAP") + push(uint(self.flow_outputs, 2)) + asm("OP_CAT OP_SWAP")
                 + _pick(3) + asm("OP_TOALTSTACK"))
        for i in range(self.outgoing):
            code += (asm("OP_FROMALTSTACK") + _take_output_script() + asm("OP_TOALTSTACK")
                     + parse + _append_slot(i))
        if self.burn:
            code += (
                asm("OP_FROMALTSTACK") + _match_prefix(bytes(8))
                + _compact_size() + asm("OP_SPLIT OP_TOALTSTACK")
                + _match_prefix(burn_prefix(asset_id, reserve_domain))
                + _split(20) + asm("OP_SWAP") + push(bytes(20)) + asm("OP_EQUAL OP_NOT OP_VERIFY")
                + _split(8) + asm("OP_OVER") + _unsigned() + asm("OP_SWAP") + _unsigned()
                + asm("OP_GREATERTHAN OP_VERIFY OP_OVER") + _append_slot(self.outgoing)
            )
        return (
            code + asm("OP_FROMALTSTACK OP_SIZE OP_0 OP_NUMEQUALVERIFY OP_2DROP OP_TOALTSTACK")
            + asm("OP_DROP") * (2 if keep_parents else self.incoming + 2)
            + asm("OP_FROMALTSTACK OP_FROMALTSTACK")
        )

    def lock(self, asset, key):
        return self.relation(asset.asset_id(), asset.reserve_domain) + verifier_lock(asset, key)

    def witness(self, asset, key, proof, tx, parents, policy):
        """Build witnesses for the current proof and the shared relation."""
        if len(tx.inputs) != self.incoming + 1 or len(tx.outputs) != self.flow_outputs:
            raise ValueError("incorrect transaction shape")
        if (len(parents) != len(tx.inputs) or len(policy.verifier_locks) != self.guards
                or policy.freeze_key != self.freeze_key):
            raise ValueError("incorrect parents or policy")
        policy.selected_verifier(tx, parents[0].serialize())
        lock = self.lock(asset, key)
        if parents[0].outputs[0].script != lock:
            raise ValueError("unexpected verifier for this profile")
        slots = []
        for index, (txin, parent) in enumerate(zip(tx.inputs[1:], parents[1:], strict=True), 1):
            if (txin.txid != parent.txid_wire() or not 0 <= txin.vout < len(parent.outputs)
                    or not 1 <= len(parent.inputs) <= MAX_PARENT_INPUTS
                    or not 1 <= len(parent.outputs) <= MAX_PARENT_OUTPUTS):
                raise ValueError("incorrect token parent or vout")
            slots.append(Slot(index, _active_quantity(asset, policy, parent.outputs[txin.vout].script)))
        outputs = tuple(Slot(index, _active_quantity(asset, policy, output.script))
                        for index, output in enumerate(tx.outputs[:self.outgoing]))
        if self.burn:
            receipt = read_burn(tx, self.outgoing, asset)
            outputs += (Slot(self.outgoing, receipt.quantity),)
        statement = transfer_bytes(asset, verifier_key_id(key), tx, parents[0], lock,
                                   tuple(slots), outputs, script_code=COMPACT_SCRIPTCODE)
        return self.witness_material(key, proof, public_inputs(statement), tx, parents)

    def witness_material(self, key, proof, signals, tx, parents):
        point = verification_key_point(key.ic, signals) or (0, 0)
        fields = unlocking_fields(key, signals, proof, projective_g1=True, projective_g2=True)
        material = tuple(parent.serialize() for parent in parents[1:])
        outputs = b"".join(output.serialize() for output in tx.outputs)
        prevouts = b"".join(txin.outpoint() for txin in tx.inputs)
        preimage = preimage_all(tx, 0, parents[0].outputs[0].value, COMPACT_SCRIPTCODE)
        return unlocking_script((*point, *fields)) + b"".join(
            push(part) for part in (*material, outputs, prevouts, preimage)
        )


def _active_quantity(asset, policy, script):
    state = policy.parse(script)
    if state is None or state.asset_id != asset.asset_id() or state.frozen:
        raise ValueError("incorrect active token")
    return state.quantity
