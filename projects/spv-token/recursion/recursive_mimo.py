"""Bind an outer BSB22 proof to two concrete split parents and a 2→2 spend.

This profile checks two independently proved 1→2 steps. It does not take
proofs of its own profile as predecessors.
"""
from dataclasses import dataclass

from committed_verifier import CommitmentRelation, RECURSION_DOMAIN, recursive_digest_script, verifier_fields
from committed_verifier import verifier_lock as committed_lock
from descriptor import VerifierDescriptor
from mimo_verifier import MimoProfile, _parse_active_token, _select_parent_output, _split, _unsigned
from parent_preimage import predecessor_statement_digest, verifier_funding_script_hash
from shared.script import asm, number, push
from shared.transaction import hash256, preimage_all
from statement import TRANSFER_DOMAIN, Slot, public_inputs, transfer_bytes, uint
from transaction_verifier import verifier_key_id
from transfer import COMPACT_SCRIPTCODE, compact_preimage_digest_script, compact_verifier_binding
from verifier import VerificationKey, unlocking_script

MAX_QUANTITY = 2**64 - 1
KEY_DOMAIN = b"BSV/CCTP/recursion-key/v1\0"


def recursive_key_id(key, relation):
    """Identify both the outer Groth16 and single-commitment parameters."""
    points = b"".join(
        uint(value, 48)
        for point in (relation.generator, relation.sigma_neg)
        for coefficient in point
        for value in coefficient
    )
    return hash256(KEY_DOMAIN + VerifierDescriptor(key, (0, 0, 0)).encode() + points)


def _add_quantities(offsets):
    code = asm("OP_0")
    for offset in offsets:
        code += (asm("OP_OVER") + _split(offset) + asm("OP_NIP OP_8 OP_SPLIT OP_DROP")
                 + _unsigned() + asm("OP_DUP OP_0NOTEQUAL OP_VERIFY OP_ADD"))
    return code


def _assert_u64():
    return asm("OP_DUP") + number(MAX_QUANTITY) + asm("OP_GREATERTHAN OP_NOT OP_VERIFY")


def _conserve_child_slots():
    """Preserve exactly two input and two output slots, enforcing live supply."""
    return (
        _add_quantities((6, 18)) + _assert_u64() + asm("OP_TOALTSTACK")
        + _add_quantities((32, 44)) + asm("OP_FROMALTSTACK OP_NUMEQUALVERIFY")
    )


@dataclass(frozen=True)
class SplitLeaf:
    key: VerificationKey
    profile: MimoProfile

    def __post_init__(self):
        if (self.profile.incoming, self.profile.outgoing, self.profile.burn) != (1, 2, False):
            raise ValueError("expected a 1→2 split predecessor profile")

    def statement_script(self, asset):
        """Rebuild a leaf's proof statement from its authenticated transaction."""
        asset_id = asset.asset_id()
        parse = _parse_active_token(asset_id, self.profile.freeze_key, self.profile.guards)
        lock_hash = verifier_funding_script_hash(self.profile.lock(asset, self.key))
        # The leaf circuit equates outgoing amounts to the input amount.
        return (
            asm("OP_OVER OP_DUP OP_0") + _select_parent_output() + parse + asm("OP_DROP OP_SWAP OP_1")
            + _select_parent_output() + parse + asm("OP_DROP OP_2DUP") + _unsigned() + asm("OP_SWAP")
            + _unsigned() + asm("OP_ADD") + _assert_u64() + asm("9 OP_NUM2BIN OP_8 OP_SPLIT OP_DROP")
            + push(uint(1, 2) + uint(1, 4)) + asm("OP_SWAP OP_CAT")
            + push(uint(2, 2) + uint(0, 4)) + asm("OP_CAT OP_ROT OP_CAT")
            + push(uint(1, 4)) + asm("OP_CAT OP_SWAP OP_CAT OP_ROT OP_ROT")
            + predecessor_statement_digest(asset_id, verifier_key_id(self.key), lock_hash)
        )

    def statement(self, asset, policy, transaction, funding):
        if len(transaction.inputs) != 2 or len(transaction.outputs) != 2 or transaction.inputs[0].vout != 0:
            raise ValueError("incorrect split predecessor shape")
        outputs = _slots(asset, policy, transaction.outputs, first=0)
        quantity = sum(slot.quantity for slot in outputs)
        return transfer_bytes(asset, verifier_key_id(self.key), transaction, funding,
                              self.profile.lock(asset, self.key), (Slot(1, quantity),), outputs,
                              script_code=COMPACT_SCRIPTCODE)


def _slots(asset, policy, outputs, *, first):
    asset_id = asset.asset_id()
    slots = []
    for i, output in enumerate(outputs, first):
        state = policy.parse(output.script)
        if state is None or state.asset_id != asset_id or state.frozen:
            raise ValueError("expected active canonical token output")
        slots.append(Slot(i, state.quantity))
    return tuple(slots)


@dataclass(frozen=True)
class RecursiveMimo:
    leaf: SplitLeaf
    key: VerificationKey
    knowledge_relation: CommitmentRelation

    @property
    def profile(self):
        leaf = self.leaf.profile
        return MimoProfile(2, 2, leaf.guards, leaf.freeze_key)

    def statement_script(self, asset):
        identity = TRANSFER_DOMAIN + asset.asset_id() + recursive_key_id(self.key, self.knowledge_relation)
        leaf = self.leaf.statement_script(asset)
        return (
            self.profile.relation(asset.asset_id(), keep_parents=True)
            + asm("OP_SWAP") + _conserve_child_slots() + asm("OP_SWAP")
            + compact_preimage_digest_script()
            + push(identity) + asm("OP_SWAP OP_CAT OP_SWAP OP_CAT OP_HASH256 OP_TOALTSTACK")
            # [funding0, funding1, parent0, parent1] -> [parent1, funding1, parent0, funding0]
            + asm("OP_2 OP_ROLL OP_2SWAP OP_SWAP") + leaf + asm("OP_TOALTSTACK") + leaf
            + asm("OP_FROMALTSTACK OP_SWAP OP_FROMALTSTACK") + recursive_digest_script()
        )

    def lock(self, asset):
        return self.statement_script(asset) + committed_lock(self.key, self.knowledge_relation) + compact_verifier_binding()

    def statements(self, asset, policy, transaction, verifier_parent, parents, funders):
        if len(transaction.inputs) != 3 or len(transaction.outputs) != 2 or len(parents) != 2 or len(funders) != 2:
            raise ValueError("incorrect recursive MIMO shape")
        if parents[0].txid_wire() == parents[1].txid_wire() or transaction.inputs[0].vout != 0:
            raise ValueError("expected two independent split predecessors and verifier vout zero")
        incoming = []
        for txin, parent in zip(transaction.inputs[1:], parents, strict=True):
            if txin.txid != parent.txid_wire() or not 0 <= txin.vout < len(parent.outputs):
                raise ValueError("wrong recursive token outpoint")
            incoming.append(parent.outputs[txin.vout])
        child = transfer_bytes(asset, recursive_key_id(self.key, self.knowledge_relation),
                               transaction, verifier_parent, self.lock(asset),
                               _slots(asset, policy, incoming, first=1),
                               _slots(asset, policy, transaction.outputs, first=0),
                               script_code=COMPACT_SCRIPTCODE)
        preceding = tuple(self.leaf.statement(asset, policy, parent, funding)
                          for parent, funding in zip(parents, funders, strict=True))
        return child, preceding

    @staticmethod
    def signals(child, preceding):
        first, second = (hash256(statement) for statement in preceding)
        if first == second:
            raise ValueError("recursive statements must describe different predecessors")
        return public_inputs(RECURSION_DOMAIN + hash256(child) + first + second)

    @staticmethod
    def transaction_material(transaction, verifier_parent, parents, funders):
        return b"".join(push(field) for field in (
            *(funding.serialize() for funding in funders), *(parent.serialize() for parent in parents),
            b"".join(output.serialize() for output in transaction.outputs),
            b"".join(txin.outpoint() for txin in transaction.inputs),
            preimage_all(transaction, 0, verifier_parent.outputs[0].value, COMPACT_SCRIPTCODE),
        ))

    def witness(self, asset, policy, proof, transaction, verifier_parent, parents, funders):
        child, preceding = self.statements(asset, policy, transaction, verifier_parent, parents, funders)
        signals = self.signals(child, preceding)
        fields = verifier_fields(self.key, self.knowledge_relation, signals, proof)
        return unlocking_script(fields) + self.transaction_material(transaction, verifier_parent, parents, funders)
