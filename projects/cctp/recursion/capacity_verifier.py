"""One real wide payment using the existing two-slot continuity proving key."""
from dataclasses import dataclass, replace
from functools import cached_property

from capacity_records import capacity_record_script, encode_capacity_record
from capacity_relation import WideProfile, ordered_parent_groups, select_wide_token_output_script, wide_group_stream
from capacity_tree import capacity_receipt, capacity_receipt_script
from capacity_wire import (
    CAPACITY_OUTPUT_SIZE, CAPACITY_SHAPES, CONTEXT_SIZE, CapacityReceipt, capacity_parent_digest_script,
    context_material, is_capacity_parent_script, parent_outputs_script, verify_capacity_receipt_script,
)
from committed_verifier import verifier_fields
from continuity_preimage import _funding_output, current_funding_hash
from continuity_verifier import ContinuityVerifier
from mimo_verifier import _select_parent_output, _split
from operational_token import TokenPolicy, _shared_guard_digest_script
from recursive_mimo import _slots
from shared.script import asm, number, push
from shared.transaction import Input, Transaction, blob, hash256, preimage_all
from transaction_relation import TokenState
from transfer import COMPACT_SCRIPTCODE, compact_preimage_digest_script
from verifier import unlocking_script


@dataclass(frozen=True)
class CapacityVerifier(ContinuityVerifier):
    capacity: int = 64
    compressed_ancestry: bool = False

    def __post_init__(self):
        super().__post_init__()
        if self.capacity not in (64, 256) or not self.certified_mints or not self.shared_ordinary_guard:
            raise ValueError("capacity requires certified minting and the shared guard at width 64 or 256")
        if type(self.compressed_ancestry) is not bool:
            raise ValueError("expected an explicit capacity witness encoding")

    @cached_property
    def capacity_modes(self):
        return tuple(mode for mode, shape in CAPACITY_SHAPES.items() if shape[1] in (1, self.capacity))

    @cached_property
    def _token_script_size(self):
        template = TokenPolicy((b"capacity token size placeholder",), self.freeze_key,
                               certified_admin=True, shared_ordinary_guard=True)
        return len(template.lock(TokenState(self.asset.asset_id(), 1, self.freeze_key)))

    @cached_property
    def _parent_outputs(self):
        return parent_outputs_script(self.capacity_modes, self._token_script_size)

    def _prior_digest(self):
        wide = capacity_parent_digest_script(self.capacity_modes, self._token_script_size,
                                              self.asset.asset_id(), self.key_digest)
        return (asm("OP_2 OP_PICK") + is_capacity_parent_script() + asm("OP_IF") + wide
                + asm("OP_ELSE") + super()._prior_digest() + asm("OP_ENDIF"))

    def _parent_output(self):
        return (
            asm("OP_OVER") + is_capacity_parent_script() + asm("OP_IF OP_SWAP") + self._parent_outputs
            + select_wide_token_output_script(self._token_script_size, CAPACITY_OUTPUT_SIZE)
            + asm("OP_ELSE") + _select_parent_output() + asm("OP_ENDIF")
        )

    def _capacity_path(self, mode):
        incoming, outgoing = CAPACITY_SHAPES[mode]
        decoder = capacity_record_script() if self.compressed_ancestry else None
        relation = WideProfile(incoming, outgoing, tail_size=CAPACITY_OUTPUT_SIZE).relation(
            self.asset.asset_id(), self.freeze_key, parent_outputs=self._parent_outputs,
            parent_digest=self._prior_digest(), token_script_size=self._token_script_size,
            record_decoder=decoder,
        )
        companion_material = (asm("5 OP_ROLL OP_4 OP_PICK") if decoder is not None
                              else asm("OP_4 OP_ROLL OP_3 OP_PICK"))
        dictionary = b""
        if decoder is not None:
            # The first dictionary entry is the authenticated executing lock
            # field. Decode the auxiliary entry using only that first entry.
            dictionary = (
                asm("OP_TOALTSTACK 5 OP_ROLL OP_OVER OP_0") + decoder
                + asm("5 OP_ROLL") * 4 + asm("OP_FROMALTSTACK")
            )
        return (
            # Identify executing verifier vin0 and the exact compact companion vin1.
            asm("OP_4 OP_ROLL OP_OVER") + current_funding_hash(keep_lock_field=self.compressed_ancestry)
            + companion_material + _split(36) + asm("OP_NIP 36 OP_SPLIT OP_DROP")
            + _funding_output() + asm("OP_NIP OP_OVER") + _shared_guard_digest_script() + asm("OP_EQUALVERIFY")
            # Rebuild ancestry from the actual parent groups; the receipt also
            # carries the compact context with hashOutputs left to the successor.
            + dictionary + relation + asm("OP_ROT") + capacity_receipt_script(self.asset.asset_id(), self.key_digest, self.capacity)
            + verify_capacity_receipt_script(mode) + compact_preimage_digest_script()
        )

    def _statement_variants(self):
        return super()._statement_variants() + tuple((mode, self._capacity_path(mode)) for mode in self.capacity_modes)

    def _layout(self, tx):
        if tx.outputs and CapacityReceipt.matches(tx.outputs[-1]):
            return "capacity", 0
        return super()._layout(tx)

    def _capacity_receipt(self, tx):
        if not tx.outputs or not CapacityReceipt.matches(tx.outputs[-1]):
            raise ValueError("not a capacity payment")
        receipt = CapacityReceipt.parse(tx.outputs[-1])
        incoming, outgoing = CAPACITY_SHAPES[receipt.mode]
        if (receipt.mode not in self.capacity_modes or len(tx.inputs) != incoming + 2
                or len(tx.outputs) != outgoing + 1):
            raise ValueError("capacity mode does not match the actual transaction shape")
        return receipt

    def context(self, tx, funding):
        if self._layout(tx)[0] != "capacity":
            return super().context(tx, funding)
        receipt = self._capacity_receipt(tx)
        self.policy.selected_verifier(tx, funding.serialize())
        preimage = preimage_all(tx, 0, funding.outputs[0].value, COMPACT_SCRIPTCODE)
        if receipt.material != context_material(preimage):
            raise ValueError("capacity receipt does not encode the actual compact verifier context")
        return receipt.ancestry, hash256(preimage)

    def prepare_capacity(self, mode, token_inputs, token_outputs, funding, companion, ancestry):
        carrier = CapacityReceipt(mode, ancestry, bytes(CONTEXT_SIZE))
        tx = Transaction((Input(funding.txid_wire(), 0), Input(companion.txid_wire(), 0), *token_inputs),
                         (*token_outputs, carrier.output()))
        self.policy.selected_shared_guard(tx, companion.serialize())
        self.policy.selected_verifier(tx, funding.serialize())
        material = context_material(preimage_all(tx, 0, funding.outputs[0].value, COMPACT_SCRIPTCODE))
        result = replace(tx, outputs=(*token_outputs, replace(carrier, material=material).output()))
        self._capacity_receipt(result)
        return result

    def validate_capacity(self, tx, funding, companion, pairs):
        receipt, context = self.context(tx, funding)
        self._capacity_receipt(tx)
        self.policy.selected_shared_guard(tx, companion.serialize())
        ordered = ordered_parent_groups(tx, pairs)
        if len({txin.outpoint() for txin in tx.inputs}) != len(tx.inputs):
            raise ValueError("duplicated actual capacity input")
        by_id = {parent.txid_wire(): parent for _, parent in ordered}
        selected = []
        for txin in tx.inputs[2:]:
            parent = by_id[txin.txid]
            if not 0 <= txin.vout < len(parent.outputs):
                raise ValueError("incorrect capacity parent vout")
            selected.append(parent.outputs[txin.vout])
        sent = sum(slot.quantity for slot in _slots(self.asset, self.policy, selected, first=2))
        received = sum(slot.quantity for slot in _slots(self.asset, self.policy, tx.outputs[:-1], first=0))
        if not 0 < sent < 2**64 or sent != received:
            raise ValueError("capacity payment must conserve a positive uint64 token total")
        digests = tuple(self.proof_digest(parent, support) for support, parent in ordered)
        if capacity_receipt(self.asset.asset_id(), self.key_digest, self.capacity, digests) != receipt:
            raise ValueError("wrong capacity ancestry for the actual ordered parent groups")
        return receipt, context

    def capacity_material(self, tx, funding, companion, pairs, *, dictionary_parent=b""):
        mode = self._capacity_receipt(tx).mode
        prefix = ()
        encoder = None
        if self.compressed_ancestry:
            first = blob(self.lock)
            prefix = (encode_capacity_record(dictionary_parent, (first, b"")),)

            def encoder(raw):
                return encode_capacity_record(raw, (first, dictionary_parent))
        elif dictionary_parent:
            raise ValueError("capacity verifier does not accept compressed parent records")
        return b"".join(push(part) for part in (
            *prefix, wide_group_stream(tx, pairs, encode_record=encoder), funding.serialize(), companion.serialize(),
            b"".join(output.serialize() for output in tx.outputs),
            b"".join(txin.outpoint() for txin in tx.inputs),
            preimage_all(tx, 0, funding.outputs[0].value, COMPACT_SCRIPTCODE),
        )) + number(mode)

    def capacity_witness_suffix(self, tx, funding, companion, pairs):
        if self.compressed_ancestry:
            # The full node executes reconstruction and txid checks. The
            # dictionary choice is arbitrary and need not be reproduced here.
            preimage = preimage_all(tx, 0, funding.outputs[0].value, COMPACT_SCRIPTCODE)
            return push(preimage) + number(self._capacity_receipt(tx).mode)
        return self.capacity_material(tx, funding, companion, pairs)

    def capacity_witness(self, proof, tx, funding, companion, pairs, *, dictionary_parent=b""):
        receipt, context = self.validate_capacity(tx, funding, companion, pairs)
        scalars = receipt.signals(self.asset.asset_id(), self.key_digest, context)
        return (unlocking_script(verifier_fields(self.key, self.commitment, scalars, proof))
                + self.capacity_material(tx, funding, companion, pairs, dictionary_parent=dictionary_parent))
