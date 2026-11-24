"""BSV boundary for anchored, same-key token continuity."""
from dataclasses import dataclass, replace
from functools import cached_property

from burn_receipt import BURN_MARKER, read_burn
from committed_verifier import CommitmentRelation, verifier_fields
from committed_verifier import verifier_lock as committed_lock
from continuity_preimage import current_funding_hash, prior_digest, statement_limbs, vin_one_transaction_material_check
from continuity_statement import OUTPUT_PREFIX, OUTPUT_SIZE, ParentReceipt, ZERO
from issuance_base import MINTED_VOUT, check_first_mint, runtime_first_mint_base_script
from mimo_verifier import MimoProfile, _match_prefix, _parse_active_token
from mint import ROOT_OFFSET, STATE_MARKER, MintPolicy, read_deposit
from operational_token import TokenPolicy
from recursive_mimo import _add_quantities, _assert_u64, _slots
from shared.script import asm, number, push
from shared.transaction import Output, Transaction, hash256, preimage_all
from statement import fixed
from transfer import COMPACT_SCRIPTCODE, compact_preimage_digest_script, compact_verifier_binding
from verifier import VerificationKey, unlocking_script

SINGLE_OUTPUT_MARKER = Output(0, asm("OP_0 OP_RETURN") + push(b"BSV/CCTP/single-output/v1\x00"))


def _conserve(input_count, output_count=2):
    first_output_quantity = 8 + 12 * input_count
    return (
        _add_quantities(tuple(6 + 12*i for i in range(input_count)))
        + _assert_u64() + asm("OP_TOALTSTACK")
        + _add_quantities(tuple(first_output_quantity + 12*i for i in range(output_count)))
        + asm("OP_FROMALTSTACK OP_NUMEQUALVERIFY OP_DROP")
    )


@dataclass(frozen=True)
class ContinuityVerifier:
    mint_template: MintPolicy
    freeze_key: bytes
    key: VerificationKey
    commitment: CommitmentRelation
    key_digest: bytes
    certified_mints: bool = False
    certified_admin: bool = False
    certified_burns: bool = False
    certified_single_output: bool = False
    certified_pause: bool = False
    shared_ordinary_guard: bool = False

    def __post_init__(self):
        fixed(self.key_digest, 32)
        if type(self.certified_mints) is not bool or self.mint_template.certified_verifier_hash is not None:
            raise ValueError("provide an unbound mint template and select its proof profile explicitly")
        if type(self.certified_admin) is not bool or (self.certified_admin and not self.certified_mints):
            raise ValueError("certified token administration requires certified minting")
        if type(self.certified_burns) is not bool or (self.certified_burns and not self.certified_mints):
            raise ValueError("certified burn requires certified minting")
        if type(self.certified_single_output) is not bool or (self.certified_single_output and not self.certified_mints):
            raise ValueError("certified single-output transfers require certified minting")
        if (type(self.certified_pause) is not bool or self.certified_pause
                and (not self.certified_mints or self.mint_template.pause_authority is None)):
            raise ValueError("certified pause requires certified minting and a pause authority")
        if type(self.shared_ordinary_guard) is not bool or self.shared_ordinary_guard and not self.certified_admin:
            raise ValueError("shared ordinary guard requires certified token administration")

    @property
    def asset(self):
        return self.mint_template.asset

    @cached_property
    def lock(self):
        return self.statement_script() + committed_lock(self.key, self.commitment) + compact_verifier_binding()

    @cached_property
    def policy(self):
        return TokenPolicy((self.lock,), self.freeze_key, certified_admin=self.certified_admin,
                           shared_ordinary_guard=self.shared_ordinary_guard)

    @cached_property
    def mint_policy(self):
        guard_hash = self.policy.verifier_hashes()[0] if self.certified_mints else None
        return replace(self.mint_template, lock_token=self.policy.lock, certified_verifier_hash=guard_hash,
                       certified_pause=self.certified_pause)

    def _collect_prior_digests(self, count):
        # After authenticating the current funding, the remaining witness is
        # [ancestor fundings..., actual token parents..., current lock hash].
        if count == 0:
            return (asm("OP_ROT OP_SWAP") + runtime_first_mint_base_script(self.mint_template, self.freeze_key)
                    + push(ParentReceipt(()).payload()))
        prior = self._prior_digest()
        if count == 1:
            return asm("OP_ROT OP_SWAP") + prior + push(b"\x01") + asm("OP_SWAP OP_CAT") + push(ZERO) + asm("OP_CAT")
        return (
            asm("OP_TOALTSTACK OP_2 OP_ROLL OP_2SWAP OP_SWAP OP_FROMALTSTACK OP_DUP OP_TOALTSTACK")
            + prior + asm("OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK")
            + prior + asm("OP_FROMALTSTACK OP_SWAP OP_CAT")
            + push(b"\x02") + asm("OP_SWAP OP_CAT")
        )

    def _path(self, count, *, burn_change=None, single=False):
        incoming = max(1, count)
        burning = burn_change is not None
        outgoing = burn_change if burning else 1 if single else 2
        profile = MimoProfile(incoming, outgoing, 1, self.freeze_key, burn=burning)
        marker = SINGLE_OUTPUT_MARKER.serialize() if single else b""
        relation = profile.relation(
            self.asset.asset_id(), self.asset.reserve_domain, keep_parents=True, output_tail=len(marker) + OUTPUT_SIZE,
            parent_vout=MINTED_VOUT if count == 0 else None, certified_admin=self.certified_admin,
            burn_first=burning, distinct_token_inputs=single, shared_ordinary_guard=self.shared_ordinary_guard,
            parent_output=self._parent_output(),
        )
        return (
            relation + asm("OP_3 OP_ROLL") + _conserve(incoming, profile.flow_outputs)
            # Identify the executing verifier, without embedding its own hash.
            + asm("OP_DUP") + number(2*incoming + 4) + asm("OP_ROLL OP_SWAP")
            + current_funding_hash()
            + asm("OP_DUP OP_4 OP_PICK OP_EQUALVERIFY OP_3 OP_ROLL OP_DROP OP_SWAP")
            + compact_preimage_digest_script()
            + asm("OP_TOALTSTACK OP_SWAP OP_TOALTSTACK")
            + self._collect_prior_digests(count)
            # Compare the actual final OP_RETURN output field to the ordered
            # proof digests derived from the actual spent predecessors.
            + asm("OP_DUP OP_FROMALTSTACK") + _match_prefix(marker + OUTPUT_PREFIX)
            + asm("OP_EQUALVERIFY OP_FROMALTSTACK")
        )

    def _prior_digest(self):
        return prior_digest(self.asset.asset_id(), self.key_digest, certified_admin=self.certified_admin,
                            certified_pause=self.certified_pause)

    def _parent_output(self):
        return None

    def _mint_path(self, genesis, *, pause=False):
        from issuance_base import runtime_mint_state_script

        current = (
            vin_one_transaction_material_check(preceding_outputs=1 if pause else 3)
            + asm("OP_DUP") + number(4 if genesis else 5) + asm("OP_ROLL OP_SWAP")
            + current_funding_hash() + asm("OP_SWAP") + compact_preimage_digest_script()
            + asm("OP_TOALTSTACK OP_SWAP OP_TOALTSTACK")
        )
        state = runtime_mint_state_script(self.mint_template, self.freeze_key, genesis_only=genesis,
                                          certified_admin=self.certified_admin, certified_pause=self.certified_pause,
                                          shared_ordinary_guard=self.shared_ordinary_guard)
        if genesis:
            payload = state + push(ParentReceipt(()).payload())
        else:
            payload = (
                asm("OP_2DUP") + state + asm("OP_ROT OP_SWAP")
                + (self._prior_digest() if self.certified_pause else prior_digest(self.asset.asset_id(), self.key_digest))
                + push(b"\x01") + asm("OP_SWAP OP_CAT") + push(ZERO) + asm("OP_CAT")
            )
        return (
            current + payload + asm("OP_DUP OP_FROMALTSTACK") + _match_prefix(OUTPUT_PREFIX)
            + asm("OP_EQUALVERIFY OP_FROMALTSTACK")
        )

    def _admin_path(self):
        # The exact token lock at vin0 enforces the issuer signature and the
        # paired flag toggle. This path authenticates that token and its proof.
        parse_token = _parse_active_token(self.asset.asset_id(), self.freeze_key, 1,
                                          certified_admin=True, allow_frozen=True,
                                          shared_ordinary_guard=self.shared_ordinary_guard)
        return (
            vin_one_transaction_material_check(preceding_outputs=1, select_parent_script=True,
                                               parent_output=self._parent_output())
            + asm("OP_DUP 6 OP_ROLL OP_SWAP") + current_funding_hash()
            + asm("OP_SWAP") + compact_preimage_digest_script()
            + asm("OP_TOALTSTACK OP_SWAP OP_TOALTSTACK OP_SWAP") + parse_token
            + asm("OP_2 OP_PICK OP_EQUALVERIFY OP_DROP OP_ROT OP_SWAP")
            + self._prior_digest()
            + push(b"\x01") + asm("OP_SWAP OP_CAT") + push(ZERO) + asm("OP_CAT")
            + asm("OP_DUP OP_FROMALTSTACK") + _match_prefix(OUTPUT_PREFIX)
            + asm("OP_EQUALVERIFY OP_FROMALTSTACK")
        )

    def _statement_variants(self):
        if self.certified_mints:
            variants = (
                (1, self._path(1)), (2, self._path(2)),
                (3, self._mint_path(genesis=True)), (4, self._mint_path(genesis=False)),
            )
        else:
            variants = tuple((count, self._path(count)) for count in (0, 1, 2))
        if self.certified_admin:
            variants += ((5, self._admin_path()),)
        if self.certified_burns:
            variants += tuple((5 + count + 2*change, self._path(count, burn_change=change))
                              for change in (0, 1) for count in (1, 2))
        if self.certified_pause:
            variants += ((10, self._mint_path(genesis=True, pause=True)),
                         (11, self._mint_path(genesis=False, pause=True)))
        if self.certified_single_output:
            variants += tuple((11 + count, self._path(count, single=True)) for count in (1, 2))
        return variants

    def statement_script(self):
        variants = self._statement_variants()
        code = b""
        for mode, branch in variants[:-1]:
            code += asm("OP_DUP") + number(mode) + asm("OP_NUMEQUAL OP_IF OP_DROP") + branch + asm("OP_ELSE")
        mode, branch = variants[-1]
        return (
            code + number(mode) + asm("OP_NUMEQUALVERIFY") + branch
            + asm("OP_ENDIF") * (len(variants) - 1) + statement_limbs(self.asset.asset_id(), self.key_digest)
        )

    def burn_profile(self, tx):
        """Return the number of token change outputs for a certified burn layout."""
        if not self.certified_burns or not tx.outputs or not tx.outputs[0].script.startswith(BURN_MARKER):
            return None
        if len(tx.outputs) not in (2, 3):
            raise ValueError("incorrect certified burn output layout")
        read_burn(tx, 0, self.asset)
        return len(tx.outputs) - 2

    def _layout(self, tx):
        if self.burn_profile(tx) is not None:
            return "burn", 0
        if self.certified_mints and len(tx.outputs) == 4:
            return "mint", 1
        if self.certified_pause and len(tx.outputs) == 2 and tx.outputs[0].script.startswith(STATE_MARKER):
            return "pause", 1
        if self.certified_admin and len(tx.outputs) == 2:
            return "admin", 1
        if len(tx.outputs) == 3:
            if self.certified_single_output and tx.outputs[1] == SINGLE_OUTPUT_MARKER:
                return "single", 0
            return "transfer", 0
        raise ValueError("incorrect continuity output layout")

    def verifier_input_index(self, tx):
        """Select the verifier vin used by the canonical continuity layout."""
        return self._layout(tx)[1]

    def context(self, tx, funding):
        """Read the typed receipt and hash the actual compact verifier preimage."""
        layout, index = self._layout(tx)
        self.policy.selected_verifier(tx, funding.serialize(), index=index)
        receipt = ParentReceipt.parse(tx.outputs[-1])
        if layout in ("mint", "pause") and (len(receipt.parents) > 1 or tx.inputs[0].vout != 0):
            raise ValueError("incorrect mint state vout or receipt")
        if layout == "admin" and len(receipt.parents) != 1:
            raise ValueError("token administration requires one predecessor proof")
        if layout == "burn" and not receipt.parents:
            raise ValueError("certified burn requires prior proofs for its token inputs")
        if layout == "single" and not receipt.parents:
            raise ValueError("certified single-output transfer requires prior proofs")
        if len(tx.inputs) != (2 if index else 1 + max(1, len(receipt.parents))):
            raise ValueError("wrong verifier and protocol input shape")
        preimage = preimage_all(tx, index, funding.outputs[0].value, COMPACT_SCRIPTCODE)
        return receipt, hash256(preimage)

    def proof_digest(self, tx, funding):
        receipt, context = self.context(tx, funding)
        return receipt.digest(self.asset.asset_id(), self.key_digest, context)

    def _active_input_quantity(self, tx, parents, supporting):
        if len(parents) != len(tx.inputs) - 1 or len(supporting) != len(parents):
            raise ValueError("wrong parent or supporting transaction count")
        if len({txin.outpoint() for txin in tx.inputs}) != len(tx.inputs):
            raise ValueError("duplicated input outpoint")
        actual = []
        for txin, parent in zip(tx.inputs[1:], parents, strict=True):
            if txin.txid != parent.txid_wire() or not 0 <= txin.vout < len(parent.outputs):
                raise ValueError("wrong token input outpoint")
            actual.append(parent.outputs[txin.vout])
        return sum(item.quantity for item in _slots(self.asset, self.policy, actual, first=1))

    def _check_parent_digests(self, receipt, parents, supporting):
        if receipt.parents != tuple(
            self.proof_digest(parent, support) for parent, support in zip(parents, supporting, strict=True)
        ):
            raise ValueError("receipt does not match the actual predecessors")

    def validate(self, tx, funding, parents, supporting):
        receipt, context = self.context(tx, funding)
        layout = self._layout(tx)[0]
        if layout not in ("transfer", "single"):
            raise ValueError("not a token transfer")
        incoming = self._active_input_quantity(tx, parents, supporting)
        successors = tx.outputs[:1] if layout == "single" else tx.outputs[:2]
        outgoing = sum(item.quantity for item in _slots(self.asset, self.policy, successors, first=0))
        if incoming != outgoing or incoming >= 2**64:
            raise ValueError("token supply must be conserved within uint64")
        if not receipt.parents:
            if self.certified_mints:
                raise ValueError("certified tokens require a prior transaction proof")
            check_first_mint(self.mint_policy, self.policy, parents[0], tx.inputs[1].vout, supporting[0])
        else:
            self._check_parent_digests(receipt, parents, supporting)
        return receipt, context

    def burn_mode(self, tx):
        """Select the burn verifier branch from its layout and proof count."""
        change = self.burn_profile(tx)
        if change is None:
            raise ValueError("not a certified burn")
        count = len(ParentReceipt.parse(tx.outputs[-1]).parents)
        if not count or len(tx.inputs) != count + 1:
            raise ValueError("certified burn requires one proof per token input")
        return 5 + count + 2 * change

    def validate_burn(self, tx, funding, parents, supporting):
        """Check the actual burn, change and ordered lineage for its proof statement."""
        self.burn_mode(tx)
        receipt, context = self.context(tx, funding)
        burn = read_burn(tx, 0, self.asset)
        incoming = self._active_input_quantity(tx, parents, supporting)
        change = sum(item.quantity for item in _slots(self.asset, self.policy, tx.outputs[1:-1], first=1))
        if incoming != burn.quantity + change or incoming >= 2**64:
            raise ValueError("token supply must equal the gross burn plus change within uint64")
        self._check_parent_digests(receipt, parents, supporting)
        return receipt, context, burn

    def burn_material(self, tx, funding, parents, supporting):
        """Encode the exact proof-independent vin0 witness suffix for a burn."""
        return self.transaction_material(tx, funding, parents, supporting, count=self.burn_mode(tx))

    def burn_witness(self, proof, tx, funding, parents, supporting):
        receipt, context, _ = self.validate_burn(tx, funding, parents, supporting)
        signals = receipt.signals(self.asset.asset_id(), self.key_digest, context)
        return (unlocking_script(verifier_fields(self.key, self.commitment, signals, proof))
                + self.burn_material(tx, funding, parents, supporting))

    @staticmethod
    def transaction_material(tx: Transaction, funding: Transaction, parents, supporting, *, count, verifier_index=0):
        """Serialize proof-independent wire witnesses in input order."""
        return b"".join(push(part) for part in (
            funding.serialize(), *(support.serialize() for support in supporting),
            *(parent.serialize() for parent in parents),
            b"".join(output.serialize() for output in tx.outputs),
            b"".join(txin.outpoint() for txin in tx.inputs),
            preimage_all(tx, verifier_index, funding.outputs[0].value, COMPACT_SCRIPTCODE),
        )) + number(count)

    def witness(self, proof, tx, funding, parents, supporting):
        receipt, context = self.validate(tx, funding, parents, supporting)
        signals = receipt.signals(self.asset.asset_id(), self.key_digest, context)
        return (
            unlocking_script(verifier_fields(self.key, self.commitment, signals, proof))
            + self.transaction_material(tx, funding, parents, supporting, count=self.transfer_mode(tx))
        )

    def transfer_mode(self, tx):
        """Select a token transfer branch from its actual output layout."""
        layout = self._layout(tx)[0]
        count = len(ParentReceipt.parse(tx.outputs[-1]).parents)
        if layout == "single" and count:
            return 11 + count
        if layout == "transfer":
            return count
        raise ValueError("not a certified token transfer profile")

    def validate_mint(self, tx, funding, state_parent, previous_verifier=None):
        if self._layout(tx)[0] != "mint":
            raise ValueError("not a certified mint")
        receipt, context = self.context(tx, funding)
        if tx.inputs[0].txid != state_parent.txid_wire():
            raise ValueError("wrong actual mint-state parent")
        deposit = read_deposit(tx)
        self.mint_policy.check_deposit(deposit)
        if tx.outputs[1] != self.mint_policy.token_output(deposit.net_quantity, deposit.owner):
            raise ValueError("mint output differs from authorized deposit")
        self._validate_prior_state(receipt, state_parent, previous_verifier)
        return receipt, context

    def _validate_prior_state(self, receipt, state_parent, previous_verifier):
        if not receipt.parents:
            if previous_verifier is not None:
                raise ValueError("genesis must not have a predecessor proof")
            self.mint_policy.check_genesis(state_parent)
        elif (previous_verifier is None or self._layout(state_parent)[0] not in ("mint", "pause")
                or receipt.parents != (self.proof_digest(state_parent, previous_verifier),)):
            raise ValueError("receipt does not match the certified preceding mint state")

    def validate_pause(self, tx, funding, state_parent, previous_verifier=None):
        if self._layout(tx)[0] != "pause":
            raise ValueError("not a certified mint pause transition")
        receipt, context = self.context(tx, funding)
        if tx.inputs[0].txid != state_parent.txid_wire() or not state_parent.outputs:
            raise ValueError("wrong actual mint-state parent")
        self._validate_prior_state(receipt, state_parent, previous_verifier)
        prior = state_parent.outputs[0]
        offset = ROOT_OFFSET - 3
        root = prior.script[offset:offset + 32]
        active = self.mint_policy.state_lock(root)
        paused = self.mint_policy.state_lock(root, paused=True)
        if prior.script not in (active, paused):
            raise ValueError("invalid prior mint state lock")
        expected = Output(prior.value, paused if prior.script == active else active)
        if tx.outputs[0] != expected:
            raise ValueError("pause must toggle the anchored state and preserve its root and value")
        return receipt, context

    def mint_witness(self, proof, tx, funding, state_parent, previous_verifier=None):
        receipt, context = self.validate_mint(tx, funding, state_parent, previous_verifier)
        signals = receipt.signals(self.asset.asset_id(), self.key_digest, context)
        support = () if previous_verifier is None else (previous_verifier,)
        return (
            unlocking_script(verifier_fields(self.key, self.commitment, signals, proof))
            + self.transaction_material(tx, funding, (state_parent,), support,
                                        count=3 + len(receipt.parents), verifier_index=1)
        )

    def pause_witness(self, proof, tx, funding, state_parent, previous_verifier=None):
        receipt, context = self.validate_pause(tx, funding, state_parent, previous_verifier)
        signals = receipt.signals(self.asset.asset_id(), self.key_digest, context)
        support = () if previous_verifier is None else (previous_verifier,)
        return (
            unlocking_script(verifier_fields(self.key, self.commitment, signals, proof))
            + self.transaction_material(tx, funding, (state_parent,), support,
                                        count=10 + len(receipt.parents), verifier_index=1)
        )

    def validate_admin(self, tx, funding, parent, previous_verifier):
        if self._layout(tx)[0] != "admin":
            raise ValueError("not a certified token administration transaction")
        receipt, context = self.context(tx, funding)
        txin = tx.inputs[0]
        if txin.txid != parent.txid_wire() or not 0 <= txin.vout < len(parent.outputs):
            raise ValueError("wrong actual token parent")
        prior = parent.outputs[txin.vout]
        state = self.policy.parse(prior.script)
        if state is None or state.asset_id != self.asset.asset_id():
            raise ValueError("wrong prior token asset or lock")
        expected = replace(prior, script=self.policy.lock(replace(state, frozen=not state.frozen)))
        if tx.outputs[0] != expected or receipt.parents != (self.proof_digest(parent, previous_verifier),):
            raise ValueError("the admin spend must preserve the token and bind its actual predecessor proof")
        return receipt, context

    def admin_witness(self, proof, tx, funding, parent, previous_verifier):
        receipt, context = self.validate_admin(tx, funding, parent, previous_verifier)
        signals = receipt.signals(self.asset.asset_id(), self.key_digest, context)
        return (
            unlocking_script(verifier_fields(self.key, self.commitment, signals, proof))
            + self.transaction_material(tx, funding, (parent,), (previous_verifier,), count=5, verifier_index=1)
        )
