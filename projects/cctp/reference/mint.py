"""Consensus mint covenant and host transaction builder for the CCTP bridge."""

from collections.abc import Callable
from dataclasses import dataclass, replace
from functools import cached_property
from hashlib import sha256
from typing import TYPE_CHECKING

from mint_events import (
    DEPOSIT_DOMAIN, DEPOSIT_SIZE, EMPTY_LEAF, EMPTY_ROOT, EVENT_ID_DOMAIN, FEE_OFFSET,
    GROSS_OFFSET, NODE_DOMAIN, OWNER_OFFSET, POSITION_SIZE, SPENT_LEAF, TREE_DEPTH,
    Deposit, DepositPosition, MintEvents, compressed_key,
)
from shared.pushtx import PUBLIC, binding_der
from shared.script import asm, number, push
from shared.transaction import Input, Output, Transaction, amount, blob, compact, hash256, preimage_all
from statement import AssetDescriptor, fixed, uint
from transaction_relation import TokenState
from usdc_amount import USDC_DECIMALS

if TYPE_CHECKING:
    from projects.cctp.recursion.continuity_statement import ParentReceipt

STATE_DOMAIN = b"BSV/CCTP/mint-state/v1\0"
STATE_MARKER = push(STATE_DOMAIN)
ROOT_OFFSET = 3 + len(STATE_MARKER) + 1
P2PKH_PREFIX = asm("OP_DUP OP_HASH160") + b"\x14"
P2PKH_SUFFIX = asm("OP_EQUALVERIFY OP_CHECKSIG")
RECORD_PREFIX = asm("OP_0 OP_RETURN") + push(DEPOSIT_DOMAIN)
# Distinct public fixture points 2G and 3G used solely to locate owner fields.
TEMPLATE_OWNER = bytes.fromhex("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
SECOND_OWNER = bytes.fromhex("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
TEMPLATE_QUANTITY = 0x1122334455667788


def _slice(offset: int, size: int) -> bytes:
    start = number(offset) + asm("OP_SPLIT OP_NIP") if offset else b""
    return start + number(size) + asm("OP_SPLIT OP_DROP")


def _size(size: int) -> bytes:
    return asm("OP_SIZE") + number(size) + asm("OP_NUMEQUALVERIFY")


def _unsigned() -> bytes:
    return push(b"\0") + asm("OP_CAT OP_BIN2NUM")


def _branch_hash() -> bytes:
    return asm("OP_CAT") + push(NODE_DOMAIN) + asm("OP_SWAP OP_CAT OP_HASH256")


def _sparse_fold() -> bytes:
    # Main stack after one level: key quotient, unused siblings, old hash, new hash.
    def fold_pair(right: bool) -> bytes:
        order = asm("OP_SWAP") if right else b""
        return (asm("OP_3 OP_PICK OP_OVER") + order + _branch_hash()
                + asm("OP_3 OP_PICK OP_2 OP_PICK") + order + _branch_hash())

    level = (
        asm("OP_2 OP_ROLL 32 OP_SPLIT OP_SWAP OP_4 OP_PICK OP_2 OP_MOD OP_IF")
        + fold_pair(True) + asm("OP_ELSE") + fold_pair(False) + asm("OP_ENDIF")
        + asm("OP_2 OP_ROLL OP_DROP OP_3 OP_ROLL OP_DROP OP_3 OP_ROLL OP_DROP "
              "OP_3 OP_ROLL OP_2 OP_DIV OP_2SWAP OP_3 OP_ROLL")
    )
    return level * TREE_DEPTH


def _authenticate(key: bytes) -> bytes:
    # Verify the supplied preimage by constructing a CHECKSIG for the native
    # current input. Require the authority to separately sign the same input.
    script = (
        asm("OP_DEPTH 7 OP_NUMEQUALVERIFY OP_OVER OP_DUP OP_SIZE OP_4 OP_SUB OP_SPLIT OP_NIP")
        + push(b"\x41\0\0\0") + asm("OP_EQUALVERIFY OP_HASH256")
        + binding_der() + push(b"\x41") + asm("OP_CAT") + push(PUBLIC) + asm("OP_CHECKSIGVERIFY")
        + asm("OP_6 OP_PICK OP_DUP OP_SIZE OP_1SUB OP_SPLIT OP_NIP")
        + push(b"\x41") + asm("OP_EQUALVERIFY") + push(key) + asm("OP_CHECKSIGVERIFY")
    )
    # The first of exactly two prevouts must be this covenant's vout zero.
    return script + (
        asm("OP_3 OP_PICK") + _size(72) + asm("OP_DUP OP_HASH256 OP_3 OP_PICK")
        + _slice(4, 32) + asm("OP_EQUALVERIFY")
        + _slice(0, 36) + asm("OP_DUP") + _slice(32, 4) + push(bytes(4))
        + asm("OP_EQUALVERIFY OP_2 OP_PICK") + _slice(68, 36) + asm("OP_EQUALVERIFY")
    )


def _split_state_output() -> bytes:
    # Copy the authenticated scriptCode and store the incoming satoshis.
    return asm("OP_OVER 104 OP_SPLIT OP_NIP OP_SIZE 52 OP_SUB OP_SPLIT 8 OP_SPLIT OP_DROP OP_TOALTSTACK")


def _finish_outputs() -> bytes:
    # Append the optional P2PKH change then authenticate the complete outputs.
    return (
        asm("OP_2 OP_PICK OP_SIZE OP_0NOTEQUAL OP_IF")
        + _size(28) + asm("OP_8 OP_SPLIT OP_SWAP")
        + push(bytes([25]) + P2PKH_PREFIX) + asm("OP_CAT OP_SWAP OP_CAT")
        + push(P2PKH_SUFFIX) + asm("OP_CAT OP_CAT OP_ELSE OP_DROP OP_ENDIF")
        + _verify_outputs_digest()
    )


def _verify_outputs_digest() -> bytes:
    return asm("OP_HASH256 OP_OVER OP_SIZE 40 OP_SUB OP_SPLIT OP_NIP 32 OP_SPLIT OP_DROP "
               "OP_EQUALVERIFY OP_2DROP OP_2DROP OP_2DROP OP_1")


def _finish_certified_outputs() -> bytes:
    from projects.cctp.recursion.continuity_statement import OUTPUT_PREFIX, OUTPUT_SIZE

    # The receipt occupies the same witness slot used by legacy P2PKH change.
    # Check the whole serialized output, including zero satoshis, canonical
    # script prefix, cardinality and padding. The verifier input checks the
    # meaning of the active predecessor digests.
    return (
        asm("OP_2 OP_PICK") + _size(OUTPUT_SIZE)
        + asm("OP_DUP") + _slice(0, len(OUTPUT_PREFIX)) + push(OUTPUT_PREFIX) + asm("OP_EQUALVERIFY")
        + asm("OP_DUP") + number(len(OUTPUT_PREFIX)) + asm("OP_SPLIT OP_NIP OP_1 OP_SPLIT OP_SWAP")
        + _unsigned() + asm("OP_DUP 0 3 OP_WITHIN OP_VERIFY 32 OP_MUL OP_SPLIT OP_NIP")
        + _unsigned() + asm("OP_0 OP_NUMEQUALVERIFY OP_CAT") + _verify_outputs_digest()
    )


def _certified_guard(verifier_hash: bytes) -> bytes:
    from transfer import verifier_input_script_hash

    return (
        asm("OP_DEPTH OP_8 OP_NUMEQUALVERIFY OP_7 OP_ROLL OP_4 OP_PICK OP_3 OP_PICK")
        + verifier_input_script_hash(input_index=1) + push(verifier_hash) + asm("OP_EQUALVERIFY")
    )


@dataclass(frozen=True)
class MintPolicy:
    asset: AssetDescriptor
    source_chain_id: int
    reserve_contract: bytes
    attestor: bytes
    lock_token: Callable[[TokenState], bytes]
    carrier: int = 1000
    pause_authority: bytes | None = None
    certified_verifier_hash: bytes | None = None
    certified_pause: bool = False

    def __post_init__(self):
        self.asset.encode()
        if self.asset.decimals != USDC_DECIMALS:
            raise ValueError("USDC mint requires six decimal places")
        uint(self.source_chain_id, 8)
        fixed(self.reserve_contract, 20)
        compressed_key(self.attestor)
        if self.pause_authority is not None:
            compressed_key(self.pause_authority)
            if self.pause_authority == self.attestor:
                raise ValueError("mint and pause authorities must be distinct")
        if self.certified_verifier_hash is not None and not any(fixed(self.certified_verifier_hash, 32)):
            raise ValueError("certified mint requires a concrete verifier script hash")
        if (type(self.certified_pause) is not bool or self.certified_pause
                and (self.certified_verifier_hash is None or self.pause_authority is None)):
            raise ValueError("certified pause requires a verifier and a pause authority")
        amount(self.carrier)
        if not self.source_chain_id or not any(self.reserve_contract) or not self.carrier:
            raise ValueError("expected a concrete source chain, reserve contract and token carrier")

    @cached_property
    def source(self) -> bytes:
        return uint(self.source_chain_id, 8) + uint(self.asset.reserve_domain, 4) + self.reserve_contract

    @cached_property
    def destination(self) -> bytes:
        return self.asset.reserve_asset + uint(self.asset.network, 4) + self.asset.asset_id()

    def check_deposit(self, deposit: Deposit) -> None:
        raw = deposit.encode()
        if raw[:len(self.source)] != self.source or raw[POSITION_SIZE:GROSS_OFFSET] != self.destination:
            raise ValueError("deposit is outside this mint policy")

    def token_output(self, quantity: int, owner: bytes) -> Output:
        return Output(self.carrier, self.lock_token(TokenState(self.asset.asset_id(), quantity, owner)))

    @cached_property
    def _token_chunks(self) -> tuple[bytes | str, ...]:
        """Specialize the script's output builder to a canonical token lock profile."""
        sample = self.token_output(TEMPLATE_QUANTITY, TEMPLATE_OWNER).serialize()
        different_quantity = 0x8877665544332211
        different = self.token_output(different_quantity, SECOND_OWNER).serialize()
        fields = {
            "quantity": (uint(TEMPLATE_QUANTITY, 8), uint(different_quantity, 8)),
            "owner": (TEMPLATE_OWNER, SECOND_OWNER),
        }
        variable_fields = []
        for label, (before, after) in fields.items():
            offset = sample.find(before)
            while offset != -1:
                end = offset + len(before)
                if different[offset:end] == after:
                    variable_fields.append((offset, end, label))
                offset = sample.find(before, end)

        parts = []
        start = 0
        for offset, end, label in sorted(variable_fields):
            if offset < start:
                raise ValueError("token profile fields overlap")
            parts.extend((sample[start:offset], label))
            start = end
        parts.append(sample[start:])
        if parts.count("quantity") != 1 or "owner" not in parts:
            raise ValueError("token profile must encode its quantity and compressed owner literally")
        rebuilt = b"".join(fields[part][1] if isinstance(part, str) else part for part in parts)
        if rebuilt != different:
            raise ValueError("token profile has unsupported quantity or owner derivatives")
        return tuple(parts)

    @cached_property
    def _covenant(self) -> bytes:
        if self.pause_authority is None:
            return self._mint_branch()
        # Pause-enabled witnesses append an operation selector. The lock itself
        # adds the committed pause flag above the root before selecting the branch.
        select = asm("OP_2 OP_ROLL OP_DUP OP_0 OP_EQUAL OP_OVER OP_1 OP_EQUAL OP_BOOLOR OP_VERIFY")
        if self.certified_pause:
            # Keep one verifier commitment shared by both operations.
            select += (
                asm("OP_TOALTSTACK OP_TOALTSTACK") + _certified_guard(self.certified_verifier_hash)
                + asm("OP_FROMALTSTACK OP_FROMALTSTACK")
            )
        return (
            select + asm("OP_IF")
            + self._pause_branch()
            + asm("OP_ELSE OP_NOT OP_VERIFY")
            + self._mint_branch()
            + asm("OP_ENDIF")
        )

    def _mint_branch(self) -> bytes:
        # Unlocking stack (top at right): sig, Merkle path, deposit, prevouts,
        # optional change, preimage. The locking prefix adds the old root.
        script = b""
        if self.certified_verifier_hash is not None and not self.certified_pause:
            script += _certified_guard(self.certified_verifier_hash)
        script += _authenticate(self.attestor)
        # Validate mint scope and use just the source position as the replay key.
        script += (
            asm("OP_4 OP_PICK") + _size(DEPOSIT_SIZE) + asm("OP_DUP")
            + _slice(0, len(self.source)) + push(self.source) + asm("OP_EQUALVERIFY OP_DUP")
            + _slice(POSITION_SIZE, len(self.destination)) + push(self.destination) + asm("OP_EQUALVERIFY")
            + _slice(0, POSITION_SIZE) + push(EVENT_ID_DOMAIN) + asm("OP_SWAP OP_CAT OP_HASH256")
            + _unsigned() + asm("OP_6 OP_PICK") + _size(TREE_DEPTH * 32)
            + push(EMPTY_LEAF) + push(SPENT_LEAF) + _sparse_fold()
            + asm("OP_TOALTSTACK OP_3 OP_ROLL OP_EQUALVERIFY OP_2DROP OP_FROMALTSTACK")
        )
        # Copy the authenticated scriptCode from the preimage and replace its root.
        # The covenant uses a three-byte CompactSize prefix (checked by state_lock).
        script += (
            _split_state_output()
            + number(ROOT_OFFSET) + asm("OP_SPLIT 32 OP_SPLIT OP_NIP OP_ROT OP_SWAP OP_CAT OP_CAT")
            + asm("OP_FROMALTSTACK OP_SWAP OP_CAT")
        )
        # Build vout 1 from the attested quantity and owner, keeping satoshis separate.
        script += (
            asm("OP_4 OP_PICK OP_DUP") + _slice(GROSS_OFFSET, 8) + _unsigned()
            + asm("OP_OVER") + _slice(FEE_OFFSET, 8) + _unsigned()
            + asm("OP_SUB OP_DUP OP_0 OP_GREATERTHAN OP_VERIFY 9 OP_NUM2BIN 8 OP_SPLIT OP_DROP OP_SWAP")
            + _slice(OWNER_OFFSET, 33) + asm(
                "OP_DUP OP_1 OP_SPLIT OP_DROP OP_BIN2NUM OP_DUP OP_2 OP_NUMEQUAL "
                "OP_SWAP OP_3 OP_NUMEQUAL OP_BOOLOR OP_VERIFY OP_0"
            )
        )
        for part in self._token_chunks:
            fragment = asm("OP_2 OP_PICK") if part == "quantity" else (
                asm("OP_OVER") if part == "owner" else push(part)
            )
            script += fragment + asm("OP_CAT")
        script += asm("OP_ROT OP_DROP OP_NIP OP_CAT")
        # Build vout 2 (the exact signed deposit record) and the configured vout 3.
        record_header = push(bytes(DEPOSIT_SIZE))[:-DEPOSIT_SIZE]
        record_size = len(RECORD_PREFIX) + len(record_header) + DEPOSIT_SIZE
        script += (
            push(amount(0) + compact(record_size) + RECORD_PREFIX + record_header)
            + asm("OP_CAT OP_4 OP_PICK OP_CAT")
            + (_finish_outputs() if self.certified_verifier_hash is None else _finish_certified_outputs())
        )
        return script

    def _pause_branch(self) -> bytes:
        assert self.pause_authority is not None
        pause_offset = ROOT_OFFSET + 32 + len(asm("OP_NIP"))
        return (
            asm("OP_NOT OP_TOALTSTACK") + _authenticate(self.pause_authority)
            # Reuse the normal witness layout, with no path or deposit.
            + asm("OP_5 OP_PICK") + _size(0) + asm("OP_DROP OP_4 OP_PICK") + _size(0) + asm("OP_DROP")
            + _split_state_output()
            + number(pause_offset) + asm("OP_SPLIT OP_1 OP_SPLIT OP_NIP")
            + asm("OP_FROMALTSTACK OP_FROMALTSTACK OP_IF") + push(asm("OP_1"))
            + asm("OP_ELSE") + push(asm("OP_0")) + asm("OP_ENDIF")
            + asm("OP_2SWAP OP_2 OP_ROLL OP_SWAP OP_CAT OP_CAT OP_CAT OP_NIP")
            + (_finish_certified_outputs() if self.certified_pause else _finish_outputs())
        )

    def state_lock(self, root: bytes, *, paused: bool = False) -> bytes:
        if type(paused) is not bool or (paused and self.pause_authority is None):
            raise ValueError("mint pause requires a configured authority")
        flag = number(int(paused)) if self.pause_authority is not None else b""
        script = STATE_MARKER + push(fixed(root, 32)) + asm("OP_NIP") + flag + self._covenant
        if len(compact(len(script))) != 3:
            raise ValueError("mint covenant script must use three-byte CompactSize")
        return script

    def check_genesis(self, transaction: Transaction) -> None:
        """Check the sole issuance anchor was consumed at vin 0 by this transaction."""
        if (not transaction.inputs or transaction.inputs[0].outpoint() != self.asset.issuance_outpoint
                or not transaction.outputs or transaction.outputs[0].script != self.state_lock(EMPTY_ROOT)):
            raise ValueError("transaction is not the anchored empty mint state")


def _record(deposit: Deposit) -> Output:
    return Output(0, RECORD_PREFIX + push(deposit.encode()))


def read_deposit(transaction: Transaction) -> Deposit:
    if len(transaction.outputs) < 3:
        raise ValueError("missing mint deposit record")
    record = transaction.outputs[2]
    if not record.script.startswith(RECORD_PREFIX):
        raise ValueError("invalid mint deposit record domain")
    deposit = Deposit.parse(record.script[-DEPOSIT_SIZE:])
    if record != _record(deposit):
        raise ValueError("noncanonical mint deposit record")
    return deposit


@dataclass(frozen=True)
class MintPlan:
    policy: MintPolicy
    prior: Transaction
    events: MintEvents
    deposit: Deposit
    transaction: Transaction
    path: tuple[bytes, ...]
    successor: MintEvents
    verifier_parent: Transaction | None = None


def prepare_mint(
    policy: MintPolicy, prior: Transaction, events: MintEvents, deposit: Deposit, sponsor: Input,
    *, change: Output | None = None, receipt: "ParentReceipt | None" = None,
    verifier_parent: Transaction | None = None,
) -> MintPlan:
    policy.check_deposit(deposit)
    if not prior.outputs or prior.outputs[0].script != policy.state_lock(events.root):
        if (policy.pause_authority is not None and prior.outputs
                and prior.outputs[0].script == policy.state_lock(events.root, paused=True)):
            raise ValueError("minting is paused")
        raise ValueError("prior mint state and event set disagree")
    state_input = Input(prior.txid_wire(), 0)
    if sponsor.outpoint() == state_input.outpoint():
        raise ValueError("duplicate mint input")
    if policy.certified_verifier_hash is None:
        if verifier_parent is not None or receipt is not None:
            raise ValueError("legacy mint does not accept a continuity verifier or receipt")
    else:
        if change is not None or receipt is None or sponsor.vout != 0:
            raise ValueError("certified mint requires vin-one verifier vout zero and a continuity receipt")
        if verifier_parent is not None:
            _check_verifier_parent(policy, sponsor, verifier_parent)
    successor, path = events.add(deposit.position.event_id())
    outputs = (
        Output(prior.outputs[0].value, policy.state_lock(successor.root)),
        policy.token_output(deposit.net_quantity, deposit.owner),
        _record(deposit),
    )
    if change is not None:
        _change_bytes(change)
        outputs += (change,)
    if receipt is not None:
        from projects.cctp.recursion.continuity_statement import ParentReceipt

        receipt_output = receipt.output()
        ParentReceipt.parse(receipt_output)
        outputs += (receipt_output,)
    transaction = Transaction((state_input, sponsor), outputs)
    return MintPlan(policy, prior, events, deposit, transaction, path, successor, verifier_parent)


def _check_verifier_parent(policy: MintPolicy, sponsor: Input, verifier_parent: Transaction | None) -> None:
    if verifier_parent is None:
        raise ValueError("certified mint requires the actual verifier funding transaction")
    if (sponsor.vout != 0 or sponsor.txid != verifier_parent.txid_wire()
            or len(verifier_parent.inputs) != 1 or len(verifier_parent.inputs[0].script) >= 253
            or len(verifier_parent.outputs) != 1):
        raise ValueError("incorrect certified mint verifier parent or outpoint")
    script_hash = sha256(blob(verifier_parent.outputs[0].script)).digest()
    if script_hash != policy.certified_verifier_hash:
        raise ValueError("incorrect certified mint verifier script hash")


def _mint_tail(policy: MintPolicy, transaction: Transaction) -> tuple[Output | None, "ParentReceipt | None"]:
    if len(transaction.inputs) != 2 or len(transaction.outputs) not in (3, 4):
        raise ValueError("invalid mint layout")
    if policy.certified_verifier_hash is None:
        return (transaction.outputs[3] if len(transaction.outputs) == 4 else None), None
    if len(transaction.outputs) != 4:
        raise ValueError("missing certified mint continuity receipt")
    from projects.cctp.recursion.continuity_statement import ParentReceipt

    return None, ParentReceipt.parse(transaction.outputs[3])


def _change_bytes(output: Output) -> bytes:
    script = output.script
    if len(script) != 25 or not script.startswith(P2PKH_PREFIX) or not script.endswith(P2PKH_SUFFIX):
        raise ValueError("mint change must pay a P2PKH output")
    return amount(output.value) + script[len(P2PKH_PREFIX):-len(P2PKH_SUFFIX)]


def mint_unlock(plan: MintPlan, der_signature: bytes) -> bytes:
    """Encode a Script witness for the policy's external SIGHASH_ALL signer."""
    tx = plan.transaction
    change, receipt = _mint_tail(plan.policy, tx)
    prevouts = b"".join(item.outpoint() for item in tx.inputs)
    preimage = preimage_all(tx, 0, plan.prior.outputs[0].value, plan.prior.outputs[0].script)
    tail = _change_bytes(change) if change is not None else b""
    verifier = b""
    if receipt is not None:
        _check_verifier_parent(plan.policy, tx.inputs[1], plan.verifier_parent)
        assert plan.verifier_parent is not None
        verifier = push(plan.verifier_parent.serialize())
        tail = receipt.output().serialize()
    witness = b"".join(push(field) for field in (
        der_signature + b"\x41", b"".join(plan.path), plan.deposit.encode(), prevouts, tail, preimage,
    ))
    return verifier + witness + (asm("OP_0") if plan.policy.pause_authority is not None else b"")


def authorize_mint(
    plan: MintPlan, finalized_deposit: Callable[[DepositPosition], Deposit | None],
    sign_digest: Callable[[bytes], bytes],
) -> Transaction:
    """Fulfill the plan using separate finalized-receipt and external signer adapters.

    The service must supply its view of the actual anchored state via plan.prior.
    The observer's trust and finality checks belong to the source-chain adapter.
    """
    tx = plan.transaction
    change, receipt = _mint_tail(plan.policy, tx)
    if receipt is not None:
        _check_verifier_parent(plan.policy, tx.inputs[1], plan.verifier_parent)
    expected = prepare_mint(plan.policy, plan.prior, plan.events, plan.deposit, tx.inputs[1],
                            change=change, receipt=receipt, verifier_parent=plan.verifier_parent)
    if (expected.transaction != tx or expected.path != plan.path or expected.successor != plan.successor):
        raise ValueError("plan disagrees with the canonical mint transition")
    if finalized_deposit(plan.deposit.position) != plan.deposit:
        raise ValueError("no matching finalized reserve deposit")
    state = plan.prior.outputs[0]
    digest = hash256(preimage_all(tx, 0, state.value, state.script))
    signature = sign_digest(digest)
    return tx.with_script(0, mint_unlock(plan, signature))


def prepare_pause(
    policy: MintPolicy, prior: Transaction, events: MintEvents, sponsor: Input,
    *, paused: bool, change: Output | None = None, receipt: "ParentReceipt | None" = None,
    verifier_parent: Transaction | None = None,
) -> Transaction:
    if policy.pause_authority is None or type(paused) is not bool:
        raise ValueError("mint pause requires a configured authority and explicit status")
    if not prior.outputs or prior.outputs[0].script != policy.state_lock(events.root, paused=not paused):
        raise ValueError("pause transition must toggle the actual anchored state")
    state_input = Input(prior.txid_wire(), 0)
    if sponsor.outpoint() == state_input.outpoint():
        raise ValueError("duplicate mint input")
    outputs = (Output(prior.outputs[0].value, policy.state_lock(events.root, paused=paused)),)
    if policy.certified_pause:
        from projects.cctp.recursion.continuity_statement import ParentReceipt

        if change is not None or receipt is None or sponsor.vout != 0:
            raise ValueError("certified pause requires vin-one verifier vout zero and a continuity receipt")
        if verifier_parent is not None:
            _check_verifier_parent(policy, sponsor, verifier_parent)
        receipt_output = receipt.output()
        if len(ParentReceipt.parse(receipt_output).parents) > 1:
            raise ValueError("certified pause has at most one predecessor proof")
        return Transaction((state_input, sponsor), (*outputs, receipt_output))
    if receipt is not None or verifier_parent is not None:
        raise ValueError("legacy pause does not accept a continuity verifier or receipt")
    if change is not None:
        _change_bytes(change)
        outputs += (change,)
    return Transaction((state_input, sponsor), outputs)


def authorize_pause(
    policy: MintPolicy, prior: Transaction, events: MintEvents, sponsor: Input,
    sign_digest: Callable[[bytes], bytes], *, paused: bool, change: Output | None = None,
    receipt: "ParentReceipt | None" = None, verifier_parent: Transaction | None = None,
) -> Transaction:
    transaction = prepare_pause(policy, prior, events, sponsor, paused=paused, change=change,
                                receipt=receipt, verifier_parent=verifier_parent)
    funding, tail = b"", _change_bytes(change) if change is not None else b""
    if policy.certified_pause:
        _check_verifier_parent(policy, sponsor, verifier_parent)
        assert verifier_parent is not None
        funding = push(verifier_parent.serialize())
        tail = transaction.outputs[1].serialize()
    outpoint_bytes = b"".join(item.outpoint() for item in transaction.inputs)
    state = prior.outputs[0]
    preimage = preimage_all(transaction, 0, state.value, state.script)
    signature = sign_digest(hash256(preimage)) + b"\x41"
    witness = b"".join(push(field) for field in (signature, b"", b"", outpoint_bytes, tail, preimage))
    return transaction.with_script(0, funding + witness + asm("OP_1"))


@dataclass(frozen=True)
class RecoveredMintState:
    transaction: Transaction
    events: MintEvents
    paused: bool


def recover_mint_state(
    policy: MintPolicy, genesis: Transaction, confirmed_transitions: tuple[Transaction, ...],
) -> RecoveredMintState:
    """Recover state from an already consensus-validated and confirmed lineage."""
    policy.check_genesis(genesis)
    prior, events, paused = genesis, MintEvents(), False
    for transaction in confirmed_transitions:
        size = len(transaction.outputs)
        if len(transaction.inputs) != 2 or not 1 <= size <= 4:
            raise ValueError("invalid mint history layout")
        replay = transaction.with_script(0, b"")
        if size <= 2:
            change, receipt = (transaction.outputs[1] if size == 2 else None), None
            if policy.certified_pause:
                from projects.cctp.recursion.continuity_statement import ParentReceipt

                if size != 2:
                    raise ValueError("missing certified pause continuity receipt")
                change, receipt = None, ParentReceipt.parse(transaction.outputs[1])
                replay = replay.with_script(1, b"")
            paused = not paused
            expected = prepare_pause(policy, prior, events, replay.inputs[1], paused=paused, change=change,
                                     receipt=receipt)
        else:
            change, receipt = _mint_tail(policy, transaction)
            if receipt is not None:
                replay = replay.with_script(1, b"")
            plan = prepare_mint(policy, prior, events, read_deposit(transaction), replay.inputs[1],
                                change=change, receipt=receipt)
            expected, events = plan.transaction, plan.successor
        if replay != expected:
            raise ValueError("mint history does not extend the anchored state")
        prior = transaction
    return RecoveredMintState(prior, events, paused)


def recover_events(policy: MintPolicy, genesis: Transaction, confirmed_mints: tuple[Transaction, ...]) -> MintEvents:
    return recover_mint_state(policy, genesis, confirmed_mints).events
