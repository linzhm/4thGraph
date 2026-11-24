"""Operational token locks for a fixed asset verifier set and a freeze role."""
from dataclasses import dataclass, field, replace
from hashlib import sha256

from shared.script import asm, number, push
from shared.transaction import Output, Transaction, blob, hash256, preimage_forkid
from statement import fixed
from transaction_relation import TokenState
from transfer import authenticate_forkid_preimage, shared_guard_lock, verifier_input_script_hash

TOKEN_DOMAIN = b"BSV/CCTP/token/v2\x00"
TOKEN_MARKER = push(TOKEN_DOMAIN)
METADATA_SIZE = 74
FLAG_OFFSET = len(TOKEN_MARKER) + 1 + METADATA_SIZE - 1
FORKID_ALL = 0x41
FORKID_SINGLE = 0x43


def _shared_guard_digest_script() -> bytes:
    """Replace the only verifier digest in a canonical guard output script field."""
    placeholder = b"BSV/CCTP/shared-ordinary-guard-template/v1\0"
    placeholder_guard = sha256(blob(placeholder)).digest()
    template = blob(shared_guard_lock(placeholder))
    if template.count(placeholder_guard) != 1:
        raise ValueError("shared guard template must contain exactly one verifier digest")
    lead, tail = template.split(placeholder_guard)
    another = placeholder + b"variant"
    if lead + sha256(blob(another)).digest() + tail != blob(shared_guard_lock(another)):
        raise ValueError("shared guard does not only vary by its verifier digest")
    return push(lead) + asm("OP_SWAP OP_CAT") + push(tail) + asm("OP_CAT OP_SHA256")


def _verify_signature(key: bytes) -> bytes:
    return (
        asm("OP_DEPTH OP_1 OP_NUMEQUALVERIFY OP_DUP OP_SIZE OP_1SUB OP_SPLIT OP_NIP")
        + push(bytes([FORKID_ALL])) + asm("OP_EQUALVERIFY")
        + push(key) + asm("OP_CHECKSIG")
    )


def _certified_admin_guard() -> bytes:
    """Consume the actual vin-one verifier material, preserving both preimages."""
    return (
        # [issuer signature, verifier funding, prevouts, ALL preimage,
        # receipt output, SINGLE preimage, prior flag].
        asm("OP_DEPTH OP_7 OP_NUMEQUALVERIFY OP_4 OP_PICK OP_SIZE 72 OP_NUMEQUALVERIFY "
            "36 OP_SPLIT OP_DROP OP_4 OP_PICK 68 OP_SPLIT OP_NIP 36 OP_SPLIT OP_DROP OP_EQUALVERIFY "
            "OP_5 OP_ROLL OP_5 OP_ROLL OP_5 OP_PICK")
        + verifier_input_script_hash(input_index=1)
        + asm("OP_FROMALTSTACK OP_EQUALVERIFY")
    )


def _certified_admin_outputs() -> bytes:
    from projects.cctp.recursion.continuity_statement import OUTPUT_PREFIX, OUTPUT_SIZE, ZERO

    # Verify the SAME paired successor against the SINGLE and the ALL
    # commitments. ALL ensures the receipt is the only other actual vout.
    first_bytes = OUTPUT_PREFIX + b"\x01"
    return (
        asm("OP_DUP OP_HASH256 OP_ROT OP_EQUALVERIFY OP_OVER OP_SIZE")
        + number(OUTPUT_SIZE) + asm("OP_NUMEQUALVERIFY OP_DUP")
        + number(len(first_bytes)) + asm("OP_SPLIT OP_DROP")
        + push(first_bytes) + asm("OP_EQUALVERIFY")
        + number(OUTPUT_SIZE - len(ZERO)) + asm("OP_SPLIT OP_NIP")
        + push(ZERO) + asm("OP_EQUALVERIFY OP_SWAP OP_CAT OP_HASH256 OP_SWAP "
                           "OP_SIZE 40 OP_SUB OP_SPLIT OP_NIP 32 OP_SPLIT OP_DROP OP_EQUALVERIFY")
    )


def _freeze_branch(key: bytes, *, certified_admin: bool = False) -> bytes:
    # The SINGLE preimage authentically exposes the output at this input's
    # index. The issuer's independent ALL signature covers the whole spend.
    return (
        (_certified_admin_guard() if certified_admin else b"")
        + push(b"\x01") + asm("OP_XOR OP_TOALTSTACK OP_DUP")
        + authenticate_forkid_preimage(FORKID_SINGLE) + asm("OP_DROP")
        + asm("104 OP_SPLIT OP_NIP OP_SIZE 44 OP_SUB OP_SPLIT")
        + asm("OP_4 OP_SPLIT OP_NIP 32 OP_SPLIT OP_DROP OP_SWAP")
        + asm("OP_SIZE OP_8 OP_SUB OP_SPLIT OP_SWAP")
        # The v2 script length is always encoded by 3-byte CompactSize.
        + number(3 + FLAG_OFFSET)
        + asm("OP_SPLIT OP_1 OP_SPLIT OP_NIP OP_FROMALTSTACK OP_SWAP")
        + asm("OP_CAT OP_CAT OP_CAT")
        + (_certified_admin_outputs() if certified_admin else asm("OP_HASH256 OP_EQUALVERIFY"))
        + _verify_signature(key)
    )


@dataclass(frozen=True)
class TokenPolicy:
    """Exact accepted verifier locks, plus a dedicated freeze public key.

    The authenticated mint must pin this policy when creating the original
    token output. Ordinary proofs must preserve the policy of the parents.
    """
    verifier_locks: tuple[bytes, ...]
    freeze_key: bytes
    certified_admin: bool = field(default=False, kw_only=True)
    shared_ordinary_guard: bool = field(default=False, kw_only=True)

    def __post_init__(self):
        fixed(self.freeze_key, 33)
        if self.freeze_key[0] not in (2, 3):
            raise ValueError("expected compressed freeze key")
        locks = self.verifier_locks
        if not locks or any(type(lock) is not bytes or not lock for lock in locks):
            raise ValueError("expected complete verifier locks")
        if len(set(locks)) != len(locks):
            raise ValueError("duplicate verifier lock")
        if type(self.certified_admin) is not bool or (self.certified_admin and len(locks) != 1):
            raise ValueError("certified administration requires one exact verifier lock")
        if (type(self.shared_ordinary_guard) is not bool
                or self.shared_ordinary_guard and not self.certified_admin):
            raise ValueError("shared ordinary guard requires certified administration and one verifier")

    def verifier_hashes(self) -> tuple[bytes, ...]:
        return tuple(sorted(sha256(blob(lock)).digest() for lock in self.verifier_locks))

    def selected_verifier(self, tx: Transaction, raw: bytes, *, index=0) -> Transaction:
        parent = Transaction.parse(raw)
        if (type(index) is not int or not 0 <= index < len(tx.inputs)
                or tx.inputs[index].txid != parent.txid_wire() or tx.inputs[index].vout != 0
                or len(parent.inputs) != 1 or len(parent.inputs[0].script) >= 253
                or len(parent.outputs) != 1 or parent.outputs[0].script not in self.verifier_locks):
            raise ValueError("invalid verifier parent")
        return parent

    def shared_guard_lock(self) -> bytes:
        """Return the exact script for the optional vin-one companion funding."""
        if not self.shared_ordinary_guard:
            raise ValueError("shared ordinary guard is not enabled")
        return shared_guard_lock(self.verifier_locks[0])

    def selected_shared_guard(self, tx: Transaction, raw: bytes) -> Transaction:
        expected = self.shared_guard_lock()
        parent = Transaction.parse(raw)
        if (len(tx.inputs) < 2 or tx.inputs[1].txid != parent.txid_wire() or tx.inputs[1].vout != 0
                or len(parent.inputs) != 1 or len(parent.inputs[0].script) >= 253
                or len(parent.outputs) != 1 or parent.outputs[0].script != expected):
            raise ValueError("invalid shared guard parent at vin one")
        return parent

    def _ordinary_guard(self) -> bytes:
        if self.shared_ordinary_guard:
            # Both branches consume the one universal digest stored above
            # the mode check. The companion then enforces that same
            # universal verifier's actual funding at vin zero.
            return (
                asm("OP_DUP OP_0 OP_EQUAL OP_OVER OP_1 OP_EQUAL OP_BOOLOR OP_VERIFY OP_IF")
                + verifier_input_script_hash(input_index=1)
                + asm("OP_FROMALTSTACK") + _shared_guard_digest_script() + asm("OP_EQUALVERIFY OP_ELSE")
                + verifier_input_script_hash() + asm("OP_FROMALTSTACK OP_EQUALVERIFY OP_ENDIF")
            )
        if self.certified_admin:
            return verifier_input_script_hash() + asm("OP_FROMALTSTACK OP_EQUALVERIFY")
        first, *remaining = self.verifier_hashes()
        if not remaining:
            return verifier_input_script_hash() + push(first) + asm("OP_EQUALVERIFY")
        compare = asm("OP_DUP") + push(first) + asm("OP_EQUAL")
        for digest in remaining:
            compare += asm("OP_OVER") + push(digest) + asm("OP_EQUAL OP_BOOLOR")
        return verifier_input_script_hash() + compare + asm("OP_NIP OP_VERIFY")

    def lock(self, state: TokenState) -> bytes:
        shared_digest = (push(self.verifier_hashes()[0]) + asm("OP_TOALTSTACK")
                         if self.certified_admin else b"")
        script = (
            TOKEN_MARKER + push(state.encode())
            + asm("OP_NIP") + shared_digest + asm("OP_SIZE OP_1SUB OP_SPLIT OP_NIP OP_SWAP OP_IF")
            + _freeze_branch(self.freeze_key, certified_admin=self.certified_admin)
            + asm("OP_ELSE OP_NOT OP_VERIFY")
            + self._ordinary_guard()
            + _verify_signature(state.owner)
            + asm("OP_ENDIF")
        )
        if not 253 <= len(script) <= 65535:
            raise ValueError("token script outside canonical v2 length profile")
        return script

    def parse(self, script: bytes) -> TokenState | None:
        if not script.startswith(TOKEN_MARKER):
            return None
        metadata = script[len(TOKEN_MARKER) + 1:FLAG_OFFSET + 1]
        if len(metadata) != METADATA_SIZE or metadata[-1] not in (0, 1):
            raise ValueError("invalid token metadata")
        token = TokenState(metadata[:32], int.from_bytes(metadata[32:40], "little"),
                           metadata[40:73], bool(metadata[-1]))
        if script != self.lock(token):
            raise ValueError("noncanonical token lock or policy")
        return token


def shared_guard_witness(tx, policy, verifier_parent, shared_guard_parent):
    """Unlock the actual vin-one companion, binding the full verifier at vin zero."""
    policy.selected_verifier(tx, verifier_parent.serialize())
    guard = policy.selected_shared_guard(tx, shared_guard_parent.serialize()).outputs[0]
    prevouts = b"".join(item.outpoint() for item in tx.inputs)
    preimage = preimage_forkid(tx, 1, guard.value, guard.script, FORKID_ALL)
    return push(verifier_parent.serialize()) + push(prevouts) + push(preimage)


def ordinary_witness(tx, index, parent, policy, verifier_parent, signer, *, shared_guard_parent=None):
    """Use the external owner signer for the ForkID ALL digest."""
    txin = tx.inputs[index]
    if txin.txid != parent.txid_wire() or not 0 <= txin.vout < len(parent.outputs):
        raise ValueError("incorrect token parent")
    policy.selected_verifier(tx, verifier_parent.serialize())
    output = parent.outputs[txin.vout]
    state = policy.parse(output.script)
    if state is None or state.frozen:
        raise ValueError("expected active token")
    guard_parent = verifier_parent
    selector = b""
    if shared_guard_parent is not None:
        if not policy.shared_ordinary_guard or index < 2:
            raise ValueError("shared guard owner spends require token inputs after vin one")
        policy.selected_shared_guard(tx, shared_guard_parent.serialize())
        guard_parent = shared_guard_parent
        selector = asm("OP_1")
    elif policy.shared_ordinary_guard:
        selector = asm("OP_0")
    prevouts = b"".join(item.outpoint() for item in tx.inputs)
    preimage = preimage_forkid(tx, index, output.value, output.script, FORKID_ALL)
    return (push(signer(hash256(preimage)) + bytes([FORKID_ALL]))
            + push(guard_parent.serialize()) + push(prevouts) + push(preimage) + selector + asm("OP_0"))


def freeze_witness(tx, index, parent, policy, signer, *, verifier_parent=None):
    """Authorize the actual spend with an external freeze-role signer."""
    txin = tx.inputs[index]
    if txin.txid != parent.txid_wire() or not 0 <= txin.vout < len(parent.outputs):
        raise ValueError("incorrect token parent")
    output = parent.outputs[txin.vout]
    state = policy.parse(output.script)
    if state is None:
        raise ValueError("expected token")
    preimage = preimage_forkid(tx, index, output.value, output.script, FORKID_SINGLE)
    full_preimage = preimage_forkid(tx, index, output.value, output.script, FORKID_ALL)
    transition = b""
    if policy.certified_admin:
        from projects.cctp.recursion.continuity_statement import ParentReceipt

        if index != 0 or len(tx.inputs) != 2 or len(tx.outputs) != 2 or verifier_parent is None:
            raise ValueError("certified administration needs token vin0, verifier vin1 and two outputs")
        policy.selected_verifier(tx, verifier_parent.serialize(), index=1)
        successor = Output(output.value, policy.lock(replace(state, frozen=not state.frozen)))
        if tx.outputs[0] != successor or len(ParentReceipt.parse(tx.outputs[1]).parents) != 1:
            raise ValueError("certified administration needs the paired toggle and one predecessor digest")
        prevouts = b"".join(item.outpoint() for item in tx.inputs)
        transition = b"".join(push(item) for item in (
            verifier_parent.serialize(), prevouts, full_preimage, tx.outputs[1].serialize(),
        ))
    elif verifier_parent is not None:
        raise ValueError("legacy administration has no verifier parent")
    signature = signer(hash256(full_preimage)) + bytes([FORKID_ALL])
    return push(signature) + transition + push(preimage) + asm("OP_1")
