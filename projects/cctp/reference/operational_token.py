"""Operational token locks for a fixed asset verifier set and a freeze role."""
from dataclasses import dataclass
from hashlib import sha256

from shared.script import asm, number, push
from shared.transaction import Transaction, blob, hash256, preimage_forkid
from statement import fixed
from transaction_relation import TokenState
from transfer import authenticate_forkid_preimage, verifier_input_script_hash

TOKEN_DOMAIN = b"BSV/CCTP/token/v2\x00"
TOKEN_MARKER = push(TOKEN_DOMAIN)
METADATA_SIZE = 74
FLAG_OFFSET = len(TOKEN_MARKER) + 1 + METADATA_SIZE - 1
FORKID_ALL = 0x41
FORKID_SINGLE = 0x43


def _verify_signature(key: bytes) -> bytes:
    return (
        asm("OP_DEPTH OP_1 OP_NUMEQUALVERIFY OP_DUP OP_SIZE OP_1SUB OP_SPLIT OP_NIP")
        + push(bytes([FORKID_ALL])) + asm("OP_EQUALVERIFY")
        + push(key) + asm("OP_CHECKSIG")
    )


def _freeze_branch(key: bytes) -> bytes:
    # The SINGLE preimage authentically exposes the output at this input's
    # index. The issuer's independent ALL signature covers the whole spend.
    return (
        push(b"\x01") + asm("OP_XOR OP_TOALTSTACK OP_DUP")
        + authenticate_forkid_preimage(FORKID_SINGLE) + asm("OP_DROP")
        + asm("104 OP_SPLIT OP_NIP OP_SIZE 44 OP_SUB OP_SPLIT")
        + asm("OP_4 OP_SPLIT OP_NIP 32 OP_SPLIT OP_DROP OP_SWAP")
        + asm("OP_SIZE OP_8 OP_SUB OP_SPLIT OP_SWAP")
        # The v2 script length is always encoded by 3-byte CompactSize.
        + number(3 + FLAG_OFFSET)
        + asm("OP_SPLIT OP_1 OP_SPLIT OP_NIP OP_FROMALTSTACK OP_SWAP")
        + asm("OP_CAT OP_CAT OP_CAT OP_HASH256 OP_EQUALVERIFY")
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

    def __post_init__(self):
        fixed(self.freeze_key, 33)
        if self.freeze_key[0] not in (2, 3):
            raise ValueError("expected compressed freeze key")
        locks = self.verifier_locks
        if not locks or any(type(lock) is not bytes or not lock for lock in locks):
            raise ValueError("expected complete verifier locks")
        if len(set(locks)) != len(locks):
            raise ValueError("duplicate verifier lock")

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

    def _ordinary_guard(self) -> bytes:
        first, *remaining = self.verifier_hashes()
        if not remaining:
            return verifier_input_script_hash() + push(first) + asm("OP_EQUALVERIFY")
        compare = asm("OP_DUP") + push(first) + asm("OP_EQUAL")
        for digest in remaining:
            compare += asm("OP_OVER") + push(digest) + asm("OP_EQUAL OP_BOOLOR")
        return verifier_input_script_hash() + compare + asm("OP_NIP OP_VERIFY")

    def lock(self, state: TokenState) -> bytes:
        script = (
            TOKEN_MARKER + push(state.encode())
            + asm("OP_NIP OP_SIZE OP_1SUB OP_SPLIT OP_NIP OP_SWAP OP_IF")
            + _freeze_branch(self.freeze_key)
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


def ordinary_witness(tx, index, parent, policy, verifier_parent, signer):
    """Use the external owner signer for the ForkID ALL digest."""
    txin = tx.inputs[index]
    if txin.txid != parent.txid_wire() or not 0 <= txin.vout < len(parent.outputs):
        raise ValueError("incorrect token parent")
    policy.selected_verifier(tx, verifier_parent.serialize())
    output = parent.outputs[txin.vout]
    state = policy.parse(output.script)
    if state is None or state.frozen:
        raise ValueError("expected active token")
    prevouts = b"".join(item.outpoint() for item in tx.inputs)
    preimage = preimage_forkid(tx, index, output.value, output.script, FORKID_ALL)
    return (push(signer(hash256(preimage)) + bytes([FORKID_ALL]))
            + push(verifier_parent.serialize()) + push(prevouts) + push(preimage) + asm("OP_0"))


def freeze_witness(tx, index, parent, policy, signer):
    """Authorize the actual spend with an external freeze-role signer."""
    txin = tx.inputs[index]
    if txin.txid != parent.txid_wire() or not 0 <= txin.vout < len(parent.outputs):
        raise ValueError("incorrect token parent")
    output = parent.outputs[txin.vout]
    state = policy.parse(output.script)
    if state is None:
        raise ValueError("expected token")
    preimage = preimage_forkid(tx, index, output.value, output.script, FORKID_SINGLE)
    signature_digest = hash256(preimage_forkid(tx, index, output.value, output.script, FORKID_ALL))
    return push(signer(signature_digest) + bytes([FORKID_ALL])) + push(preimage) + asm("OP_1")
