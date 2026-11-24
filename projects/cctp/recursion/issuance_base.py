"""Script-authenticated first-mint ancestry for the CCTP v2 token policy.

The invoking verifier authenticates both the mint raw transaction and the
selected vout against the actual input outpoint. This fragment then authenticates
the raw genesis through mint vin 0. Adopted BSV consensus supplies proof that
the mint spent the checked genesis covenant and satisfied its mint branch.
"""

from dataclasses import replace

from mimo_verifier import _compact_size, _match_prefix, _parse_active_token, _split, _take_output_script, _unsigned
from mint import MintPolicy, RECORD_PREFIX, ROOT_OFFSET, read_deposit, recover_mint_state
from mint_events import DEPOSIT_SIZE, EMPTY_ROOT
from operational_token import TokenPolicy
from shared.script import asm, number, push
from shared.transaction import Transaction, hash256
from statement import fixed
from transaction_relation import TokenState

GENESIS_MAX_INPUTS = 4
GENESIS_MAX_OUTPUTS = 4
MINTED_VOUT = 1
_GUARD_PLACEHOLDER = b"BSV/CCTP/issuance-guard-template/v1\0"


def _skip_input_payload() -> bytes:
    """Consume CompactSize scriptSig, its bytes, and the sequence."""
    return _compact_size() + asm("OP_SPLIT OP_NIP OP_4 OP_SPLIT OP_NIP")


def _finish_transaction() -> bytes:
    return asm("OP_SIZE OP_4 OP_NUMEQUALVERIFY OP_DROP")


def _mint_and_genesis_cursor(mint_policy: MintPolicy, freeze_key: bytes, guard_count: int) -> bytes:
    """Consume [mint raw, genesis raw, approved guard vector], leaving [genesis lock, approved guard vector]."""
    asset_id = mint_policy.asset.asset_id()
    check_minted_token = _parse_active_token(asset_id, freeze_key, guard_count)
    record_prefix = RECORD_PREFIX + push(bytes(DEPOSIT_SIZE))[:-DEPOSIT_SIZE]
    record_size = len(record_prefix) + DEPOSIT_SIZE

    code = (
        # Authenticate the genesis raw by matching the complete outpoint from
        # the already authenticated mint's vin zero.
        asm("OP_SIZE") + number(32 * guard_count) + asm("OP_NUMEQUALVERIFY OP_TOALTSTACK")
        + asm("OP_DUP OP_HASH256") + push(bytes(4)) + asm("OP_CAT OP_2 OP_ROLL OP_4 OP_SPLIT OP_NIP")
        + _compact_size() + asm("OP_2 OP_NUMEQUALVERIFY")
        + _split(36) + asm("OP_SWAP OP_2 OP_ROLL OP_EQUALVERIFY")
        + _skip_input_payload()
        + _split(36) + asm("OP_NIP") + _skip_input_payload()
        # Require the mint branch's exact output count, avoiding ambiguity
        # with an authorized pause action that spends the same state lock.
        + _compact_size() + asm("OP_DUP 3 5 OP_WITHIN OP_VERIFY OP_TOALTSTACK")
        + _take_output_script() + asm("OP_NIP")
        + _take_output_script() + asm("OP_SWAP") + check_minted_token
        # [genesis, remainder, quantity, guard]. Save output count again
        # while consuming the minted token's guard and proving it is nonzero.
        + asm("OP_FROMALTSTACK OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_SWAP OP_TOALTSTACK OP_EQUALVERIFY")
        + _unsigned() + asm("OP_0NOTEQUAL OP_VERIFY")
        + _match_prefix(bytes(8)) + _compact_size() + number(record_size) + asm("OP_NUMEQUALVERIFY")
        + _match_prefix(record_prefix) + _split(DEPOSIT_SIZE) + asm("OP_NIP")
        + asm("OP_FROMALTSTACK OP_4 OP_NUMEQUAL OP_IF")
        + _take_output_script() + asm("OP_NIP OP_ENDIF") + _finish_transaction()
    )

    return code + _state_output(mint_policy, genesis_only=True) + asm("OP_FROMALTSTACK")


def _state_output(mint_policy: MintPolicy, *, genesis_only: bool) -> bytes:
    """Consume bounded canonical transaction bytes and leave its first locking script."""
    skip_input = (
        asm("OP_DUP OP_0NOTEQUAL OP_IF OP_SWAP") + _split(36) + asm("OP_NIP")
        + _skip_input_payload() + asm("OP_SWAP OP_1SUB OP_ENDIF")
    )
    skip_output = (
        asm("OP_DUP OP_0NOTEQUAL OP_IF OP_SWAP") + _take_output_script()
        + asm("OP_NIP OP_SWAP OP_1SUB OP_ENDIF")
    )
    code = (asm("OP_4 OP_SPLIT OP_NIP") + _compact_size()
            + asm(f"OP_DUP 1 {GENESIS_MAX_INPUTS + 1} OP_WITHIN OP_VERIFY"))
    if genesis_only:
        code += (
            asm("OP_1SUB OP_TOALTSTACK") + _match_prefix(fixed(mint_policy.asset.issuance_outpoint, 36))
            + _skip_input_payload() + asm("OP_FROMALTSTACK") + skip_input * (GENESIS_MAX_INPUTS - 1)
        )
    else:
        code += skip_input * GENESIS_MAX_INPUTS
    return (
        code + asm("OP_0 OP_NUMEQUALVERIFY")
        + _compact_size() + asm(f"OP_DUP 1 {GENESIS_MAX_OUTPUTS + 1} OP_WITHIN OP_VERIFY")
        + asm("OP_1SUB OP_TOALTSTACK") + _take_output_script() + asm("OP_FROMALTSTACK")
        + skip_output * (GENESIS_MAX_OUTPUTS - 1) + asm("OP_0 OP_NUMEQUALVERIFY")
        + _finish_transaction()
    )


def first_mint_base_script(mint_policy: MintPolicy, token_policy: TokenPolicy) -> bytes:
    """Consume [authenticated mint raw, its selected vout as a Script number, genesis raw]."""
    guards = token_policy.verifier_hashes()
    return (
        asm("OP_SWAP OP_1 OP_NUMEQUALVERIFY") + push(b"".join(guards))
        + _mint_and_genesis_cursor(mint_policy, token_policy.freeze_key, len(guards))
        + asm("OP_DROP OP_HASH256") + push(hash256(mint_policy.state_lock(EMPTY_ROOT))) + asm("OP_EQUALVERIFY")
    )


def _runtime_template(mint_policy: MintPolicy, freeze_key: bytes) -> tuple[bytes, int, bytes]:
    placeholder_policy = TokenPolicy((_GUARD_PLACEHOLDER,), freeze_key)
    placeholder = placeholder_policy.verifier_hashes()[0]
    template = replace(mint_policy, lock_token=placeholder_policy.lock).state_lock(EMPTY_ROOT)

    # A second well-separated build proves that replacing just this field is
    # the complete effect of the runtime verifier identity on the bytecode.
    other_policy = TokenPolicy((_GUARD_PLACEHOLDER + b"second",), freeze_key)
    alternate = replace(mint_policy, lock_token=other_policy.lock).state_lock(EMPTY_ROOT)
    offset = template.find(placeholder)
    if (offset < 0 or template.count(placeholder) != 1
            or template[:offset] + other_policy.verifier_hashes()[0] + template[offset + 32:] != alternate):
        raise ValueError("mint template does not have one replaceable verifier guard")
    return template, offset, placeholder


def runtime_first_mint_base_script(mint_policy: MintPolicy, freeze_key: bytes) -> bytes:
    """Consume [authenticated mint raw, genesis raw, authenticated verifier hash].

    The caller must also enforce that its actual spent vout is one. The hash
    must be SHA256 of the actual input-zero verifier's serialized script field.
    The mint lock can then embed the verifier identity without a self-reference
    in the verifier's own script bytes.
    """
    template, offset, placeholder = _runtime_template(mint_policy, freeze_key)
    return (
        _mint_and_genesis_cursor(mint_policy, freeze_key, 1)
        + asm("OP_SWAP OP_SIZE") + number(len(template)) + asm("OP_NUMEQUALVERIFY")
        + _split(offset) + _split(32) + asm("OP_3 OP_ROLL OP_2 OP_ROLL OP_EQUALVERIFY")
        + push(placeholder) + asm("OP_SWAP OP_CAT OP_CAT OP_HASH256")
        + push(hash256(template)) + asm("OP_EQUALVERIFY")
    )


def _certified_state_template(mint_template: MintPolicy, freeze_key: bytes) -> tuple[bytes, bytes]:
    def instantiate(placeholder_lock):
        policy = TokenPolicy((placeholder_lock,), freeze_key)
        digest, = policy.verifier_hashes()
        covenant = replace(mint_template, lock_token=policy.lock, certified_verifier_hash=digest)
        return digest, covenant.state_lock(EMPTY_ROOT)

    placeholder, template = instantiate(_GUARD_PLACEHOLDER)
    alternate_guard, alternate = instantiate(_GUARD_PLACEHOLDER + b"second")
    if template.count(placeholder) != 2 or template.replace(placeholder, alternate_guard) != alternate:
        raise ValueError("certified mint template must replace precisely two verifier hash fields")
    return template, placeholder


def runtime_mint_state_script(mint_template: MintPolicy, freeze_key: bytes, *, genesis_only: bool) -> bytes:
    """Consume [authenticated state tx raw, authenticated verifier hash].

    The caller authenticates the txid and selected vout zero. Genesis mode
    proves issuance directly from the asset anchor and empty, active state.
    The continuing mode authenticates the exact state script template, with
    its event root and pause flag carried by the confirmed transaction. Its
    caller must separately establish prior state provenance.
    """
    if type(genesis_only) is not bool:
        raise ValueError("genesis_only must be boolean")
    template, placeholder = _certified_state_template(mint_template, freeze_key)
    # Compare the two configured guard occurrences to the same authenticated
    # verifier hash, then normalize to the template's fixed digest bytes.
    first = template.index(placeholder)
    second = template.index(placeholder, first + 32)
    check_guard = asm("OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_EQUALVERIFY")
    fields = [(first, placeholder, check_guard), (second, placeholder, check_guard)]
    if not genesis_only:
        # ROOT_OFFSET includes the script field's three-byte CompactSize.
        root_offset = ROOT_OFFSET - 3
        fields.append((root_offset, EMPTY_ROOT, asm("OP_DROP")))
        if mint_template.pause_authority is not None:
            pause_offset = root_offset + 32 + len(asm("OP_NIP"))
            check_pause = (asm("OP_DUP") + push(asm("OP_0")) + asm("OP_EQUAL OP_SWAP")
                           + push(asm("OP_1")) + asm("OP_EQUAL OP_BOOLOR OP_VERIFY"))
            fields.append((pause_offset, asm("OP_0"), check_pause))

    code = (asm("OP_SIZE 32 OP_NUMEQUALVERIFY OP_TOALTSTACK")
            + _state_output(mint_template, genesis_only=genesis_only)
            + asm("OP_SIZE") + number(len(template)) + asm("OP_NUMEQUALVERIFY OP_0 OP_SWAP"))
    cursor = 0
    for offset, normalized, verify in sorted(fields):
        # Carry the normalized prefix and remaining actual bytes. Consume
        # each variable field once and append its checked canonical value.
        code += (
            _split(offset - cursor) + asm("OP_TOALTSTACK OP_CAT OP_FROMALTSTACK")
            + _split(len(normalized)) + asm("OP_SWAP") + verify + push(normalized)
            + asm("OP_ROT OP_SWAP OP_CAT OP_SWAP")
        )
        cursor = offset + len(normalized)
    return (code + asm("OP_CAT OP_HASH256") + push(hash256(template))
            + asm("OP_EQUALVERIFY OP_FROMALTSTACK OP_DROP"))


def check_first_mint(
    mint_policy: MintPolicy, token_policy: TokenPolicy, mint: Transaction, vout: int, genesis: Transaction,
) -> TokenState:
    """Host reference for the anchored first mint over already confirmed transaction objects."""
    if type(vout) is not int or vout != MINTED_VOUT:
        raise ValueError("first mint must select token vout one")
    if (not 1 <= len(genesis.inputs) <= GENESIS_MAX_INPUTS
            or not 1 <= len(genesis.outputs) <= GENESIS_MAX_OUTPUTS):
        raise ValueError("genesis transaction is outside the issuance parser profile")
    recover_mint_state(mint_policy, genesis, (mint,))
    state = token_policy.parse(mint.outputs[vout].script)
    deposit = read_deposit(mint)
    if state != TokenState(mint_policy.asset.asset_id(), deposit.net_quantity, deposit.owner):
        raise ValueError("first mint selected output does not match the deposit and token policy")
    return state
