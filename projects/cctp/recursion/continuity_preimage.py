"""Rebuild ForkID commitments at the BSV continuity verifier boundary."""
from continuity_statement import CONTINUITY_DOMAIN, OUTPUT_PREFIX, PARENT_SIZE
from mimo_verifier import _match_prefix, _pick, _select_parent_output, _split, _unsigned
from parent_preimage import _compact_size, _count, _read_input, _skip_output
from shared.script import asm, number, push
from shared.transaction import blob
from statement import fixed
from transfer import COMPACT_SCRIPTCODE, digest_limbs_script

# Version, two component hashes, current outpoint, then CompactSize + script.
CURRENT_OUTPOINT = 68
CURRENT_AMOUNT = 104 + len(blob(COMPACT_SCRIPTCODE))


def _funding_output():
    """Consume [one-input funding raw, vout-zero outpoint]; leave [sats, lock hash]."""
    return (
        asm("32 OP_SPLIT") + push(bytes(4)) + asm("OP_EQUALVERIFY OP_OVER OP_HASH256 OP_EQUALVERIFY")
        + asm("OP_4 OP_SPLIT OP_NIP") + _count(1) + _read_input()
        + asm("OP_ROT OP_DROP OP_SWAP OP_DROP") + _count(1)
        + asm("OP_8 OP_SPLIT OP_SIZE OP_4 OP_SUB OP_SPLIT OP_DROP OP_DUP")
        + _compact_size() + asm("OP_SWAP OP_SIZE OP_ROT OP_NUMEQUALVERIFY OP_DROP OP_SHA256")
    )


def current_funding_hash():
    """Consume [funding raw, current preimage]; pin the actual verifier's own lock."""
    return (
        asm("OP_DUP") + _split(CURRENT_OUTPOINT) + asm("OP_NIP 36 OP_SPLIT OP_DROP OP_SWAP OP_TOALTSTACK")
        + _funding_output() + asm("OP_FROMALTSTACK") + _split(CURRENT_AMOUNT)
        + asm("OP_NIP OP_8 OP_SPLIT OP_DROP OP_ROT OP_EQUALVERIFY")
    )


def _hash_input_column(input_count, offset):
    # Stack [expected lock hash, funding, outpoint0, seq0, ...]. Leave the
    # ordered column's hash, retaining the original fields for the other hash.
    code = _pick(2 * input_count - 1 - offset)
    for i in range(1, input_count):
        code += _pick(2 * input_count - 1 - offset - 2 * i + 1) + asm("OP_CAT")
    return code + asm("OP_HASH256 OP_TOALTSTACK")


def _prior_preimage(input_count, *, output_count=3, verifier_index=0):
    """Consume [parent raw, its funding raw, current lock hash]; leave [receipt, preimage]."""
    if output_count == 2:
        count = asm("OP_1 OP_NUMEQUALVERIFY")
    else:
        count = asm("0 2 OP_WITHIN OP_VERIFY") if input_count == 2 else asm("OP_2 OP_NUMEQUALVERIFY")
    selected = asm("OP_2SWAP OP_2DROP") if verifier_index else asm("OP_2DROP") * (input_count - 1)
    return (
        # Put the expected lock hash under funding; parse the parent itself.
        asm("OP_ROT OP_ROT OP_SWAP OP_4 OP_SPLIT OP_SWAP OP_TOALTSTACK")
        + _count(input_count) + _read_input() * input_count + _count(output_count)
        + asm("OP_SIZE OP_4 OP_SUB OP_SPLIT OP_OVER") + _skip_output() * (output_count - 1)
        + _match_prefix(OUTPUT_PREFIX)
        + asm("OP_SIZE") + number(PARENT_SIZE) + asm("OP_NUMEQUALVERIFY")
        + asm("OP_DUP OP_1 OP_SPLIT OP_DROP") + _unsigned() + count
        + asm("OP_TOALTSTACK OP_SWAP OP_HASH256 OP_SWAP OP_TOALTSTACK OP_TOALTSTACK")
        + _hash_input_column(input_count, 1) + _hash_input_column(input_count, 0)
        + selected + asm("OP_TOALTSTACK OP_DUP OP_TOALTSTACK") + _funding_output()
        + asm("OP_ROT OP_EQUALVERIFY OP_FROMALTSTACK") + push(blob(COMPACT_SCRIPTCODE))
        + asm("OP_CAT OP_SWAP OP_CAT OP_FROMALTSTACK OP_CAT "
              "OP_FROMALTSTACK OP_FROMALTSTACK OP_CAT OP_SWAP OP_CAT "
              "OP_FROMALTSTACK OP_CAT OP_FROMALTSTACK OP_CAT "
              "OP_FROMALTSTACK OP_FROMALTSTACK OP_ROT OP_CAT")
        + push(b"\x41\x00\x00\x00") + asm("OP_CAT")
    )


def _count_outputs_in_two_input_parent():
    # The two-input shape may be a spend at verifier vin0 (3 vouts) or a
    # certified mint at verifier vin1 (4 vouts). Determine which from raw.
    skip_input = _split(36) + asm("OP_NIP") + _compact_size() + asm("OP_SPLIT OP_NIP OP_4 OP_SPLIT OP_NIP")
    return (
        asm("OP_2 OP_PICK OP_4 OP_SPLIT OP_NIP") + _count(2)
        + skip_input * 2 + asm("OP_1 OP_SPLIT OP_DROP")
    )


def prior_preimage(*, certified_admin=False):
    """Parse the actual parent context, including verifiers at mint or toggle vin1."""
    ordinary = _prior_preimage(2)
    if certified_admin:
        ordinary = (
            asm("OP_2 OP_NUMEQUAL OP_IF") + _prior_preimage(2, output_count=2, verifier_index=1)
            + asm("OP_ELSE") + ordinary + asm("OP_ENDIF")
        )
    vin_one = _prior_preimage(2, output_count=4, verifier_index=1)
    cases = (
        asm("OP_DUP OP_4 OP_NUMEQUAL OP_IF OP_DROP") + vin_one + asm("OP_ELSE") + ordinary + asm("OP_ENDIF")
        if certified_admin else push(b"\x04") + asm("OP_EQUAL OP_IF") + vin_one + asm("OP_ELSE") + ordinary + asm("OP_ENDIF")
    )
    return (
        asm("OP_2 OP_PICK OP_4 OP_SPLIT OP_NIP OP_1 OP_SPLIT OP_DROP")
        + push(b"\x02") + asm("OP_EQUAL OP_IF")
        + _count_outputs_in_two_input_parent() + cases
        + asm("OP_ELSE") + _prior_preimage(3) + asm("OP_ENDIF")
    )


def continuity_digest(asset_id, key_digest):
    """Consume [receipt payload, transaction context digest]; leave proof digest."""
    prefix = CONTINUITY_DOMAIN + fixed(asset_id, 32) + fixed(key_digest, 32)
    return asm("OP_SWAP OP_CAT") + push(prefix) + asm("OP_SWAP OP_CAT OP_HASH256")


def prior_digest(asset_id, key_digest, *, certified_admin=False):
    return prior_preimage(certified_admin=certified_admin) + asm("OP_HASH256") + continuity_digest(asset_id, key_digest)


def statement_limbs(asset_id, key_digest):
    return continuity_digest(asset_id, key_digest) + digest_limbs_script()


def vin_one_transaction_material_check(*, preceding_outputs=3, select_parent_script=False):
    """Authenticate [parent, outputs, prevouts, preimage] for verifier vin1.

    Leave the actual parent, its selected output script if requested, the final
    receipt output, and the authenticated preimage. The vin0 covenant executes
    separately and the executing verifier checks its compact signature later.
    """
    if select_parent_script:
        selected = (
            asm("OP_TOALTSTACK OP_2 OP_PICK OP_HASH256 OP_EQUALVERIFY OP_1 OP_PICK OP_FROMALTSTACK")
            + _unsigned() + _select_parent_output() + asm("OP_SWAP")
        )
    else:
        selected = push(bytes(4)) + asm("OP_EQUALVERIFY OP_2 OP_PICK OP_HASH256 OP_EQUALVERIFY")
    return (
        asm("OP_SIZE 192 OP_NUMEQUALVERIFY OP_DUP OP_TOALTSTACK")
        + asm("OP_DUP OP_4 OP_SPLIT OP_NIP 32 OP_SPLIT OP_DROP")
        + asm("OP_2 OP_PICK OP_HASH256 OP_EQUALVERIFY")
        + _split(152) + asm("OP_NIP 32 OP_SPLIT OP_DROP OP_2 OP_PICK OP_HASH256 OP_EQUALVERIFY")
        + asm("OP_SIZE 72 OP_NUMEQUALVERIFY OP_FROMALTSTACK OP_DUP OP_TOALTSTACK")
        + _split(CURRENT_OUTPOINT) + asm("OP_NIP 36 OP_SPLIT OP_DROP")
        + asm("OP_OVER 36 OP_SPLIT OP_NIP OP_EQUALVERIFY")
        + asm("36 OP_SPLIT OP_DROP 32 OP_SPLIT") + selected
        + _skip_output() * preceding_outputs
        + asm("OP_SIZE") + number(len(OUTPUT_PREFIX) + PARENT_SIZE) + asm("OP_NUMEQUALVERIFY OP_FROMALTSTACK")
    )
