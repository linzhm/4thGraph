"""BSV statement boundary for the committed Chronicle transfer circuit."""

from chronicle_preimage import CHRONICLE_ALL, VERIFIER_SEQUENCES
from chronicle_preimage_script import otda_all_fields
from continuity_statement import COMMITTED_CONTINUITY_DOMAIN, COMMITTED_OUTPUT_PREFIX, COMMITTED_PARENT_SLOTS
from mimo_verifier import _match_prefix
from parent_preimage import _skip_output
from shared.script import asm, number, push
from statement import fixed
from transfer import digest_limbs_script


def statement_script(asset_id, self_key, *, token_inputs, token_outputs):
    """Consume the 0x61 preimage above proof fields and leave two uint128 limbs.

    The shared verifier is vin zero and the last output is the receipt. Follow
    this statement with Groth16 verification and `bind_all_context()` to check
    the saved digest and signature type against the actual executing input.
    """
    if any(type(count) is not int or not 1 <= count <= COMMITTED_PARENT_SLOTS
           for count in (token_inputs, token_outputs)):
        raise ValueError("expected one to four token inputs and outputs")
    header = COMMITTED_CONTINUITY_DOMAIN + fixed(asset_id, 32) + fixed(self_key, 32)
    sequence = VERIFIER_SEQUENCES[CHRONICLE_ALL].to_bytes(4, "little")
    receipt_prefix = COMMITTED_OUTPUT_PREFIX + bytes([token_inputs])
    return (
        push(bytes([CHRONICLE_ALL])) + asm("OP_TOALTSTACK OP_DUP OP_HASH256 OP_TOALTSTACK")
        + otda_all_fields(1 + token_inputs, 1 + token_outputs, 0)
        # Keep only the output vector after checking the executing input's sequence.
        + asm("OP_DROP OP_SWAP") + push(sequence) + asm("OP_EQUALVERIFY OP_TOALTSTACK")
        + asm("OP_2DROP OP_2DROP OP_FROMALTSTACK")
        + _skip_output() * token_outputs + _match_prefix(receipt_prefix)
        + asm("OP_SIZE 32 OP_NUMEQUALVERIFY") + number(token_inputs) + asm("OP_SWAP OP_CAT")
        + asm("OP_FROMALTSTACK OP_DUP OP_TOALTSTACK") + push(header)
        + asm("OP_SWAP OP_CAT OP_SWAP OP_CAT OP_HASH256") + digest_limbs_script()
    )
