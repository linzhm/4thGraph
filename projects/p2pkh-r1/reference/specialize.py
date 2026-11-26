"""Size and verify mode-specific P2PKH-R1 locks as an experimental comparison."""
from assemble import assemble
from fourthgraph.bsv.script import asm


def specialized_lock(owner, family):
    # Preserve the native scriptCode suffix so the standard signer can
    # generate both the positive and excluded-mode controls.
    p_type = assemble(owner, compiled_curve=True, entry="P_TYPE")
    if family in ("bip143", "forkid"):
        unsigned = assemble(owner, compiled_curve=True, entry="LE_UNSIGNED")
        overrides = {
            "SELECT_AUTHORIZATION": (
                asm("OP_NOT OP_VERIFY 2 OP_PICK OP_SIZE 159 OP_NUMEQUALVERIFY OP_DROP "
                    "2 OP_PICK 104 OP_SPLIT OP_NIP 3 OP_SPLIT OP_DROP 0x0268ac OP_EQUALVERIFY") + p_type
            ),
            "CHECK_TYPE": asm("0x7fffffff OP_AND") + unsigned + asm("65 68 OP_WITHIN OP_VERIFY"),
            "NATIVE_BINDING": (
                asm("OP_FROMALTSTACK OP_DROP OP_0 OP_IF OP_ELSE OP_CODESEPARATOR OP_ENDIF OP_CHECKSIG")
            ),
        }
    elif family == "otda":
        companion = assemble(owner, compiled_curve=True, entry="COMPANION_AUTHORIZATION")
        overrides = {
            "SELECT_AUTHORIZATION": (
                asm("OP_IF") + companion + asm("OP_ELSE") + p_type
                + asm("OP_DUP OP_1 OP_SPLIT OP_DROP 0x20 OP_AND 0x20 OP_EQUALVERIFY OP_ENDIF")
            ),
        }
    else:
        raise ValueError("expected bip143 or otda specialization")
    return assemble(owner, compiled_curve=True, injected=overrides)
