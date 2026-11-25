"""Current-input P2PKH-R1 signing messages and unlocking scripts."""
from dataclasses import dataclass
from hashlib import sha256

from tx_engine import Script, sig_hash_preimage

from fixed_templates import compiled_template, otda_reconstruction

GROUP_ORDER_R1 = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
UNIVERSAL_FLAGS = frozenset({base | mode for base in (0x41, 0x42, 0x43)
                             for mode in (0, 0x20, 0x80, 0xa0)})

# The last executed separator differs between ordinary and companion authorization.
ORDINARY_CODE = bytes.fromhex("68ac")
COMPANION_CODE = bytes.fromhex("63ad67ab68ac")
COMPRESSIBLE_OTDA_TYPES = (0x61, 0xe1)


@dataclass(frozen=True)
class SpendAuthorization:
    requested_type: int
    preimage: bytes
    companion: bool

    def digest(self):
        return sha256(sha256(self.preimage).digest()).digest()


def authorization(tx, index, amount, requested_type):
    if requested_type not in UNIVERSAL_FLAGS or not 0 <= index < len(tx.tx_ins):
        raise ValueError("unsupported sighash or input index")
    companion = (requested_type & 0x7f) == 0x63 and index >= len(tx.tx_outs)
    actual = requested_type & ~0x20 if companion else requested_type
    otda = bool(actual & 0x20)
    code = COMPANION_CODE if companion else ORDINARY_CODE
    if otda:
        suffix = Script()
        suffix.append_data(code)
        pre = bytes(sig_hash_preimage(tx, index, suffix, amount, actual))
    else:
        # Supply the actual executed branch's scriptCode verbatim, including its
        # unexecuted separator. A lexical last-separator search cannot infer this path.
        pre = bytes(sig_hash_preimage(tx, index, Script.parse_string("OP_CHECKSIG"), amount, actual))
        if len(pre) != 158 or pre[104:106] != bytes.fromhex("01ac"):
            raise ValueError("unexpected engine BIP143 layout")
        pre = pre[:104] + bytes([len(code)]) + code + pre[106:]
    return SpendAuthorization(requested_type, pre, companion)


def _compressed_otda_preimage(tx, preimage, *, shared_kernels):
    version, program = otda_reconstruction(shared_kernels=shared_kernels)
    if tx.version != version:
        return None
    template = compiled_template()
    outputs = []
    has_template_output = False
    for output in tx.tx_outs:
        script = output.script_pubkey
        owner = template.owner(script.raw_serialize())
        has_template_output |= owner is not None
        raw = output.amount.to_bytes(8, "little", signed=True) + script.serialize()
        outputs.append((raw, owner))
    if not has_template_output:
        return None

    # The last eight bytes are locktime and sighash type. Verify the
    # serialized output block before replacing it with reconstruction code.
    serialized = b"".join(raw for raw, _ in outputs)
    if not preimage.endswith(serialized, 0, len(preimage) - 8):
        raise ValueError("OTDA outputs differ from the signing preimage")
    out = Script()
    out.append_data(program)
    out.append_pushdata(preimage[:-len(serialized) - 8])
    # main: fixed prefix, fixed suffix, reconstructed preimage so far.
    for raw, owner in outputs:
        if owner is None:
            out.append_pushdata(raw)
            out.append_data(b"\x7e")  # OP_CAT
        else:
            out.append_pushdata(raw[:-len(template.script)])
            out.append_data(bytes.fromhex("7e52797e"))  # OP_CAT OP_2 OP_PICK OP_CAT
            out.append_pushdata(owner)
            out.append_data(bytes.fromhex("7e787e"))  # OP_CAT OP_OVER OP_CAT
    out.append_pushdata(preimage[-8:])
    out.append_data(bytes.fromhex("7e7b757c75"))  # OP_CAT OP_ROT OP_DROP OP_SWAP OP_DROP
    return out


def current_input_unlock(auth, pubkey, signature, *, compress_otda_for=None, shared_kernels=False):
    """Serialize the four stack values and the derived companion selector."""
    if len(pubkey) != 65 or pubkey[0] != 4 or len(signature) != 64:
        raise ValueError("expected X9.63 public key and raw R1 signature")
    s = int.from_bytes(signature[32:], "big")
    if not 0 < s < GROUP_ORDER_R1:
        raise ValueError("invalid P-256 signature scalar")
    inverse = pow(s, -1, GROUP_ORDER_R1).to_bytes(32, "little")
    out = Script()
    out.append_pushdata(auth.preimage)
    if compress_otda_for is not None and auth.requested_type in COMPRESSIBLE_OTDA_TYPES:
        compressed = _compressed_otda_preimage(
            compress_otda_for, auth.preimage, shared_kernels=shared_kernels,
        )
        if compressed is not None and len(compressed.raw_serialize()) < len(out.raw_serialize()):
            out = compressed
    for data in (pubkey, signature):
        out.append_pushdata(data)
    out.append_pushdata(inverse)
    out.append_data(bytes([0x51 if auth.companion else 0x00]))
    return out
