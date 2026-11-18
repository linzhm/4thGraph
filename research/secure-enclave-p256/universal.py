"""Wallet for P2PKH-R1 v7. All byte strings are serialized in BSV wire order."""
from dataclasses import dataclass
from hashlib import sha256

from tx_engine import Script, sig_hash_preimage

from handwritten import GROUP_ORDER_R1, UNIVERSAL_FLAGS

# The last executed separator differs between ordinary and companion authorization.
ORDINARY_CODE = bytes.fromhex("68ac")
COMPANION_CODE = bytes.fromhex("63ad67ab68ac")


@dataclass(frozen=True)
class SpendAuthorization:
    requested_type: int
    preimage: bytes
    ordinal: int
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
    ordinal = index if otda and not actual & 0x80 else 0
    return SpendAuthorization(requested_type, pre, ordinal, companion)


def universal_unlocking_script(parent, auth, pubkey, signature):
    if not parent or len(pubkey) != 65 or pubkey[0] != 4 or len(signature) != 64:
        raise ValueError("expected parent, X9.63 public key and raw R1 signature")
    s = int.from_bytes(signature[32:], "big")
    if not 0 < s < GROUP_ORDER_R1:
        raise ValueError("invalid P-256 signature scalar")
    inverse = pow(s, -1, GROUP_ORDER_R1).to_bytes(32, "little")
    out = Script()
    for data in (parent, auth.preimage, pubkey, signature, auth.ordinal.to_bytes(4, "little"), inverse):
        out.append_pushdata(data)
    out.append_data(bytes([0x51 if auth.companion else 0x00]))
    return out
