"""Construct, recognize, and authorize canonical P2PKH-SM2 payments."""
from functools import cache
from hashlib import sha256
import json
from pathlib import Path
from assemble import TEMPLATE_VERSION, assemble
from sighash import authorization
from sm2 import USER_ID,hash256,public_key_hash160,verify
from fourthgraph.bsv.otda_reconstruction import Reconstruction
from fourthgraph.bsv.script import push
from fourthgraph.bsv.transaction import Transaction,Input,Output,preimage_all,amount

VERSIONS = Path(__file__).resolve().parents[1] / "versions"
MANIFEST = VERSIONS / "v1.0.0/layout.json"
CONSTRUCTOR_LAYOUT = VERSIONS / "v1.1.0/layout.json"
RECONSTRUCT_ALL = frozenset((0x61, 0xe1))
RECONSTRUCT_SINGLE = frozenset((0x63, 0xe3))


@cache
def _canonical():
    layout=json.loads(MANIFEST.read_text())
    raw=assemble(bytes(20))
    if (layout['version']!=TEMPLATE_VERSION or len(raw)!=layout['script_bytes']
            or sha256(raw).hexdigest()!=layout['base_script_sha256']):
        raise ValueError('canonical SM2 template differs from manifest')
    start=layout['owner_hash160']['offset']
    if raw[start:start+20]!=bytes(20) or sha256(raw[:start]+raw[start+20:]).hexdigest()!=layout['fixed_bytes_sha256']:
        raise ValueError('invalid SM2 owner slot/fingerprint')
    return raw,start


def locking_script_from_owner_hash(owner, *, version=TEMPLATE_VERSION):
    if not isinstance(owner,bytes) or len(owner)!=20: raise ValueError('expected a 20-byte owner hash')
    if version != TEMPLATE_VERSION: raise ValueError('unsupported P2PKH-SM2 template version')
    raw,start=_canonical()
    return raw[:start]+owner+raw[start+20:]


def locking_script_from_public_key(key, *, version=TEMPLATE_VERSION):
    return locking_script_from_owner_hash(public_key_hash160(key), version=version)


def identify(raw):
    """Return (version, owner) after verifying the complete locking program."""
    if not isinstance(raw, bytes):
        return None
    template, start = _canonical()
    if (len(raw) == len(template) and raw[:start] == template[:start]
            and raw[start+20:] == template[start+20:]):
        return TEMPLATE_VERSION, raw[start:start+20]
    return None


def recognize(raw):
    result = identify(raw)
    return result[1] if result else None


@cache
def _otda_pattern():
    layout = json.loads(CONSTRUCTOR_LAYOUT.read_text())['otda_constructor']
    program = bytes.fromhex(CONSTRUCTOR_LAYOUT.with_name(layout['file']).read_text(encoding='ascii'))
    if len(program) != layout['bytes'] or sha256(program).hexdigest() != layout['sha256']:
        raise ValueError('SM2 OTDA constructor differs from its manifest')
    template, start = _canonical()
    return Reconstruction(program, (template[:start], template[start+20:]), (20,))


def _preimage_script(tx, index, auth, *, compress_otda, chronicle_active):
    if compress_otda is not None and type(compress_otda) is not bool:
        raise ValueError('compress_otda must be a boolean')
    if compress_otda is True and not chronicle_active:
        raise ValueError('SM2 OTDA reconstruction requires an active Chronicle context')
    literal = push(auth.preimage)
    if not chronicle_active or compress_otda is False or tx.version != 2 or auth.companion:
        return literal
    if auth.requested_type in RECONSTRUCT_ALL:
        outputs = tx.outputs
    elif auth.requested_type in RECONSTRUCT_SINGLE:
        outputs = (tx.outputs[index],)
    else:
        return literal
    program = _otda_pattern().build(auth.preimage, outputs)
    return program if program is not None and len(program) < len(literal) else literal


def current_input_unlock(tx, index, previous_amount, key, signature, sighash_type=0x41,
                         *, chronicle_active=True, version=TEMPLATE_VERSION, compress_otda=None):
    public_key_hash160(key)
    if version != TEMPLATE_VERSION:
        raise ValueError('unsupported P2PKH-SM2 template version')
    auth = authorization(tx, index, previous_amount, sighash_type, chronicle_active=chronicle_active)
    preimage_script = _preimage_script(tx, index, auth, compress_otda=compress_otda,
                                       chronicle_active=chronicle_active)
    return _encode_unlock(auth, key, signature, preimage_script)


def _encode_unlock(auth, key, signature, preimage_script):
    message = auth.message
    k1_n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    k1_gx=0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    if (int.from_bytes(message,'big')+k1_gx)%k1_n==0:
        raise ValueError('degenerate PUSHTX digest; rebuild the transaction')
    if not verify(key,message,signature): raise ValueError('invalid SM2 authorization')
    return preimage_script+push(key)+push(signature)


def sign_previous(tx, index, previous, key, signer, sighash_type, chronicle_active, *, compress_otda=None):
    template = identify(previous.script)
    if template is None or template[1] != public_key_hash160(key):
        raise ValueError('funding output does not belong to key/template')
    auth = authorization(tx, index, previous.value, sighash_type, chronicle_active=chronicle_active)
    preimage_script = _preimage_script(tx, index, auth, compress_otda=compress_otda,
                                       chronicle_active=chronicle_active)
    return tx.with_script(index, _encode_unlock(auth, key, signer(auth.message, USER_ID), preimage_script))


def sign_input(tx, index, funding_raw, key, signer, sighash_type=0x41, *, chronicle_active=True,
               compress_otda=None):
    """Sign one input after matching its outpoint to the previous transaction.

    The caller selects coverage and supplies the chain activation context.
    Eligible version-2 spends automatically use a shorter reconstruction.
    Pass compress_otda=False to reproduce the literal encoding.
    Other inputs, including their existing unlocking scripts, are preserved.
    """
    if not 0 <= index < len(tx.inputs):
        raise ValueError('invalid input index')
    current = tx.inputs[index]
    funding = Transaction.parse(funding_raw)
    if funding.txid_wire() != current.txid or not 0 <= current.vout < len(funding.outputs):
        raise ValueError('funding transaction does not match current outpoint')
    return sign_previous(tx, index, funding.outputs[current.vout], key, signer,
                          sighash_type, chronicle_active, compress_otda=compress_otda)


def sign_payment(funding_raw,vout,outputs,fee,key,signer):
    """One-input BIP143 ALL payment. signer(SHA256d(P), user_id) returns r||s."""
    funding=Transaction.parse(funding_raw)
    if not 0<=vout<len(funding.outputs): raise ValueError('invalid funding output')
    previous=funding.outputs[vout]
    amount(fee); outputs=tuple(outputs)
    if not outputs: raise ValueError('payment requires outputs')
    for out in outputs: out.serialize()
    if sum(x.value for x in outputs)+fee!=previous.value: raise ValueError('outputs and fee must equal input value')
    tx=Transaction((Input(funding.txid_wire(),vout),),outputs)
    return sign_previous(tx, 0, previous, key, signer, 0x41, False)
