"""Construct, recognize, and authorize canonical P2PKH-SM2 payments."""
from functools import cache
from hashlib import sha256
import json
from pathlib import Path
from assemble import assemble
from sighash import authorization
from sm2 import USER_ID,hash256,public_key_hash160,verify
from shared.script import push
from shared.transaction import Transaction,Input,Output,preimage_all,amount

MANIFEST=Path(__file__).resolve().parents[1]/'template/layout.json'


@cache
def _canonical(version=2):
    if version not in (1, 2):
        raise ValueError('unknown P2PKH-SM2 version')
    manifest = MANIFEST if version == 2 else MANIFEST.with_name('layout-v1.json')
    layout=json.loads(manifest.read_text())
    raw=assemble(bytes(20), version)
    if len(raw)!=layout['script_bytes'] or sha256(raw).hexdigest()!=layout['base_script_sha256']:
        raise ValueError('canonical SM2 template differs from manifest')
    start=layout['owner_hash160']['offset']
    if raw[start:start+20]!=bytes(20) or sha256(raw[:start]+raw[start+20:]).hexdigest()!=layout['fixed_bytes_sha256']:
        raise ValueError('invalid SM2 owner slot/fingerprint')
    return raw,start


def locking_script_from_owner_hash(owner, *, version=2):
    if not isinstance(owner,bytes) or len(owner)!=20: raise ValueError('expected a 20-byte owner hash')
    raw,start=_canonical(version)
    return raw[:start]+owner+raw[start+20:]


def locking_script_from_public_key(key, *, version=2):
    return locking_script_from_owner_hash(public_key_hash160(key), version=version)


def identify(raw):
    """Return (version, owner) after verifying the complete locking program."""
    if not isinstance(raw, bytes):
        return None
    for version in (2, 1):
        template, start = _canonical(version)
        if (len(raw) == len(template) and raw[:start] == template[:start]
                and raw[start+20:] == template[start+20:]):
            return version, raw[start:start+20]
    return None


def recognize(raw):
    result = identify(raw)
    return result[1] if result else None


def current_input_unlock(tx, index, previous_amount, key, signature, sighash_type=0x41,
                         *, chronicle_active=True, version=2):
    public_key_hash160(key)
    if version not in (1, 2) or (version == 1 and sighash_type != 0x41):
        raise ValueError('sighash type unavailable for this template version')
    auth = authorization(tx, index, previous_amount, sighash_type, chronicle_active=chronicle_active)
    return _encode_unlock(auth, key, signature)


def _encode_unlock(auth, key, signature):
    preimage = auth.preimage
    message = auth.message
    k1_n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    k1_gx=0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    if (int.from_bytes(message,'big')+k1_gx)%k1_n==0:
        raise ValueError('degenerate PUSHTX digest; rebuild the transaction')
    if not verify(key,message,signature): raise ValueError('invalid SM2 authorization')
    return push(preimage)+push(key)+push(signature)


def _sign_previous(tx, index, previous, key, signer, sighash_type, chronicle_active):
    template = identify(previous.script)
    if template is None or template[1] != public_key_hash160(key):
        raise ValueError('funding output does not belong to key/template')
    if template[0] == 1 and sighash_type != 0x41:
        raise ValueError('v1 outputs require ForkID ALL')
    auth = authorization(tx, index, previous.value, sighash_type, chronicle_active=chronicle_active)
    return tx.with_script(index, _encode_unlock(auth, key, signer(auth.message, USER_ID)))


def sign_input(tx, index, funding_raw, key, signer, sighash_type=0x41, *, chronicle_active=True):
    """Sign one input after matching its outpoint to the previous transaction.

    The caller selects coverage and supplies the chain activation context.
    Other inputs, including their existing unlocking scripts, are preserved.
    """
    if not 0 <= index < len(tx.inputs):
        raise ValueError('invalid input index')
    current = tx.inputs[index]
    funding = Transaction.parse(funding_raw)
    if funding.txid_wire() != current.txid or not 0 <= current.vout < len(funding.outputs):
        raise ValueError('funding transaction does not match current outpoint')
    return _sign_previous(tx, index, funding.outputs[current.vout], key, signer,
                          sighash_type, chronicle_active)


def sign_payment(funding_raw,vout,outputs,fee,key,signer):
    """One-input ForkID ALL payment. signer(SHA256d(P), user_id) returns r||s."""
    funding=Transaction.parse(funding_raw)
    if not 0<=vout<len(funding.outputs): raise ValueError('invalid funding output')
    previous=funding.outputs[vout]
    amount(fee); outputs=tuple(outputs)
    if not outputs: raise ValueError('payment requires outputs')
    for out in outputs: out.serialize()
    if sum(x.value for x in outputs)+fee!=previous.value: raise ValueError('outputs and fee must equal input value')
    tx=Transaction((Input(funding.txid_wire(),vout),),outputs)
    return _sign_previous(tx, 0, previous, key, signer, 0x41, False)
