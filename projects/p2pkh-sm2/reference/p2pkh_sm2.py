"""Construct, recognize, and authorize canonical P2PKH-SM2 payments."""
from functools import cache
from hashlib import sha256
import json
from pathlib import Path
from assemble import SIGNED_WINDOW_TEMPLATE_VERSION, SPLIT_ROTATION_TEMPLATE_VERSION
from assemble import TEMPLATE_PROFILES, TEMPLATE_VERSION, assemble
from sighash import authorization
from sm2 import USER_ID,hash256,public_key_hash160,verify
from fourthgraph.bsv.otda_reconstruction import Reconstruction, reconstruct_mixed
from fourthgraph.bsv.script import push
from fourthgraph.bsv.transaction import Transaction,Input,Output,preimage_all,amount

VERSIONS = Path(__file__).resolve().parents[1] / 'versions'
LOCK_LAYOUTS = {version: VERSIONS / profile / 'layout.json'
                for version, profile in TEMPLATE_PROFILES.items()}
CONSTRUCTOR_LAYOUTS = LOCK_LAYOUTS | {
    TEMPLATE_VERSION: VERSIONS / 'v1.1.0/layout.json',
}
MIXED_OTDA_VERSIONS = (SPLIT_ROTATION_TEMPLATE_VERSION, SIGNED_WINDOW_TEMPLATE_VERSION)
MIXED_OTDA_FILE = VERSIONS / 'v1.8.0/mixed-otda-constructor.json'
RECONSTRUCT_ALL = frozenset((0x61, 0xe1))
RECONSTRUCT_SINGLE = frozenset((0x63, 0xe3))


@cache
def _layout(version):
    if version not in LOCK_LAYOUTS:
        raise ValueError('unsupported P2PKH-SM2 template version')
    return json.loads(LOCK_LAYOUTS[version].read_text(encoding='utf-8'))


@cache
def _canonical(version=TEMPLATE_VERSION):
    layout = _layout(version)
    raw = assemble(bytes(20), version)
    if (layout['version']!=version or len(raw)!=layout['script_bytes']
            or sha256(raw).hexdigest()!=layout['base_script_sha256']):
        raise ValueError('canonical SM2 template differs from manifest')
    start=layout['owner_hash160']['offset']
    if raw[start:start+20]!=bytes(20) or sha256(raw[:start]+raw[start+20:]).hexdigest()!=layout['fixed_bytes_sha256']:
        raise ValueError('invalid SM2 owner slot/fingerprint')
    return raw,start


def locking_script_from_owner_hash(owner, *, version=TEMPLATE_VERSION):
    if not isinstance(owner,bytes) or len(owner)!=20: raise ValueError('expected a 20-byte owner hash')
    raw,start=_canonical(version)
    return raw[:start]+owner+raw[start+20:]


def locking_script_from_public_key(key, *, version=TEMPLATE_VERSION):
    return locking_script_from_owner_hash(public_key_hash160(key), version=version)


def identify(raw):
    """Return (version, owner) after verifying the complete locking program."""
    if not isinstance(raw, bytes):
        return None
    for version in LOCK_LAYOUTS:
        if len(raw) != _layout(version)['script_bytes']:
            continue
        template, start = _canonical(version)
        if raw[:start] == template[:start] and raw[start+20:] == template[start+20:]:
            return version, raw[start:start+20]
    return None


def recognize(raw):
    result = identify(raw)
    return result[1] if result else None


@cache
def _otda_pattern(version=TEMPLATE_VERSION):
    path = CONSTRUCTOR_LAYOUTS[version]
    layout = json.loads(path.read_text(encoding='utf-8'))['otda_constructor']
    program = bytes.fromhex(path.with_name(layout['file']).read_text(encoding='ascii'))
    if len(program) != layout['bytes'] or sha256(program).hexdigest() != layout['sha256']:
        raise ValueError('SM2 OTDA constructor differs from its manifest')
    template, start = _canonical(version)
    return Reconstruction(program, (template[:start], template[start+20:]), (20,))


@cache
def _mixed_otda_program():
    record = json.loads(MIXED_OTDA_FILE.read_text(encoding='utf-8'))
    program = bytes.fromhex(record['program_hex'])
    if (tuple(record['templates']) != MIXED_OTDA_VERSIONS or len(program) != record['bytes']
            or sha256(program).hexdigest() != record['sha256']):
        raise ValueError('mixed SM2 OTDA constructor differs from its manifest')
    return program


def _combine_otda_programs(patterns):
    pair = tuple(_otda_pattern(version) for version in MIXED_OTDA_VERSIONS)
    for index in range(len(patterns) - 1):
        if patterns[index:index + 2] == pair:
            programs = [pattern.program for pattern in patterns]
            programs[index:index + 2] = [_mixed_otda_program()]
            return b''.join(programs)
    return None


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
    output_sizes = {len(output.script) for output in outputs}
    patterns = {version: _otda_pattern(version) for version in LOCK_LAYOUTS
                if _layout(version)['script_bytes'] in output_sizes}
    candidates = [literal]
    for pattern in patterns.values():
        if (program := pattern.build(auth.preimage, outputs)) is not None:
            candidates.append(program)
    if len(patterns) > 1:
        combine = _combine_otda_programs if all(version in patterns for version in MIXED_OTDA_VERSIONS) else None
        program = reconstruct_mixed(auth.preimage, outputs, tuple(patterns.values()), combine_programs=combine)
        if program is not None:
            candidates.append(program)
    return min(candidates, key=len)


def current_input_unlock(tx, index, previous_amount, key, signature, sighash_type=0x41,
                         *, chronicle_active=True, version=TEMPLATE_VERSION, compress_otda=None):
    public_key_hash160(key)
    if version not in LOCK_LAYOUTS:
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
