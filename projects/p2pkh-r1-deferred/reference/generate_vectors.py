"""Rebuild the public test templates and the deterministic activation vector."""
import argparse
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from textwrap import wrap

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from deferred import (
    ACTIVATION_SIGHASH, ASSEMBLY_TEMPLATE_VERSION, DEFERRED_TEMPLATE_VERSION, TARGET_R1_VERSION,
    activation_preimages, funding_output, public_key_hash160, target_output_from_owner_hash,
)
from fixed_templates import LEGACY_TEMPLATE_VERSION
from forth_lock import RELEASE_OPTIMIZATION, RELEASE_TEMPLATE, compile_template
from fourthgraph.bsv.script import push
from fourthgraph.bsv.transaction import CHRONICLE, SIGHASH_TYPES, Input, Transaction, hash256

TEMPLATE = Path(__file__).resolve().parents[1] / 'template'
ASSEMBLY_TEMPLATE = TEMPLATE / f'v{ASSEMBLY_TEMPLATE_VERSION}'
TEMPLATE_RECIPES = (
    (TEMPLATE, LEGACY_TEMPLATE_VERSION, None, None),
    (ASSEMBLY_TEMPLATE, TARGET_R1_VERSION, ASSEMBLY_TEMPLATE_VERSION, None),
    (RELEASE_TEMPLATE, TARGET_R1_VERSION, DEFERRED_TEMPLATE_VERSION, RELEASE_OPTIMIZATION),
)
FIELDS = {
    'owner_hash160': (1, 20),
    'target_script_sha256': (22, 32),
    'input_value_le64': (109, 8),
    'target_txout_hash256': (134, 32),
}


def fingerprint(script, fields):
    fixed = bytearray(script)
    for offset, length in fields.values():
        fixed[offset:offset + length] = bytes(length)
    return sha256(fixed).hexdigest()


def artifacts(target_r1_version, template_version, optimization):
    fields = FIELDS.copy()
    if optimization is not None:
        compiled = compile_template(optimization)
        value_offset, output_hash_offset = (len(compiled.metadata) + offset for offset in compiled.fields)
        fields.update(input_value_le64=(value_offset, 8), target_txout_hash256=(output_hash_offset, 32))
    vectors = []
    for scalar, value in ((1, 100_000), (2, 120_000), (3, 1)):
        key = ec.derive_private_key(scalar, ec.SECP256R1()).public_key()
        public_key = key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        owner = public_key_hash160(public_key)
        target = target_output_from_owner_hash(value, owner, target_r1_version=target_r1_version)
        output = funding_output(value, public_key, target_r1_version=target_r1_version, optimization=optimization)
        legacy = push(public_key) + output.script[21:]
        vectors.append(dict(id=scalar, value_sats=value, public_key_x963=public_key.hex(),
                            owner_hash160=owner.hex(),
                            target_script_sha256=sha256(target.script).hexdigest(),
                            target_txout_hash256=hash256(target.serialize()).hex(),
                            legacy_locking_script_sha256=sha256(legacy).hexdigest(),
                            locking_script_sha256=sha256(output.script).hexdigest()))
        if optimization is not None:
            vectors[-1]["full_key_locking_script_sha256"] = vectors[-1].pop("legacy_locking_script_sha256")
        if scalar == 1:
            base = output.script
            funding = Transaction((Input(b'\xf0' * 32, 0),), (output,))
            unsigned = Transaction((Input(funding.txid_wire(), 0),), (target,))
            preimage, _ = activation_preimages(unsigned, 0, value, ACTIVATION_SIGHASH)
            witness = push(preimage)
            activation = unsigned.with_script(0, witness)
            payment = dict(vector_id=scalar, funding_tx_hex=funding.serialize().hex(),
                           input_index=0, output_index=0, sighash='43',
                           activation_preimage_hex=preimage.hex(), unlocking_script_hex=witness.hex(),
                           activation_txid=activation.txid())
            modes = []
            for flag in sorted(SIGHASH_TYPES):
                version = 2 if flag & CHRONICLE else 1
                spend = replace(unsigned, version=version)
                preimage, auxiliary = activation_preimages(spend, 0, value, flag)
                witness = (push(auxiliary) if auxiliary else b'') + push(preimage)
                activated = spend.with_script(0, witness)
                modes.append(dict(sighash=f'{flag:02x}', transaction_version=version,
                                  activation_preimage_hex=preimage.hex(), auxiliary_hex=auxiliary.hex(),
                                  unlocking_script_hex=witness.hex(),
                                  activation_txid=activated.txid()))
    layout = dict(template='P2PKH-R1-Deferred', base_script_hex_file='template.hex', script_bytes=len(base),
                  fields={name: dict(offset=offset, length=length) for name, (offset, length) in fields.items()},
                  fixed_bytes_sha256=fingerprint(base, fields), base_vector_id=1,
                  base_script_sha256=sha256(base).hexdigest(), vectors=vectors)
    if template_version is not None:
        layout.update(template_version=template_version, target_r1_version=target_r1_version)
    if optimization is not None:
        layout["optimization"] = optimization
    return {'template.hex': '\n'.join(wrap(base.hex(), 128)) + '\n', 'layout.json': json.dumps(layout, indent=2) + '\n',
            'activation-single.json': json.dumps(payment, indent=2) + '\n',
            'sighash-modes.json': json.dumps(dict(vector_id=1, cases=modes), indent=2) + '\n'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true', help='regenerate the checked-in files')
    args = parser.parse_args()
    for directory, *recipe in TEMPLATE_RECIPES:
        for name, content in artifacts(*recipe).items():
            path = directory / name
            if args.write:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding='ascii')
            elif path.read_text(encoding='ascii') != content:
                parser.error(f'{path} is out of date')


if __name__ == '__main__':
    main()
