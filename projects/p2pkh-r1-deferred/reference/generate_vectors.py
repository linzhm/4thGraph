"""Rebuild the public test templates and the deterministic activation vector."""
import argparse
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from textwrap import wrap

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from deferred import activate_input, activation_preimages, funding_output, recognize, target_output
from fixed_templates import LEGACY_TEMPLATE_VERSION, TEMPLATE_VERSION
from fourthgraph.bsv.script import push
from fourthgraph.bsv.transaction import CHRONICLE, SIGHASH_TYPES, Input, Transaction

VERSIONS = Path(__file__).resolve().parents[1] / 'versions'
TEMPLATE = VERSIONS / f'v{LEGACY_TEMPLATE_VERSION}'
RELEASE_TEMPLATE = VERSIONS / f'v{TEMPLATE_VERSION}'
FIELDS = {
    'owner_hash160': (1, 20),
    'target_script_sha256': (22, 32),
    'input_value_le64': (109, 8),
    'target_txout_hash256': (134, 32),
}


def fingerprint(script):
    fixed = bytearray(script)
    for offset, length in FIELDS.values():
        fixed[offset:offset + length] = bytes(length)
    return sha256(fixed).hexdigest()


def artifacts(*, target_r1_version):
    vectors = []
    for scalar, value in ((1, 100_000), (2, 120_000), (3, 1)):
        key = ec.derive_private_key(scalar, ec.SECP256R1()).public_key()
        public_key = key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        output = funding_output(value, public_key, target_r1_version=target_r1_version)
        commitment = recognize(output)
        legacy = push(public_key) + output.script[21:]
        vectors.append(dict(id=scalar, value_sats=value, public_key_x963=public_key.hex(),
                            owner_hash160=commitment.owner_hash160.hex(),
                            target_script_sha256=commitment.script_hash.hex(),
                            target_txout_hash256=commitment.output_hash.hex(),
                            legacy_locking_script_sha256=sha256(legacy).hexdigest(),
                            locking_script_sha256=sha256(output.script).hexdigest()))
        if scalar == 1:
            base = output.script
            funding = Transaction((Input(b'\xf0' * 32, 0),), (output,))
            target = target_output(value, public_key, target_r1_version=target_r1_version)
            unsigned = Transaction((Input(funding.txid_wire(), 0),), (target,))
            activation = activate_input(unsigned, 0, funding.serialize())
            witness = activation.inputs[0].script
            payment = dict(vector_id=scalar, funding_tx_hex=funding.serialize().hex(),
                           input_index=0, output_index=0, sighash='43',
                           activation_preimage_hex=witness[2:].hex(), unlocking_script_hex=witness.hex(),
                           activation_txid=activation.txid())
            modes = []
            for flag in sorted(SIGHASH_TYPES):
                version = 2 if flag & CHRONICLE else 1
                spend = replace(unsigned, version=version)
                preimage, auxiliary = activation_preimages(spend, 0, value, flag)
                activated = activate_input(spend, 0, funding.serialize(), sighash=flag)
                modes.append(dict(sighash=f'{flag:02x}', transaction_version=version,
                                  activation_preimage_hex=preimage.hex(), auxiliary_hex=auxiliary.hex(),
                                  unlocking_script_hex=activated.inputs[0].script.hex(),
                                  activation_txid=activated.txid()))
    layout = dict(template='P2PKH-R1-Deferred', base_script_hex_file='template.hex', script_bytes=len(base),
                  fields={name: dict(offset=offset, length=length) for name, (offset, length) in FIELDS.items()},
                  fixed_bytes_sha256=fingerprint(base), base_vector_id=1,
                  base_script_sha256=sha256(base).hexdigest(), vectors=vectors)
    if target_r1_version == TEMPLATE_VERSION:
        layout.update(template_version=TEMPLATE_VERSION, target_r1_version=target_r1_version)
    return {'template.hex': '\n'.join(wrap(base.hex(), 128)) + '\n', 'layout.json': json.dumps(layout, indent=2) + '\n',
            'activation-single.json': json.dumps(payment, indent=2) + '\n',
            'sighash-modes.json': json.dumps(dict(vector_id=1, cases=modes), indent=2) + '\n'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true', help='regenerate the checked-in files')
    args = parser.parse_args()
    for directory, version in ((TEMPLATE, LEGACY_TEMPLATE_VERSION), (RELEASE_TEMPLATE, TEMPLATE_VERSION)):
        for name, content in artifacts(target_r1_version=version).items():
            path = directory / name
            if args.write:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding='ascii')
            elif path.read_text(encoding='ascii') != content:
                parser.error(f'{path} is out of date')


if __name__ == '__main__':
    main()
