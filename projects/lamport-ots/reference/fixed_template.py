"""Load the Lamport v0.2.0 candidate without compiling its Forth source."""
from functools import cache
from hashlib import sha256
import json
from pathlib import Path

from fourthgraph.bsv.otda_reconstruction import Reconstruction

VERSION = '0.2.0'
TEMPLATE_DIRECTORY = Path(__file__).resolve().parents[1] / 'versions' / f'v{VERSION}'
COMMITMENT_BYTES = 32


def _read_bytes(artifact):
    data = bytes.fromhex((TEMPLATE_DIRECTORY / artifact['file']).read_text(encoding='ascii'))
    if len(data) != artifact['bytes'] or sha256(data).hexdigest() != artifact['sha256']:
        raise ValueError(f'Lamport artifact differs from its layout: {artifact["file"]}')
    return data


@cache
def v020_forth_pattern():
    layout = json.loads((TEMPLATE_DIRECTORY / 'layout.json').read_text(encoding='ascii'))
    lock = _read_bytes(layout['lock'])
    program = _read_bytes(layout['reconstruction'])
    offset = layout['commitment_offset']
    end = offset + COMMITMENT_BYTES
    if (layout['version'] != VERSION or not 0 < offset < end < len(lock)
            or lock[offset - 1] != COMMITMENT_BYTES or lock[offset:end] != bytes(COMMITMENT_BYTES)):
        raise ValueError('invalid Lamport v0.2.0 commitment field')
    return Reconstruction(program, (lock[:offset], lock[end:]), (COMMITMENT_BYTES,))
