"""Generate or check the pinned Lamport v0.2.0 lock and OTDA program."""
import argparse
from hashlib import sha256
import json

from script import compile_forth_pattern
from fixed_template import COMMITMENT_BYTES, TEMPLATE_DIRECTORY, VERSION


def build_artifacts():
    pattern = compile_forth_pattern(packed=True)
    prefix, suffix = pattern.fixed_parts
    lock = prefix + bytes(COMMITMENT_BYTES) + suffix

    def artifact(filename, data):
        return dict(file=filename, bytes=len(data), sha256=sha256(data).hexdigest())

    layout = {
        'version': VERSION,
        'commitment_offset': len(prefix),
        'lock': artifact('template.hex', lock),
        'reconstruction': artifact('otda-reconstruct.hex', pattern.program),
    }
    return {
        'layout.json': json.dumps(layout, indent=2) + '\n',
        layout['lock']['file']: lock.hex() + '\n',
        layout['reconstruction']['file']: pattern.program.hex() + '\n',
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    check = parser.parse_args().check
    if not check:
        TEMPLATE_DIRECTORY.mkdir(exist_ok=True)
    for name, content in build_artifacts().items():
        path = TEMPLATE_DIRECTORY / name
        if check:
            if path.read_text(encoding='ascii') != content:
                parser.exit(1, f'Lamport artifact differs from source: {name}\n')
        else:
            path.write_text(content, encoding='ascii')
