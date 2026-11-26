"""Generate or recognize a P2PKH-R1-Deferred locking script."""
import argparse
import json
from pathlib import Path
import sys

from deferred import OPTIMIZATIONS, funding_output, funding_output_from_owner_hash, recognize
from fourthgraph.bsv.transaction import Output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--value', type=int, required=True, help='actual output amount in satoshis')
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--public-key', metavar='HEX')
    source.add_argument('--owner-hash160', metavar='HEX')
    source.add_argument('--script-file', type=Path, metavar='RAW_SCRIPT')
    parser.add_argument('--format', choices=('json', 'raw'), default='json')
    parser.add_argument('--optimize', choices=OPTIMIZATIONS, help='generate a Forth lock in this compiler mode')
    args = parser.parse_args()
    if args.script_file is not None and args.optimize is not None:
        parser.error('--optimize is available when generating a lock')
    try:
        if args.public_key is not None:
            output = funding_output(args.value, bytes.fromhex(args.public_key), optimization=args.optimize)
        elif args.owner_hash160 is not None:
            output = funding_output_from_owner_hash(args.value, bytes.fromhex(args.owner_hash160),
                                                    optimization=args.optimize)
        else:
            output = Output(args.value, args.script_file.read_bytes())
        commitment = recognize(output)
        if commitment is None:
            parser.error('script and value do not match the canonical deferred format')
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if args.format == 'raw':
        sys.stdout.buffer.write(output.script)
    else:
        fields = {
            'value_sats': output.value,
            'owner_hash160': commitment.owner_hash160.hex(),
            'target_r1_version': commitment.target_r1_version,
            'target_script_sha256': commitment.script_hash.hex(),
            'target_txout_hash256': commitment.output_hash.hex(),
            'locking_script_bytes': len(output.script),
            'locking_script_hex': output.script.hex(),
        }
        if commitment.public_key is not None:
            fields['public_key_x963'] = commitment.public_key.hex()
        if commitment.optimization is not None:
            fields['optimization'] = commitment.optimization
        print(json.dumps(fields, indent=2))


if __name__ == '__main__':
    main()
