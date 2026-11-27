"""Generate canonical script bytes; no signing keys or network access required."""
import argparse
from hashlib import sha256
import json
import sys
from assemble import TEMPLATE_VERSION, TEMPLATE_VERSIONS
from p2pkh_sm2 import locking_script_from_owner_hash,locking_script_from_public_key


def main():
    parser=argparse.ArgumentParser()
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--owner-hash160'); group.add_argument('--public-key')
    parser.add_argument('--format',choices=('json','hex','raw'),default='json')
    parser.add_argument('--version', type=int, choices=TEMPLATE_VERSIONS, default=TEMPLATE_VERSION)
    args=parser.parse_args()
    try:
        if args.owner_hash160 is not None:
            raw = locking_script_from_owner_hash(bytes.fromhex(args.owner_hash160), version=args.version)
        else:
            raw = locking_script_from_public_key(bytes.fromhex(args.public_key), version=args.version)
    except ValueError as e: parser.error(str(e))
    if args.format=='raw': sys.stdout.buffer.write(raw)
    elif args.format=='hex': print(raw.hex())
    else: print(json.dumps(dict(template='P2PKH-SM2',version=args.version,script_bytes=len(raw),script_sha256=sha256(raw).hexdigest()),indent=2))

if __name__=='__main__': main()
