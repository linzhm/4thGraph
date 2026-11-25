"""Generate the P2PKH-R1 scriptPubKey from public payment parameters."""
import argparse
from hashlib import sha256
import json
import re
import sys

from p2pkh_r1 import locking_script_from_owner_hash, public_key_hash160, recognize


def owner_from_key(value):
    if re.fullmatch(r"04[0-9a-fA-F]{128}", value) is None:
        raise argparse.ArgumentTypeError("expected a 65-byte uncompressed P-256 public key in hex")
    encoded = bytes.fromhex(value)
    try:
        return public_key_hash160(encoded)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("point is outside the P-256 curve") from exc


def owner_from_hash(value):
    if re.fullmatch(r"[0-9a-fA-F]{40}", value) is None:
        raise argparse.ArgumentTypeError("expected a 20-byte HASH160 in hex")
    return bytes.fromhex(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    owner = parser.add_mutually_exclusive_group(required=True)
    owner.add_argument("--public-key", type=owner_from_key, dest="key_hash", metavar="HEX")
    owner.add_argument("--owner-hash160", type=owner_from_hash, metavar="HEX")
    parser.add_argument("--format", choices=("manifest", "raw"), default="manifest")
    variant = parser.add_mutually_exclusive_group()
    variant.add_argument("--compiled-curve", dest="compiled_curve", action="store_true",
                         help="generate the original experimental field AST template")
    variant.add_argument("--scheduled-curve", dest="compiled_curve", action="store_const", const="scheduled",
                         help="generate the 46,302-byte scheduled field AST template")
    args = parser.parse_args()
    owner_hash = args.key_hash if args.key_hash is not None else args.owner_hash160
    raw = locking_script_from_owner_hash(owner_hash, compiled_curve=args.compiled_curve)
    if recognize(raw) != owner_hash:
        raise RuntimeError("generated script failed owner or template verification")
    if args.format == "raw":
        sys.stdout.buffer.write(raw)
        return
    manifest = {
        "template": "P2PKH-R1",
        "owner_hash160": owner_hash.hex(),
        "script_bytes": len(raw),
        "script_sha256": sha256(raw).hexdigest(),
    }
    if args.compiled_curve:
        manifest["curve_compiler"] = "field-ast-scheduled" if args.compiled_curve == "scheduled" else "field-ast"
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
