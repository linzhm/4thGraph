"""Generate the P2PKH-R1 scriptPubKey from public payment parameters."""
import argparse
from hashlib import sha256
import json
import re
import sys

from handwritten import UNIVERSAL_FLAGS
from p2pkh_r1 import locking_script_from_owner_hash, public_key_hash160
from lock_identity import identify_locking_script


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


def parse_policy(value):
    if re.fullmatch(r"[0-9a-fA-F]{2}(,[0-9a-fA-F]{2})*", value) is None:
        raise argparse.ArgumentTypeError("expected comma-separated two-digit hex sighash types")
    flags = {int(field, 16) for field in value.split(",")}
    if not flags.issubset(UNIVERSAL_FLAGS):
        raise argparse.ArgumentTypeError("unsupported v7 sighash type")
    return sorted(flags)


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    owner = parser.add_mutually_exclusive_group(required=True)
    owner.add_argument("--public-key", type=owner_from_key, dest="key_hash", metavar="HEX")
    owner.add_argument("--owner-hash160", type=owner_from_hash, metavar="HEX")
    parser.add_argument("--allow", type=parse_policy, default="41,61", metavar="HEX[,HEX...]")
    parser.add_argument("--format", choices=("manifest", "raw"), default="manifest")
    args = parser.parse_args()
    owner_hash = args.key_hash if args.key_hash is not None else args.owner_hash160
    raw = locking_script_from_owner_hash(owner_hash, args.allow)
    lock = identify_locking_script(raw)
    if (lock is None or lock.script_type != "P2PKH-R1" or lock.template_version != 7
            or lock.owner_hash160 != owner_hash or sorted(lock.allowed_types) != args.allow):
        raise RuntimeError("generated script failed template or payment parameter verification")
    if args.format == "raw":
        sys.stdout.buffer.write(raw)
        return
    print(json.dumps({
        "template": lock.script_type,
        "version": lock.template_version,
        "owner_hash160": lock.owner_hash160.hex(),
        "allowed_types": [f"{flag:02x}" for flag in args.allow],
        "script_bytes": len(raw),
        "script_sha256": sha256(raw).hexdigest(),
    }, indent=2))


if __name__ == "__main__":
    main()
