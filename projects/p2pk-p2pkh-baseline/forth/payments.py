"""Evaluate the Forth constructors for native P2PK and P2PKH locks."""

import argparse
import json

from fourthgraph.bsv.native_payments import p2pk_lock, p2pkh_lock


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    recipient = parser.add_mutually_exclusive_group(required=True)
    recipient.add_argument("--public-key", type=bytes.fromhex, help="compressed secp256k1 key for P2PK")
    recipient.add_argument("--hash160", type=bytes.fromhex, help="20-byte public-key hash for P2PKH")
    args = parser.parse_args()

    try:
        if args.public_key is not None:
            entry, lock = "p2pk", p2pk_lock(args.public_key)
        else:
            entry, lock = "p2pkh", p2pkh_lock(args.hash160)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps({"template": entry, "script_bytes": len(lock), "script_hex": lock.hex()}, indent=2))


if __name__ == "__main__":
    main()
