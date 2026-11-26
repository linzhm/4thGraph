"""Evaluate the Forth constructors for native P2PK and P2PKH locks."""

import argparse
import json
from pathlib import Path

from compiler import SourceCompiler, evaluate
from protocol import is_compressed_public_key


SOURCE = Path(__file__).with_suffix(".fth")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    recipient = parser.add_mutually_exclusive_group(required=True)
    recipient.add_argument("--public-key", type=bytes.fromhex, help="compressed secp256k1 key for P2PK")
    recipient.add_argument("--hash160", type=bytes.fromhex, help="20-byte public-key hash for P2PKH")
    args = parser.parse_args()

    if args.public_key is not None:
        if not is_compressed_public_key(args.public_key):
            parser.error("--public-key must be a compressed secp256k1 public key")
        entry, data = "p2pk", args.public_key
    else:
        if len(args.hash160) != 20:
            parser.error("--hash160 must contain 20 bytes")
        entry, data = "p2pkh", args.hash160

    program = SourceCompiler(SOURCE.read_text())
    lock, = evaluate(program.words[entry], data)
    print(json.dumps({"template": entry, "script_bytes": len(lock), "script_hex": lock.hex()}, indent=2))


if __name__ == "__main__":
    main()
