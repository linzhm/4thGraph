"""Generate or verify the checked-in Schnorr payment template."""

import argparse
from hashlib import sha256
import json

from schnorr_script import TEMPLATE_DIR, TEMPLATE_VERSION, compiled_template


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true")
    action.add_argument("--check", action="store_true")
    options = parser.parse_args()

    raw, offset = compiled_template()
    layout = {
        "template": "P2PKH-Schnorr",
        "version": TEMPLATE_VERSION,
        "script_bytes": len(raw),
        "owner_hash160": {"offset": offset, "length": 20},
        "base_script_sha256": sha256(raw).hexdigest(),
    }
    files = {
        TEMPLATE_DIR / "template.hex": raw.hex() + "\n",
        TEMPLATE_DIR / "layout.json": json.dumps(layout, indent=2) + "\n",
    }
    for path, expected in files.items():
        if options.write:
            path.write_text(expected, encoding="ascii")
        elif path.read_text(encoding="ascii") != expected:
            parser.exit(1, f"{path.name} differs from the compiler output\n")
    print(json.dumps(layout, indent=2))


if __name__ == "__main__":
    main()
