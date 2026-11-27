"""Build or verify the prebuilt WOTS+ cached-steps artifacts."""
import argparse
from hashlib import sha256
import json

from script import _chain, _payment_script
from fixed_template import TEMPLATE_DIRECTORY
from payment import COMPRESSIBLE_OTDA_TYPES
from fourthgraph.bsv.script import asm, push
from wots import CHAINS, N


def build_artifacts():
    marker = bytes(range(2 * N))
    first, tail = _payment_script(marker, cached_constants="steps").split(marker[:N])
    middle, last = tail.split(marker[N:])
    before, after = _chain(16, cached_constants="steps").split((16).to_bytes(4, "big"))
    chains = [before + i.to_bytes(4, "big") + after for i in range(CHAINS)]
    if any(raw != _chain(i, cached_constants="steps") for i, raw in enumerate(chains)):
        raise ValueError("WOTS+ chain bytecode differs outside its index field")
    lead, tail = middle.split(b"".join(chains[:2 * N]))
    gap, end = tail.split(b"".join(chains[2 * N:]))
    program = bytearray(push(before) + push(after) + push(first) + push(lead))
    for indices, suffix in ((range(2 * N), gap), (range(2 * N, CHAINS), end)):
        for i in indices:
            program.extend(asm("OP_3 OP_PICK OP_CAT") + push(i.to_bytes(4, "big"))
                           + asm("OP_CAT OP_2 OP_PICK OP_CAT"))
        if suffix:
            program.extend(push(suffix) + asm("OP_CAT"))
    program.extend(asm("OP_2SWAP OP_2DROP") + push(last))

    raw = first + bytes(N) + middle + bytes(N) + last
    layout = {
        "script": {"file": "cached-steps.hex", "bytes": len(raw), "sha256": sha256(raw).hexdigest()},
        "key_offsets": [len(first), len(first) + N + len(middle)],
        "reconstruction": {
            "file": "otda-all-reconstruct.hex", "bytes": len(program), "sha256": sha256(program).hexdigest(),
            "spend_transaction_version": 2,
            "sighash_types": [f"{flag:02x}" for flag in sorted(COMPRESSIBLE_OTDA_TYPES)],
        },
    }
    return {
        layout["script"]["file"]: raw.hex() + "\n",
        layout["reconstruction"]["file"]: program.hex() + "\n",
        "cached-steps-layout.json": json.dumps(layout, indent=2) + "\n",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for name, content in build_artifacts().items():
        file = TEMPLATE_DIRECTORY / name
        if args.check:
            if file.read_text(encoding="ascii") != content:
                parser.exit(1, f"artifact differs: {file}\n")
        else:
            file.write_text(content, encoding="ascii")


if __name__ == "__main__":
    main()
