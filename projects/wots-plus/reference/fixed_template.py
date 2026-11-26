"""Build or load fixed WOTS+ outputs and their OTDA reconstruction programs."""
from functools import cache
from hashlib import sha256
import json
from pathlib import Path

from fourthgraph.bsv.otda_reconstruction import Reconstruction
from fourthgraph.bsv.script import asm, push
from wots import CHAINS, KEY_BYTES, N

TEMPLATE_DIRECTORY = Path(__file__).resolve().parents[1] / "versions/v0.1.0"


def _read_bytes(artifact):
    data = bytes.fromhex((TEMPLATE_DIRECTORY / artifact["file"]).read_text(encoding="ascii"))
    if len(data) != artifact["bytes"] or sha256(data).hexdigest() != artifact["sha256"]:
        raise ValueError(f"WOTS+ fixed artifact differs from manifest: {artifact['file']}")
    return data


@cache
def fixed_pattern():
    layout = json.loads((TEMPLATE_DIRECTORY / "cached-steps-layout.json").read_text(encoding="ascii"))
    script = _read_bytes(layout["script"])
    program = _read_bytes(layout["reconstruction"])
    seed, commitment = layout["key_offsets"]
    if not 0 <= seed < seed + N <= commitment < commitment + N <= len(script):
        raise ValueError("invalid WOTS+ key offsets")
    if script[seed:seed + N] != bytes(N) or script[commitment:commitment + N] != bytes(N):
        raise ValueError("WOTS+ template must have zero key fields")
    parts = script[:seed], script[seed + N:commitment], script[commitment + N:]
    return Reconstruction(program, parts, (N, N))


@cache
def compact_pattern():
    from script import _compact_chain, _payment_script

    marker = bytes(range(KEY_BYTES))
    raw = _payment_script(marker, cached_constants="compact")
    first, tail = raw.split(marker[:N], 1)
    middle, last = tail.split(marker[N:], 1)
    chain = _compact_chain()
    lead, tail = middle.split(chain * (2 * N), 1)
    gap, end = tail.split(chain * (CHAINS - 2 * N), 1)

    # WOTSP-SHA2_256 uses 64 message chains and three checksum chains.
    # Keep one copy for the checksum and double the other six times.
    program = push(first) + push(lead) + push(chain) + asm("OP_DUP")
    program += asm("OP_DUP OP_CAT") * 6 + asm("OP_ROT OP_SWAP OP_CAT")
    program += push(gap) + asm("OP_CAT OP_SWAP OP_DUP OP_DUP OP_CAT OP_CAT OP_CAT")
    program += push(end) + asm("OP_CAT") + push(last)
    return Reconstruction(program, (first, middle, last), (N, N))


def lock_for_key(key, *, profile="steps"):
    if not isinstance(key, bytes) or len(key) != KEY_BYTES:
        raise ValueError("WOTS+ public key must be 64 bytes")
    pattern = compact_pattern() if profile == "compact" else fixed_pattern()
    first, middle, last = pattern.fixed_parts
    return first + key[:N] + middle + key[N:] + last
