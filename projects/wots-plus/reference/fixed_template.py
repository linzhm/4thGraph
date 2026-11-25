"""Load the prebuilt WOTS+ cached-steps output template and OTDA program."""
from functools import cache
from hashlib import sha256
import json
from pathlib import Path

from shared.otda_reconstruction import Reconstruction
from wots import KEY_BYTES, N

TEMPLATE_DIRECTORY = Path(__file__).resolve().parents[1] / "template"


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


def lock_for_key(key):
    if not isinstance(key, bytes) or len(key) != KEY_BYTES:
        raise ValueError("WOTS+ public key must be 64 bytes")
    first, middle, last = fixed_pattern().fixed_parts
    return first + key[:N] + middle + key[N:] + last
