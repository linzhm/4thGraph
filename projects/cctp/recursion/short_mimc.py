"""gnark's BLS12-381 short MiMC (one BSB22 commitment, no public indexes)."""

import json
from pathlib import Path

from field import R

# Constants pinned to gnark-crypto's BLS12-381 Fr MiMC. The Go round-trip test
# compares each against the dependency's GetConstants(), in order.
VECTOR = json.loads((Path(__file__).parent / "testdata/short-mimc.json").read_text())
ROUNDS = tuple(int(raw, 16) for raw in VECTOR["round_constants"])
COORDINATE_BITS = 384
BLOCK_BITS = 248
BLOCK_BYTES = BLOCK_BITS // 8


def _remainder(program, value, modulus):
    return program.sub(value, program.mul(program.divide(value, modulus), modulus))


def commitment_challenge(program, point):
    """Return the scalar bound to a checked finite G1 commitment in Script.

    Caller range-checks the canonical unsigned Fp coordinates and verifies
    curve/subgroup membership. Input encoding is gnark's 96-byte uncompressed
    affine serialization, without an infinity flag for this profile.
    """
    x, y = point
    encoded = program.add(program.mul(x, 1 << COORDINATE_BITS), y)
    state = 0
    for consumed in range(0, 96, BLOCK_BYTES):
        size = min(BLOCK_BYTES, 96 - consumed)
        shift = (96 - consumed - size) * 8
        head = program.divide(encoded, 1 << shift) if shift else encoded
        chunk = _remainder(program, head, 1 << (size * 8))
        if size != BLOCK_BYTES:
            # shortNativeHash writes the final bytes into the front of a
            # zeroed 31-byte chunk before representing it as a scalar.
            chunk = program.mul(chunk, 1 << ((BLOCK_BYTES - size) * 8))
        message = chunk
        for constant in ROUNDS:
            base = _remainder(program, program.add(program.add(chunk, state), constant), R)
            squared = program.mul(base, base)
            chunk = _remainder(program, program.mul(program.mul(squared, squared), base), R)
        state = _remainder(program, program.add(program.add(chunk, program.mul(2, state)), message), R)
    return _remainder(program, state, 1 << BLOCK_BITS)
