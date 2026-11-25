"""CCTP fixture with compatibility imports for the Groth16 short-MiMC implementation."""

import json
from pathlib import Path

from bsb22_short_mimc import BLOCK_BITS, BLOCK_BYTES, COORDINATE_BITS, ROUNDS, commitment_challenge

VECTOR = json.loads((Path(__file__).parent / "testdata/short-mimc.json").read_text())

__all__ = ["BLOCK_BITS", "BLOCK_BYTES", "COORDINATE_BITS", "ROUNDS", "VECTOR", "commitment_challenge"]
