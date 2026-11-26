"""Compatibility entry point for the fixed-statement BLS12-381 replay."""

import sys

import groth16_bls12381  # Puts the verifier subproject on the import path.
from bls12381 import fixed_replay

if __name__ == "__main__":
    fixed_replay.main()
else:
    sys.modules[__name__] = fixed_replay
