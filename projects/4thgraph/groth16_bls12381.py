"""Compatibility entry point for the BLS12-381 verifier."""

from pathlib import Path
import sys

directory = str(Path(__file__).resolve().with_name("groth16-bls12-381"))
if directory not in sys.path:
    sys.path.insert(0, directory)

from bls12381 import verifier

if __name__ == "__main__":
    verifier.main()
else:
    sys.modules[__name__] = verifier
