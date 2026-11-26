"""Include the verifier subproject in the top-level unittest discovery."""

from pathlib import Path
import unittest

import groth16_bls12381  # Puts the verifier subproject on the import path.


def load_tests(loader, tests, pattern):
    directory = Path(__file__).resolve().with_name("groth16-bls12-381") / "tests"
    return unittest.TestLoader().discover(str(directory), top_level_dir=str(directory))
