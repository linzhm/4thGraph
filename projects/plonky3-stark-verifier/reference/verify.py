"""Compile and replay the Plonky3 BabyBear STARK proof lock."""

from pathlib import Path

from fourthgraph.verification.stark.cli import main
from fourthgraph.verification.stark.proof import BABYBEAR


if __name__ == "__main__":
    main(BABYBEAR, Path(__file__).resolve().parents[1])
