"""Compile and replay the Goldilocks STARK proof lock."""

from pathlib import Path

from fourthgraph.verification.stark.cli import main
from fourthgraph.verification.stark.proof import GOLDILOCKS


if __name__ == "__main__":
    main(GOLDILOCKS, Path(__file__).resolve().parents[1])
