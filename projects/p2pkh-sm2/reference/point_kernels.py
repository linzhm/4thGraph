"""Compile and load the versioned SM2 point arithmetic kernels."""
import argparse
import json
from pathlib import Path

from fourthgraph.compiler.script_builder import ScriptBuilder


SOURCE = Path(__file__).with_name("point-formulas.fth")
KERNEL_NAMES = ("sm2-add-kernel", "sm2-double-kernel")
WINDOW_KERNEL_NAME = "sm2-double-window-kernel"


def compile_kernels(names=KERNEL_NAMES):
    compiler = ScriptBuilder(SOURCE.read_text(encoding="utf-8"), source_path=SOURCE, optimize=True)
    return {name: compiler.emit(name, b"") for name in names}


def load_kernels(path, names=KERNEL_NAMES):
    encoded = json.loads(path.read_text(encoding="utf-8"))
    return {name: bytes.fromhex(encoded[name]) for name in names}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="destination for the hexadecimal kernels in JSON")
    parser.add_argument("--window", action="store_true", help="generate the five-doubling window kernel")
    args = parser.parse_args()
    names = (WINDOW_KERNEL_NAME,) if args.window else KERNEL_NAMES
    encoded = {name: raw.hex() for name, raw in compile_kernels(names).items()}
    args.output.write_text(json.dumps(encoded, indent=2) + "\n", encoding="utf-8")
