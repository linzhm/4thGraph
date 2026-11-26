"""Compile and load the v1.5.0 SM2 point arithmetic kernels."""
import argparse
import json
from pathlib import Path

from fourthgraph.compiler.script_builder import ScriptBuilder


SOURCE = Path(__file__).with_name("point-formulas.fth")
KERNEL_NAMES = ("sm2-add-kernel", "sm2-double-kernel")


def compile_kernels():
    compiler = ScriptBuilder(SOURCE.read_text(encoding="utf-8"), source_path=SOURCE, optimize=True)
    return {name: compiler.emit(name, b"") for name in KERNEL_NAMES}


def load_kernels(path):
    encoded = json.loads(path.read_text(encoding="utf-8"))
    return {name: bytes.fromhex(encoded[name]) for name in KERNEL_NAMES}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="destination for the hexadecimal kernels in JSON")
    args = parser.parse_args()
    encoded = {name: raw.hex() for name, raw in compile_kernels().items()}
    args.output.write_text(json.dumps(encoded, indent=2) + "\n", encoding="utf-8")
