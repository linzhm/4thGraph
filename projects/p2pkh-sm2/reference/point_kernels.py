"""Compile and load the versioned SM2 point arithmetic kernels."""
import argparse
import json
from pathlib import Path

from fourthgraph.compiler.script_builder import ScriptBuilder


SOURCE = Path(__file__).with_name("point-formulas.fth")
CARRIED_SOURCE = Path(__file__).with_name("point-window.fth")
KERNEL_NAMES = ("sm2-add-kernel", "sm2-double-kernel")
WINDOW_KERNEL_NAME = "sm2-double-window-kernel"
AFFINE_KERNEL_NAME = "sm2-add-affine-kernel"
CARRIED_KERNEL_NAMES = ("sm2-window-double-five", "sm2-window-add-projective", "sm2-window-add-affine")
CARRIED_PASSES = ("rewrite", "share", "stack", "search")


def compile_kernels(names=KERNEL_NAMES):
    compiler = ScriptBuilder(SOURCE.read_text(encoding="utf-8"), source_path=SOURCE, optimize=True)
    return {name: compiler.emit(name, b"") for name in names}


def compile_carried_kernels():
    compiler = ScriptBuilder.from_file(CARRIED_SOURCE, formula_passes=CARRIED_PASSES)
    return {name: compiler.emit(name, b"") for name in CARRIED_KERNEL_NAMES}


def load_kernels(path, names=KERNEL_NAMES):
    encoded = json.loads(path.read_text(encoding="utf-8"))
    return {name: bytes.fromhex(encoded[name]) for name in names}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="destination for the hexadecimal kernels in JSON")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--window", action="store_true", help="generate the five-doubling window kernel")
    group.add_argument("--affine", action="store_true", help="generate the fixed-generator addition kernel")
    group.add_argument("--carried", action="store_true", help="generate the kernels with carried field constants")
    args = parser.parse_args()
    names = KERNEL_NAMES
    if args.window:
        names = (WINDOW_KERNEL_NAME,)
    elif args.affine:
        names = (AFFINE_KERNEL_NAME,)
    kernels = compile_carried_kernels() if args.carried else compile_kernels(names)
    encoded = {name: raw.hex() for name, raw in kernels.items()}
    args.output.write_text(json.dumps(encoded, indent=2) + "\n", encoding="utf-8")
