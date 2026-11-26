"""Install the 4thGraph compiler and offline decision reporter as Python zipapps."""

import argparse
from pathlib import Path
from shutil import copyfile
from tempfile import TemporaryDirectory
import zipapp

from stdlib import LIBRARIES, library_resource


PROJECT = Path(__file__).resolve().parent
COMPILER_MODULES = ("compiler", "wordsets", "ranges", "lowering", "stack_schedule", "protocol", "decision_report",
                    "stdlib", "cpn", "r1cs", "transaction_graph", "workflow_contract", "circuit_backend", "circuit_tools", "proof_contract",
                    "verification", "groth16_bls12381", "forkid_lowering")
BLS_MODULES = ("build_verifier.py", "bls12381/__init__.py", "bls12381/verifier.py", "bls12381/field.py",
               "bls12381/affine_witness.py")
SHARED_MODULES = ("pushtx", "script", "transaction")
COMMANDS = {"4thgraph": "protocol:main", "4thgraph-report": "decision_report:main",
            "4thgraph-circuit": "circuit_backend:main", "4thgraph-verify": "verification:main"}


def install(prefix):
    bin_dir = prefix.expanduser().resolve() / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    for command in COMMANDS:
        destination = bin_dir / command
        if destination.is_dir():
            raise IsADirectoryError(destination)

    with TemporaryDirectory(dir=bin_dir) as temporary:
        staging = Path(temporary)
        bundle = staging / "bundle"
        shared = bundle / "shared"
        shared.mkdir(parents=True)
        (shared / "__init__.py").touch()
        for module in COMPILER_MODULES:
            copyfile(PROJECT / f"{module}.py", bundle / f"{module}.py")
        for module in SHARED_MODULES:
            copyfile(PROJECT.parents[1] / "shared" / f"{module}.py", shared / f"{module}.py")
        for name, library in LIBRARIES.items():
            target = bundle / library_resource(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            copyfile(library.source, target)
        for module in BLS_MODULES:
            source = Path("groth16-bls12-381", module)
            target = bundle / source
            target.parent.mkdir(parents=True, exist_ok=True)
            copyfile(PROJECT / source, target)
        for command, entry in COMMANDS.items():
            zipapp.create_archive(bundle, staging / command, interpreter="/usr/bin/env python3",
                                  main=entry, compressed=True)
        for command in COMMANDS:
            (staging / command).replace(bin_dir / command)
    return bin_dir


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, default=Path.home() / ".local",
                        help="install commands in PREFIX/bin (default: ~/.local)")
    args = parser.parse_args()
    try:
        bin_dir = install(args.prefix)
    except (OSError, zipapp.ZipAppError) as error:
        parser.exit(1, f"4thGraph install: {error}\n")
    for command in COMMANDS:
        print(bin_dir / command)


if __name__ == "__main__":
    main()
