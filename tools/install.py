"""Install the standalone 4thGraph commands as Python zipapps."""

import argparse
from pathlib import Path
from shutil import copytree, ignore_patterns
from tempfile import TemporaryDirectory
import zipapp


SOURCE = Path(__file__).resolve().parents[1] / "src" / "fourthgraph"
COMMANDS = {
    "4thgraph": "fourthgraph.workflow.protocol:main",
    "4thgraph-report": "fourthgraph.reporting:main",
    "4thgraph-circuit": "fourthgraph.verification.circuit_backend:main",
    "4thgraph-verify": "fourthgraph.verification.plan:main",
}


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
        copytree(SOURCE, bundle / "fourthgraph", ignore=ignore_patterns("__pycache__", "*.pyc"))
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
