"""Prepare the pinned CCTP handoff source used by the VK boundary experiment."""

import argparse
from hashlib import file_digest, sha256
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from zipfile import ZipFile

ARCHIVE_SHA256 = "4d988782f2a991113ecae9e4e84a72b5b00f759dbd0b7a3a9a3fae4ef380e88a"
PATCHES = Path(__file__).with_name("patches")


def prepare(archive, output):
    if output.exists():
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="cctp-reference-", dir=output.parent) as staging:
        root = Path(staging) / "reference"
        with archive.open("rb") as source:
            if file_digest(source, "sha256").hexdigest() != ARCHIVE_SHA256:
                raise ValueError("archive digest differs from the pinned CCTP baseline")
            source.seek(0)
            with ZipFile(source) as bundle:
                manifest = bundle.read("MANIFEST.sha256").decode().splitlines()
                for line in manifest:
                    digest, path = line.split("  ", 1)
                    if sha256(bundle.read(path)).hexdigest() != digest:
                        raise ValueError(f"bad archive member: {path}")
                bundle.extractall(root)
        for name in ("windowed-msm.patch", "gamma-fp2.patch"):
            with (PATCHES / name).open("rb") as patch:
                subprocess.run(["patch", "-s", "-p1"], stdin=patch, cwd=root, check=True)
        root.rename(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    prepare(args.archive, args.output)
