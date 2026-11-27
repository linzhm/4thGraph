"""Read the compiled R1 template and the OTDA program from checked-in bytes."""
from dataclasses import dataclass
from functools import cache
from hashlib import sha256
import json
from pathlib import Path


TEMPLATE_VERSION = "0.2.0"
LEGACY_TEMPLATE_VERSION = "0.1.0"
OPTIMIZED_TEMPLATE_VERSION = "0.8.0"
TEMPLATE_VERSIONS = (TEMPLATE_VERSION, LEGACY_TEMPLATE_VERSION)
COMPILED_TEMPLATE_VERSIONS = (None, TEMPLATE_VERSION, OPTIMIZED_TEMPLATE_VERSION)
VERSIONS_DIRECTORY = Path(__file__).resolve().parents[1] / "versions"
TEMPLATE_DIRECTORY = VERSIONS_DIRECTORY / f"v{LEGACY_TEMPLATE_VERSION}" / "compiled"
RELEASE_DIRECTORY = VERSIONS_DIRECTORY / f"v{TEMPLATE_VERSION}"


def _directory(scheduled, template_version):
    if template_version is not None:
        return VERSIONS_DIRECTORY / f"v{template_version}"
    return RELEASE_DIRECTORY if scheduled else TEMPLATE_DIRECTORY


@dataclass(frozen=True)
class CompiledTemplate:
    script: bytes
    owner_start: int

    @property
    def owner_end(self):
        return self.owner_start + 20

    def owner(self, raw):
        if (len(raw) == len(self.script)
                and raw[:self.owner_start] == self.script[:self.owner_start]
                and raw[self.owner_end:] == self.script[self.owner_end:]):
            return raw[self.owner_start:self.owner_end]
        return None

    def lock(self, owner):
        return self.script[:self.owner_start] + owner + self.script[self.owner_end:]

    def reconstruction(self, program):
        from fourthgraph.bsv.otda_reconstruction import Reconstruction

        parts = self.script[:self.owner_start], self.script[self.owner_end:]
        return Reconstruction(program, parts, (self.owner_end - self.owner_start,))


@cache
def _layout(directory):
    return json.loads((directory / "layout.json").read_text(encoding="ascii"))


def _load_bytes(directory, file, size, digest):
    raw = bytes.fromhex((directory / file).read_text(encoding="ascii"))
    if len(raw) != size or sha256(raw).hexdigest() != digest:
        raise ValueError(f"artifact differs from P2PKH-R1 layout: {file}")
    return raw


def read_compiled_template(directory, layout):
    raw = _load_bytes(directory, layout["script_file"], layout["script_bytes"], layout["script_sha256"])
    start = layout["owner_hash160"]["offset"]
    end = start + 20
    if (layout["owner_hash160"]["length"] != 20 or not 0 <= start < end <= len(raw)
            or raw[start:end] != bytes(20)
            or sha256(raw[:start] + raw[end:]).hexdigest() != layout["fixed_bytes_sha256"]):
        raise ValueError("compiled P2PKH-R1 owner field differs from layout")
    return CompiledTemplate(raw, start)


@cache
def compiled_template(*, scheduled=False, template_version=None):
    directory = _directory(scheduled, template_version)
    return read_compiled_template(directory, _layout(directory))


def compiled_owner(raw):
    for version in COMPILED_TEMPLATE_VERSIONS:
        if len(raw) == _layout(_directory(False, version))["script_bytes"]:
            owner = compiled_template(template_version=version).owner(raw)
            if owner is not None:
                return owner
    return None


def read_otda_reconstruction(directory, layout, *, shared_kernels=False):
    artifact = layout["shared_kernels"] if shared_kernels else layout
    program = _load_bytes(directory, artifact["program_file"], artifact["program_bytes"], artifact["program_sha256"])
    return layout["spend_transaction_version"], program


@cache
def otda_reconstruction(*, shared_kernels=False, scheduled=False, template_version=None):
    directory = _directory(scheduled, template_version)
    return read_otda_reconstruction(
        directory, _layout(directory)["compressed_preimage"],
        shared_kernels=shared_kernels and directory == TEMPLATE_DIRECTORY,
    )


@cache
def otda_pattern(*, shared_kernels=False, scheduled=False, template_version=None):
    version, program = otda_reconstruction(
        shared_kernels=shared_kernels, scheduled=scheduled, template_version=template_version,
    )
    template = compiled_template(scheduled=scheduled, template_version=template_version)
    return version, template.reconstruction(program)
