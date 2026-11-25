"""Read the compiled R1 template and the OTDA program from checked-in bytes."""
from dataclasses import dataclass
from functools import cache
from hashlib import sha256
import json
from pathlib import Path


TEMPLATE_DIRECTORY = Path(__file__).resolve().parents[1] / "template/candidates"


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


@cache
def _layout():
    return json.loads((TEMPLATE_DIRECTORY / "layout.json").read_text(encoding="ascii"))


def _load_bytes(file, size, digest):
    raw = bytes.fromhex((TEMPLATE_DIRECTORY / file).read_text(encoding="ascii"))
    if len(raw) != size or sha256(raw).hexdigest() != digest:
        raise ValueError(f"artifact differs from P2PKH-R1 layout: {file}")
    return raw


@cache
def compiled_template():
    layout = _layout()
    raw = _load_bytes(layout["script_file"], layout["script_bytes"], layout["script_sha256"])
    start = layout["owner_hash160"]["offset"]
    end = start + 20
    if (layout["owner_hash160"]["length"] != 20 or not 0 <= start < end <= len(raw)
            or raw[start:end] != bytes(20)
            or sha256(raw[:start] + raw[end:]).hexdigest() != layout["fixed_bytes_sha256"]):
        raise ValueError("compiled P2PKH-R1 owner field differs from layout")
    return CompiledTemplate(raw, start)


def compiled_owner(raw):
    if len(raw) != _layout()["script_bytes"]:
        return None
    return compiled_template().owner(raw)


@cache
def otda_reconstruction(*, shared_kernels=False):
    layout = _layout()["compressed_preimage"]
    artifact = layout["shared_kernels"] if shared_kernels else layout
    program = _load_bytes(artifact["program_file"], artifact["program_bytes"], artifact["program_sha256"])
    return layout["spend_transaction_version"], program
