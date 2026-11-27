"""Compile the Forth contract and instantiate its frozen Schnorr lock."""

from functools import cache
from hashlib import new, sha256
import json
from pathlib import Path

from fourthgraph.compiler.script_builder import ScriptBuilder
SOURCE = Path(__file__).with_name("schnorr.fth")
VERSIONS_DIR = SOURCE.resolve().parents[1] / "versions"
TEMPLATE_VERSION = "v0.14.0"
TEMPLATE_DIRS = {
    version: VERSIONS_DIR / version
    for version in (TEMPLATE_VERSION, "v0.13.0", "v0.12.0", "v0.11.0", "v0.10.0",
                    "v0.9.0", "v0.8.0", "v0.7.0", "v0.6.0")
}
TEMPLATE_DIR = TEMPLATE_DIRS[TEMPLATE_VERSION]


@cache
def _contract():
    return ScriptBuilder.from_file(SOURCE)


@cache
def authorization_codes():
    contract = _contract()
    return (contract.emit("schnorr-ordinary-code", b""),
            contract.emit("schnorr-companion-code", b""))


@cache
def verifier():
    """Consume message, public x, public y, BIP340 signature, and nonce y."""
    return ScriptBuilder("REQUIRE stdlib/bip340.fth\n").emit("bip340-verify", b"")


def compile_unlock(preimage, companion, public_x, public_y, signature, nonce_y):
    """Instantiate the Forth unlocking word with approved, encoded witness data."""
    return _contract().emit("schnorr-unlock", preimage, int(companion),
                            public_x, public_y, signature, nonce_y)


def compiled_template(owner=bytes(20)):
    """Return the compiled locking script and byte offset of its owner slot."""
    _check_owner(owner)
    contract = _contract()
    offset = len(contract.emit("schnorr-lock-prefix", b"")) + 1
    return contract.emit("schnorr-lock", b"", owner), offset


def owner_hash(public_key):
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ValueError("expected a 32-byte BIP340 public key")
    return new("ripemd160", sha256(public_key).digest()).digest()


def _check_owner(owner):
    if not isinstance(owner, bytes) or len(owner) != 20:
        raise ValueError("expected a 20-byte owner hash")


@cache
def _canonical(version):
    directory = TEMPLATE_DIRS.get(version)
    if directory is None:
        raise ValueError("unsupported Schnorr locking template")
    raw = bytes.fromhex((directory / "template.hex").read_text(encoding="ascii"))
    layout = json.loads((directory / "layout.json").read_text(encoding="utf-8"))
    start = layout["owner_hash160"]["offset"]
    if (layout["version"] != version or layout["owner_hash160"]["length"] != 20
            or len(raw) != layout["script_bytes"] or sha256(raw).hexdigest() != layout["base_script_sha256"]
            or not 0 < start <= len(raw) - 20 or raw[start - 1:start + 20] != b"\x14" + bytes(20)):
        raise ValueError("Schnorr locking template differs from its manifest")
    return raw, start


def lock_for_owner(owner, *, version=None):
    _check_owner(owner)
    if version is not None and not isinstance(version, str):
        raise ValueError("unsupported Schnorr locking template")
    raw, start = _canonical(TEMPLATE_VERSION if version is None else version)
    return raw[:start] + owner + raw[start + 20:]


def recognize_template(script):
    """Return (version, owner) after comparing all fixed bytes."""
    if not isinstance(script, bytes):
        return None
    for version in TEMPLATE_DIRS:
        raw, start = _canonical(version)
        if (len(script) == len(raw) and script[:start] == raw[:start]
                and script[start + 20:] == raw[start + 20:]):
            return version, script[start:start + 20]
    return None


def recognize(script):
    match = recognize_template(script)
    return match[1] if match else None
