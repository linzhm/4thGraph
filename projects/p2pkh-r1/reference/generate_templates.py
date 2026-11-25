"""Build or check the byte templates used by the optimized R1 wallet."""
import argparse
from hashlib import sha256
import json

from tx_engine import Script

from assemble import assemble
from curve_compiler import curve_blocks
from fixed_templates import TEMPLATE_DIRECTORY
from reconstruct import shared_kernel_program
from signature import COMPRESSIBLE_OTDA_TYPES, PAIRED_OTDA_SINGLE_TYPES, ORDINARY_CODE, UNIVERSAL_FLAGS


def pushed(data):
    out = Script()
    out.append_pushdata(data)
    return out.raw_serialize()


def reconstruction(prefix, suffix):
    # Each repeat expands as data with six OP_DUP OP_CAT pairs.
    program = bytearray(pushed(prefix))
    remaining = suffix
    for block in ("DIGITS_SPLIT4", "STEP_SPLIT4"):
        fragment = assemble(bytes(20), compiled_curve=True, entry=block)
        literal, remaining = remaining.split(fragment * 64)
        program.extend(pushed(literal))
        if block == "STEP_SPLIT4":
            program.extend(b"\x7e")  # OP_CAT
        program.extend(pushed(fragment) + b"\x76\x7e" * 6 + b"\x7e")
    program.extend(pushed(remaining) + b"\x7e")
    return bytes(program)


def build_artifacts():
    marker = bytes(range(20))
    prefix, suffix = assemble(marker, compiled_curve=True).split(marker)
    zero_owner = bytes(20)
    raw = prefix + zero_owner + suffix
    program = reconstruction(prefix, suffix)
    compact = shared_kernel_program(prefix, suffix)
    layout = {
        "script_file": "compiled.hex",
        "script_bytes": len(raw),
        "script_sha256": sha256(raw).hexdigest(),
        "owner_hash160": {"offset": len(prefix), "length": len(marker)},
        "fixed_bytes_sha256": sha256(prefix + suffix).hexdigest(),
        "supported_sighash_types": [f"{flag:02x}" for flag in sorted(UNIVERSAL_FLAGS)],
        "ordinary_script_code_hex": ORDINARY_CODE.hex(),
        "compressed_preimage": {
            "spend_transaction_version": 2,
            "sighash_types": [f"{flag:02x}" for flag in COMPRESSIBLE_OTDA_TYPES],
            "program_file": "otda-all-reconstruct.hex",
            "program_bytes": len(program),
            "program_sha256": sha256(program).hexdigest(),
            "shared_kernels": {
                "program_file": "otda-all-shared-kernels.hex",
                "program_bytes": len(compact),
                "program_sha256": sha256(compact).hexdigest(),
            },
        },
        "owner_vectors": [
            {"owner_hash160": owner.hex(), "script_sha256": sha256(prefix + owner + suffix).hexdigest()}
            for owner in (zero_owner, marker, bytes([255]) * 20)
        ],
    }
    return {
        layout["script_file"]: raw.hex() + "\n",
        layout["compressed_preimage"]["program_file"]: program.hex() + "\n",
        layout["compressed_preimage"]["shared_kernels"]["program_file"]: compact.hex() + "\n",
        "layout.json": json.dumps(layout, indent=2) + "\n",
    }


def scheduled_artifacts():
    marker = bytes(range(20))
    overrides = curve_blocks(scheduled=True)
    prefix, suffix = assemble(marker, compiled_curve=True, injected=overrides).split(marker)
    template = prefix + bytes(20) + suffix
    code = shared_kernel_program(prefix, suffix, injected=overrides)
    layout = {
        "script_file": "scheduled.hex",
        "script_bytes": len(template),
        "script_sha256": sha256(template).hexdigest(),
        "owner_hash160": {"offset": len(prefix), "length": 20},
        "fixed_bytes_sha256": sha256(prefix + suffix).hexdigest(),
        "supported_sighash_types": [f"{flag:02x}" for flag in sorted(UNIVERSAL_FLAGS)],
        "ordinary_script_code_hex": ORDINARY_CODE.hex(),
        "compressed_preimage": {
            "spend_transaction_version": 2,
            "sighash_types": [f"{flag:02x}" for flag in sorted((*COMPRESSIBLE_OTDA_TYPES, *PAIRED_OTDA_SINGLE_TYPES))],
            "program_file": "otda-scheduled-reconstruct.hex",
            "program_bytes": len(code),
            "program_sha256": sha256(code).hexdigest(),
        },
    }
    return {
        layout["script_file"]: template.hex() + "\n",
        layout["compressed_preimage"]["program_file"]: code.hex() + "\n",
        "scheduled-layout.json": json.dumps(layout, indent=2) + "\n",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if any checked-in artifact differs")
    args = parser.parse_args()
    if not args.check:
        TEMPLATE_DIRECTORY.mkdir(parents=True, exist_ok=True)
    for name, content in (build_artifacts() | scheduled_artifacts()).items():
        path = TEMPLATE_DIRECTORY / name
        if args.check:
            if path.read_text(encoding="ascii") != content:
                parser.exit(1, f"artifact differs: {path}\n")
        else:
            path.write_text(content, encoding="ascii")


if __name__ == "__main__":
    main()
