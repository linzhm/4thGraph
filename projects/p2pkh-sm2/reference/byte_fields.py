"""Compile and compare the SM2 template's fixed-width Script fragments."""
import argparse
from hashlib import sha256
import json
from pathlib import Path

from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.compiler.byte_layout import ByteLayoutBuilder, LITERAL, PACKED, REPEAT, SPLIT


SOURCE = Path(__file__).with_name("byte-fields.fth")
REVERSE_NAME = "sm2-reverse-fields-kernel"
ZERO_NAME = "sm2-zero32-kernel"
BYTE_KERNEL_NAMES = (REVERSE_NAME, ZERO_NAME)


def check_fields(code, width):
    if width == 0:
        if evaluate(code, [b"lower stack"]) != ([b"lower stack", bytes(32)], []):
            raise ValueError("incorrect zero constant")
        return 1
    for data in (bytes(192), b"\xff"*192, bytes(range(192)), bytes(range(255, 63, -1))):
        expected = b"".join(data[offset:offset+32][::-1] for offset in range(0, 192, 32))
        if evaluate(code, [b"lower stack", data]) != ([b"lower stack", expected], []):
            raise ValueError("incorrect field reversal")
    for wrong_width in (0, 191, 193):
        try:
            evaluate(code, [bytes(wrong_width)])
        except ScriptError:
            continue
        raise ValueError(f"field reversal accepted {wrong_width} bytes")
    return 7


def compile_byte_kernels():
    source = SOURCE.read_bytes()
    compiler = ByteLayoutBuilder(source.decode())
    kernels, candidates = {}, {}
    for name, choices, width in ((REVERSE_NAME, (SPLIT, PACKED), 192), (ZERO_NAME, (LITERAL, REPEAT), 0)):
        best = None
        candidates[name] = []
        for choice in choices:
            code, sites = compiler.emit_plan(name, [{"site": 0, "kernel": choice}])
            checks = check_fields(code, width)
            candidates[name].append({"call_site": sites[0], "checks": checks})
            if best is None or len(code) < len(best):
                best = code
        kernels[name] = best
    report = {"source_sha256": sha256(source).hexdigest(), "candidates": candidates,
              "selected_sha256": {name: sha256(code).hexdigest() for name,code in kernels.items()}}
    return kernels, report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    kernels, report = compile_byte_kernels()
    args.output.write_text(json.dumps({name: code.hex() for name,code in kernels.items()}, indent=2)+"\n",
                           encoding="utf-8")
    if args.report:
        args.report.write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
