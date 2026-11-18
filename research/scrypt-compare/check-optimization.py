"""Audit the transpiled library and installed CLI before compiling the harness."""
import json
from pathlib import Path
import re

config = json.loads(Path(".asm/asm.json").read_text())["SECP256R1"]
source, = [p.read_text() for p in Path("artifacts").rglob("*.scrypt")
           if re.search(r"(?m)^\s*library SECP256R1\s*\{", p.read_text())]
for fn, body in config.items():
    match = re.search(r"function\s+" + fn + r"\s*\([^)]*\)[^{}]*\{\s*asm\s*\{", source)
    tokens = lambda s: re.findall(r"[{}]|[^{}\s]+", s)
    expected = tokens(body) + ["}"]
    actual = tokens(source[match.end():])[:len(expected)] if match else []
    if actual != expected:
        raise ValueError(f"ASM override differs: {fn}; actual tail {actual[-5:]}, expected {expected[-5:]}")
    print("VERIFIED_ASM", fn, len(body.split()), "tokens")
cli, = [p for p in (Path.home()/".npm/_npx").glob("*/node_modules/scrypt-cli/src/lib/compile.js")
        if json.loads((p.parents[2]/"package.json").read_text())["version"] == "0.2.3"]
if not re.search(r"compileContract\(f,\s*\{[^{}]*optimize:\s*true", cli.read_text()):
    raise ValueError("unexpected CLI artifact compilation mode")
print("VERIFIED_CLI_OPTIMIZER", "scrypt-cli 0.2.3", "optimize=true")
