"""Compare equivalent BIP340 algorithms compiled by scryptc and Script Lab."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from coincurve import PublicKeyXOnly

from compare_scrypt import measure
from schnorr_script import verifier
from shared.benchmark_validation import CONTEXT_PIN, Node, chain_metadata, stack_profile
from shared.script import asm, push
from test_schnorr import detached_unlock, malformed_witnesses, official_vectors

COMPILER_SHA256 = "889b8797ed04412e2ea6c0cc56ef5bfcdfb54451c162bcfbc12a6dd43325777b"


def compile_verifiers(compiler, directory):
    source = Path(__file__).with_name("comparison") / "bip340.scrypt"
    command = [str(compiler), "compile", "-o", directory]
    subprocess.run([*command, "--hex", str(source)], check=True, stdout=subprocess.PIPE)
    output = Path(directory) / "bip340_hex.txt"
    default = bytes.fromhex(output.read_text(encoding="ascii"))
    subprocess.run([*command, "--asm", "-O", str(source)], check=True, stdout=subprocess.PIPE)
    encoded = json.loads((Path(directory) / "bip340_asm.json").read_text(encoding="utf-8"))
    tokens = (item["opcode"] for item in encoded["output"])
    optimized = b"".join(
        asm(op) if op.startswith("OP_") or op in {"0", "-1"} else push(bytes.fromhex(op))
        for op in tokens
    )
    # The sCrypt ABI consumes its own arguments. The common guard also rejects
    # surplus items below those arguments under consensus flags without CLEANSTACK.
    guard = asm("OP_DEPTH 5 OP_NUMEQUALVERIFY")
    return {"scrypt_default": guard + default, "scrypt_optimized": guard + optimized, "script_lab": verifier()}


def cases():
    vectors = official_vectors()
    for row in vectors:
        public, message, sig = (bytes.fromhex(row[n]) for n in ("public key", "message", "signature"))
        expected = row["verification result"] == "TRUE"
        try:
            independent = PublicKeyXOnly(public).verify(sig, message)
        except ValueError:
            independent = False
        if expected != independent:
            raise ValueError(f"independent BIP340 verifier disagrees on vector {row['index']}")
        yield f"bip340/{row['index']}", detached_unlock(message, public, sig), expected

    vector = vectors[0]
    public, message, sig = (bytes.fromhex(vector[n]) for n in ("public key", "message", "signature"))
    for name, unlock in malformed_witnesses(public, message, sig):
        yield f"witness/{name}", unlock, False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=15)
    args = parser.parse_args()
    if args.samples < 0:
        parser.error("sample count must be nonnegative")
    compiler = args.compiler.resolve()
    if sha256(compiler.read_bytes()).hexdigest() != COMPILER_SHA256:
        parser.error("expected the pinned Linux x86-64 scryptc 1.19.1 compiler")
    if chain_metadata()["commit"] != CONTEXT_PIN:
        parser.error("install the pinned chain-gang revision from the project requirements")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    with TemporaryDirectory(prefix="script-lab-bip340-") as temp:
        locks = compile_verifiers(compiler, temp)

    expected_cases = tuple(cases())
    results = {}
    for implementation, lock in locks.items():
        for name, unlock, expected in expected_cases:
            stats = measure(lock, unlock, node, args.samples if name == "bip340/0" else 0)
            if stats["chain_gang"] != expected or stats["bsv_node"] != expected:
                raise ValueError(f"{implementation} disagrees on {name} (expected {expected}): {stats}")
            if name == "bip340/0":
                stack = stack_profile(lock, unlock)
                if "unavailable" in stack:
                    raise ValueError(f"{implementation} stack profile failed: {stack['unavailable']}")
                results[implementation] = {**stats, "stack": stack}
    print(json.dumps({"cases_per_implementation": len(expected_cases),
                      "positive_cases": sum(expected for _, _, expected in expected_cases),
                      "samples_per_engine": args.samples, "results": results}, indent=2))


if __name__ == "__main__":
    main()
