"""Run an external C2SP Wycheproof standard ML-DSA-44 verification corpus."""

import argparse
import json
from pathlib import Path

from fips204 import verify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vectors", type=Path)
    args = parser.parse_args()
    vectors = json.loads(args.vectors.read_text())
    if vectors["algorithm"] != "ML-DSA" or vectors["schema"] != "mldsa_verify_schema.json":
        raise ValueError("expected an ML-DSA verification corpus")

    mismatches = []
    count = 0
    for group in vectors["testGroups"]:
        for test in group["tests"]:
            valid = verify(bytes.fromhex(group["publicKey"]), bytes.fromhex(test["msg"]),
                           bytes.fromhex(test["sig"]), context=bytes.fromhex(test.get("ctx", "")))
            if valid != (test["result"] == "valid"):
                mismatches.append(test["tcId"])
            count += 1
    if count != vectors["numberOfTests"]:
        raise ValueError("asset test count mismatch")
    print(f"ML-DSA-44: {count - len(mismatches)}/{count} Wycheproof results matched")
    if mismatches:
        print(f"Mismatched case IDs: {mismatches}")
    return bool(mismatches)


if __name__ == "__main__":
    raise SystemExit(main())
