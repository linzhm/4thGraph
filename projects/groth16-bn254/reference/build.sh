#!/usr/bin/env bash
set -euo pipefail
project=projects/groth16-bn254
fixture="$project/versions/v0.1.0/fixture.json"
out="$project/workspace/build"
source="${2:-$project/verifier.fth}"
mkdir -p "$out"
owner="$(python3 - "$fixture" "$out" <<'PYBUILD'
import json
from pathlib import Path
import sys

fixture = json.loads(Path(sys.argv[1]).read_bytes())
out = Path(sys.argv[2])
for name, data in (("vk", fixture["verification_key"]), ("public", fixture["wrap"]["public"]),
                   ("proof", fixture["wrap"]["proof"])):
    (out / f"{name}.json").write_text(json.dumps(data), encoding="utf-8")
print(fixture["owner_public_key"])
PYBUILD
)"
PYTHONPATH=src:. python3 -m fourthgraph.verification.groth16_bn254 \
  --runar "${1:-workspace/runar}" --go "${GROTH16_GO:-go}" --source "$source" \
  --verification-key "$out/vk.json" --public "$out/public.json" --proof "$out/proof.json" \
  --owner "$owner" --output "$out/lock.json" --witness-output "$out/witness.hex"
