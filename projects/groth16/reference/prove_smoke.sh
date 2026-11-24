#!/usr/bin/env bash
# The ceremony and circuit are for interoperability testing only.
set -euo pipefail

project="$(cd "$(dirname "$0")/.." && pwd)"
root="$(cd "$project/../.." && pwd)"
command -v circom >/dev/null
command -v snarkjs >/dev/null
command -v node >/dev/null
command -v openssl >/dev/null
work="$(mktemp -d "${TMPDIR:-/tmp}/groth16-snarkjs.XXXXXX")"
printf 'Test artifacts: %s\n' "$work"

circom "$project/circuits/toolchain_smoke.circom" --r1cs --wasm --sym --prime bls12381 -o "$work"
printf '%s\n' '{"outputValue":"82","offset":"5","a":"7","b":"11"}' > "$work/input.json"
node "$work/toolchain_smoke_js/generate_witness.js" "$work/toolchain_smoke_js/toolchain_smoke.wasm" \
  "$work/input.json" "$work/witness.wtns"

snarkjs powersoftau new bls12-381 8 "$work/initial.ptau"
snarkjs powersoftau contribute "$work/initial.ptau" "$work/contributed.ptau" \
  --name="Smoke phase 1" -e="$(openssl rand -hex 32)"
snarkjs powersoftau prepare phase2 "$work/contributed.ptau" "$work/final.ptau"
snarkjs groth16 setup "$work/toolchain_smoke.r1cs" "$work/final.ptau" "$work/initial.zkey"
snarkjs zkey contribute "$work/initial.zkey" "$work/final.zkey" \
  --name="Smoke phase 2" -e="$(openssl rand -hex 32)"
snarkjs zkey export verificationkey "$work/final.zkey" "$work/verification_key.json"
snarkjs groth16 prove "$work/final.zkey" "$work/witness.wtns" "$work/proof.json" "$work/public.json"
snarkjs groth16 verify "$work/verification_key.json" "$work/public.json" "$work/proof.json"
PYTHONPATH="$root:$project/reference" python3 "$project/reference/import_proof.py" \
  "$work/verification_key.json" "$work/proof.json" "$work/public.json" --out "$work/bsv"
