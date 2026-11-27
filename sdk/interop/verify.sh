#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
interop="$root/sdk/interop"
venv="$root/workspace/bsv-interop-venv"
python="$venv/bin/python"
scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT
fixture="$scratch/payment.json"
projects="$scratch/projects.json"
export PYTHONPATH="$root/src:$root${PYTHONPATH:+:$PYTHONPATH}"

if [[ ! -x "$python" ]]; then
  python3 -m venv "$venv"
fi
"$python" -m pip install --disable-pip-version-check -r "$interop/python/requirements.txt"
"$python" -m pip check
npm ci --prefix "$interop/typescript" --no-audit --no-fund

"$python" -m sdk.interop.python.payment > "$fixture"
"$python" -m sdk.interop.python.projects "$projects" "$@"
node "$interop/typescript/verify.mjs" "$fixture" "$projects"
(cd "$interop/go" && GOWORK=off go run -mod=readonly . "$fixture" "$projects")
cargo run --locked --manifest-path "$interop/rust/Cargo.toml" \
  --target-dir "${CARGO_TARGET_DIR:-$root/workspace/build/bsv-interop}" -- "$fixture" "$projects"
