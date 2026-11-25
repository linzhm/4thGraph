#!/usr/bin/env bash
# Replay one project's public wallet vectors through all four source SDKs.
set -euo pipefail
cd "$(dirname "$0")/../.."

project=${1:?usage: verify.sh PROJECT}
case "$project" in
  p2pk-p2pkh-baseline|p2pkh-sm2|lamport-ots|wots-plus|ml-dsa) ;;
  *) printf 'Unknown SDK project: %s\n' "$project" >&2; exit 2 ;;
esac

scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
export SCRIPT_LAB_SDK_PROJECT="$project"
export SCRIPT_LAB_SDK_PYTHON="${SCRIPT_LAB_SDK_PYTHON:-$(command -v python)}"
export SCRIPT_LAB_SDK_BRIDGE="$PWD/shared/sdk/python/bridge.py"
export SCRIPT_LAB_SDK_VECTOR="$scratch/vectors.json"
"$SCRIPT_LAB_SDK_PYTHON" shared/sdk/tests/vector.py "$project" "$SCRIPT_LAB_SDK_VECTOR"
node --test shared/sdk/tests/typescript.ts
(cd "projects/$project/sdk/go" && go test ./... -v)

# Keep the Rust build and its generated Cargo.lock outside the source tree.
mkdir -p "$scratch/shared/sdk/rust" "$scratch/shared/sdk/tests" "$scratch/projects/$project/sdk/rust"
cp -R shared/sdk/rust/{Cargo.toml,src} "$scratch/shared/sdk/rust/"
cp shared/sdk/tests/rust.rs "$scratch/shared/sdk/tests/"
cp -R "projects/$project/sdk/rust/"{Cargo.toml,src,tests} "$scratch/projects/$project/sdk/rust/"
cargo test --manifest-path "$scratch/projects/$project/sdk/rust/Cargo.toml"
