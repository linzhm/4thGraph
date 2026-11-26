#!/usr/bin/env bash
# Replay the same public wallet API vector in each source SDK.
set -euo pipefail
cd "$(dirname "$0")/../.."

project=${1:?usage: verify_wallet.sh PROJECT}
case "$project" in
  p2pk-p2pkh-baseline|p2pkh-r1|p2pkh-r1-deferred|p2pkh-sm2|p2pkh-schnorr|lamport-ots|wots-plus|ml-dsa) ;;
  *) printf 'Unknown wallet project: %s\n' "$project" >&2; exit 2 ;;
esac

scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
export SCRIPT_LAB_SDK_PROJECT="$project"
export SCRIPT_LAB_SDK_PYTHON="${SCRIPT_LAB_SDK_PYTHON:-$(command -v python)}"
export SCRIPT_LAB_SDK_BRIDGE="$PWD/shared/sdk/python/bridge.py"
export SCRIPT_LAB_SDK_VECTOR="$scratch/vectors.json"
"$SCRIPT_LAB_SDK_PYTHON" shared/sdk/tests/wallet_vectors.py "$project" "$SCRIPT_LAB_SDK_VECTOR"
node --test shared/sdk/tests/wallet.ts
(cd shared/sdk/go && go test -count=1 -run TestWalletReplay -v)

cp -R shared/sdk/rust/{Cargo.toml,src,tests} "$scratch/"
cargo test --manifest-path "$scratch/Cargo.toml" --test wallet
