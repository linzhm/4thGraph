#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--interop" ]]; then
  shift
  exec bash "$(dirname "$0")/interop/verify.sh" "$@"
fi
exec bash "$(dirname "$0")/verify_wallet.sh" "$@"
