#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
exec bash ../../../shared/verify_node_apple.sh wots-plus "${WOTS_RPC_PORT:-18450}" test_node.NodeTests "$@"
