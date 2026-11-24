#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
exec bash ../../../shared/verify_node_apple.sh lamport-ots "${LAMPORT_RPC_PORT:-18449}" test_node "$@"
