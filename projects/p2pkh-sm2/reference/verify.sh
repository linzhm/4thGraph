#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
exec bash ../../../shared/verify_node.sh test_sighash test_node
