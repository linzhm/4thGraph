#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONPATH="../../..${PYTHONPATH:+:$PYTHONPATH}"
exec bash ../../../shared/verify_node.sh test_node "$@"
