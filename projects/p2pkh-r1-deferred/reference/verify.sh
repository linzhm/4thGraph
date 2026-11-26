#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONPATH="../../../src:../../..${PYTHONPATH:+:$PYTHONPATH}"
exec bash ../../../tools/verify_node.sh test_node test_activation_acceptance "$@"
