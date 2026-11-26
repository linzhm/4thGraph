#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
exec bash ../../../tools/verify_node.sh test_node test_acceptance
