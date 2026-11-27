#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONPATH="../../../src:../../..${PYTHONPATH:+:$PYTHONPATH}"
exec bash ../../../tools/verify_node.sh test_curve_compiler test_fixed_templates test_lock_security test_payment test_payment_acceptance
