#!/usr/bin/env bash
# Build two real CPN paths and export a portable workbench with their replay receipts.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-$root/workspace/cpn-demo}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
cd "$root"
export PYTHONPATH="$root/src:$root${PYTHONPATH:+:$PYTHONPATH}"
cp projects/proof-counter/counter.fth "$out/counter.fth"
cp projects/proof-counter/workflow.fth "$out/workflow.fth"
printf '\nassignment-disclosure: decide allow ;\n' >> "$out/workflow.fth"
cat > "$out/catalog.json" <<'JSON'
{
  "workflow_paths": {
    "direct": {"layout": "fused", "stages": {
      "advance": {"role": "compute next state", "backend": "script"},
      "decide": {"role": "choose settlement", "backend": "script"}
    }},
    "handoff": {"layout": "serial", "stages": {
      "advance": {"role": "write next state to the continuation lock", "backend": "script"},
      "decide": {"role": "read next state from the spent output", "backend": "script"}
    }},
    "settlement": {"layout": "atomic", "stages": {
      "advance": {"role": "compute next state", "backend": "script"},
      "decide": {"role": "choose settlement", "backend": "r1cs"}
    }}
  }
}
JSON

cpn() { python3 -m fourthgraph.workflow.protocol cpn "$@"; }
cpn test-keys > "$out/keys.json"
cpn tune "$out/workflow.fth" --keys "$out/keys.json" --target both --current 19 \
  --backend-catalog "$out/catalog.json" > "$out/report.json"

bash tools/verify_node.sh --profile long-script -- bash -eu -c '
  out=$1
  for name in direct handoff settlement; do
    python3 -m fourthgraph.workflow.protocol cpn replay "$out/workflow.fth" \
      --report "$out/report.json" --backend-catalog "$out/catalog.json" \
      --candidate "path/$name~stack" --output "$out/$name-receipt.json"
  done
' bash "$out"

for name in direct handoff settlement; do
  cpn verify "$out/$name-receipt.json" --report "$out/report.json" --candidate "path/$name~stack" \
    > "$out/$name-verified.json"
done
cpn workbench "$out/report.json" --candidate 'path/handoff~stack' --title 'Proof counter' --source "$out/workflow.fth" \
  --receipt "$out/direct-receipt.json" --receipt "$out/handoff-receipt.json" \
  --receipt "$out/settlement-receipt.json" --output "$out/index.html"
