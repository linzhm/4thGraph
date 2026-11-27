#!/usr/bin/env bash
# Build one wheel and replay the architecture fixtures from its installed code.
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
out="${1:?pass a new local output directory}"
mkdir -p -- "$out"
out="$(cd -- "$out" && pwd -P)"
if [[ -n $(ls -A -- "$out") ]]; then
    echo "Use an empty output directory." >&2
    exit 2
fi
if [[ -n $(git -C "$root" status --porcelain) ]]; then
    echo "Architecture acceptance requires a clean source commit." >&2
    exit 2
fi
commit="$(git -C "$root" rev-parse HEAD)"
export SOURCE_DATE_EPOCH="$(git -C "$root" show -s --format=%ct "$commit")"
py="${PYTHON:-python3}"
wheel_py="${WHEEL_PYTHON:-python3}"
unset REGTEST_URL REGTEST_COOKIE
export LC_ALL=C
mkdir "$out/wheel" "$out/run"
"$wheel_py" -m pip wheel --no-build-isolation --no-deps --no-index --wheel-dir "$out/wheel" "$root"
wheel=("$out"/wheel/fourthgraph-*.whl)
"$wheel_py" -m pip install --no-deps --no-index --target "$out/site" "${wheel[0]}"
export PYTHONPATH="$out/site${PYTHONPATH:+:$PYTHONPATH}:$root"
cd "$out/run"

fourthgraph() { "$py" -m fourthgraph.workflow.protocol "$@"; }
experiment() { fourthgraph experiment "$@"; }

fourthgraph --capabilities > compiler-capabilities.json
experiment capabilities > experiment-capabilities.json
printf '%s\n' '{"fixture":"bezier","evaluation":"spend","trace":true,"plans":[{},{"passes":["stack"]},{"passes":["rewrite","share","stack"]}]}' |
    experiment run - > bezier-first.json
experiment next bezier-first.json > bezier-next.json
experiment run bezier-next.json --parent bezier-first.json > bezier-second.json
experiment replay bezier-second.json --parent bezier-first.json > bezier-replay.json

for implementation in bezier bezier-linear; do
    printf '{"fixture":"bezier","evaluation":"spend","axis":"A","plans":[{"implementation":"%s","passes":["stack"]},{"implementation":"%s","passes":["rewrite","share","stack","search"]}]}\n' \
        "$implementation" "$implementation" | experiment run - > "$implementation-matrix.json"
    experiment replay "$implementation-matrix.json" > "$implementation-matrix-replay.json"
done
printf '%s\n' '{"fixture":"bezier","evaluation":"spend","axis":"B","plans":[{"implementation":"bezier","passes":["stack"]},{"implementation":"bezier-linear","passes":["stack"]}]}' |
    experiment run - > source-axis.json
experiment replay source-axis.json > source-axis-replay.json
printf '%s\n' '{"fixture":"point-add","evaluation":"spend","enumerate":"bindings"}' |
    experiment run - > point-add.json
experiment replay point-add.json > point-add-replay.json

"$py" -m unittest -v tests.test_pels_lock tests.test_pels_successor_library > pels-tests.log 2>&1
"$py" -m fourthgraph.replay.prefix_workflow "$root/projects/workflow-examples/serial-graph.fth" > three-stage.json

for project in workflow-examples p2pkh-r1; do
    "$py" "$root/tools/build_project_contract.py" "$project" "$out/$project" --verify > "$project-build.json"
    approval="$(sha256sum "$out/$project/manifest.json" | cut -d' ' -f1)"
    "$py" "$root/tools/verify_project_contract.py" "$out/$project/manifest.json" --approved-sha256 "$approval" \
        --replay "$out/$project/receipt.json" --output "$project-replay.json"
done

"$py" - "$commit" "${wheel[0]}" <<'PY'
from hashlib import sha256
import json
from pathlib import Path
import sys
from zipfile import ZipFile

from fourthgraph.benchmark.validation import chain_metadata

commit, wheel = sys.argv[1:]
with ZipFile(wheel) as archive:
    required = {
        "fourthgraph/benchmark/formulas/bezier.fth",
        "fourthgraph/benchmark/fixtures/point-add.fth",
        "fourthgraph/stdlib/wallet/pels-verify.fth",
        "fourthgraph/workflow/contract_runtime.mjs",
    }
    if missing := required.difference(archive.namelist()):
        raise ValueError(f"wheel is missing {sorted(missing)}")

def read(name):
    return json.loads(Path(name).read_bytes())

fixtures = {"bezier-first": (3, 625), "bezier-second": (2, 625), "bezier-matrix": (2, 625),
            "bezier-linear-matrix": (2, 625), "source-axis": (2, 625), "point-add": (3, 13)}
for name, (count, vectors) in fixtures.items():
    rows = read(name + ".json")["candidates"]
    if len(rows) != count or any(row["test"]["status"] != "passed"
                                 or row["test"]["spend"]["accepted"] != vectors
                                 or row["test"]["spend"]["rejected"] != vectors for row in rows):
        raise ValueError(f"fixture failed: {name}")
matrix = {}
for name in ("bezier", "bezier-linear"):
    matrix[name] = [{"passes": row["applied"]["passes"], "metrics": row["metrics"]}
                    for row in read(name + "-matrix.json")["candidates"]]
evidence = {str(path): sha256(path.read_bytes()).hexdigest()
            for path in sorted(Path(".").iterdir()) if path.is_file()}
for project in ("workflow-examples", "p2pkh-r1"):
    for name in ("manifest.json", "receipt.json"):
        path = Path("..", project, name)
        evidence[str(path)] = sha256(path.read_bytes()).hexdigest()
document = {"status": "passed", "compiler_commit": commit, "wheel_sha256": sha256(Path(wheel).read_bytes()).hexdigest(),
            "engine": chain_metadata(), "evidence_sha256": evidence, "matrix": matrix,
            "skipped": [line for line in Path("pels-tests.log").read_text().splitlines() if " ... skipped " in line]}
Path("../acceptance.json").write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
PY
