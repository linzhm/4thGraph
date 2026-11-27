"""Pair a project's existing Forth builder with its independently built project reactor."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory

from fourthgraph.bsv.artifacts import ANCHORS, script_listing
from fourthgraph.workflow.project_contract import ABI

ROOT = Path(__file__).resolve().parents[1]


def describe(path):
    return {"file":path.name, "sha256":sha256(path.read_bytes()).hexdigest(), "bytes":path.stat().st_size}


def build(project, output):
    config = ROOT / "projects" / project / "contract"
    spec = json.loads((config/"project.json").read_bytes())
    # Only repository-owned build adapters execute, never instructions from a wallet package.
    script, inputs = runpy.run_path(str(config/"build_script.py"))["build"]()
    output = Path(output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=output.parent) as scratch:
        dest = Path(scratch)
        raw = dest/"template.script"
        raw.write_bytes(script)
        listing = dest/"template.asm"
        anchors = []
        with listing.open("w") as lines:
            for op in script_listing(script):
                lines.write(f'{op["offset"]:06x}  {op["op"]} {op.get("data_hex", "")}'.rstrip()+"\n")
                if op["op"] in ANCHORS:
                    anchors.append(op)
        module = dest / spec["module"]
        if module.parent != dest or module.suffix != ".wasm":
            raise ValueError("project module must be a local .wasm filename")
        env = {**os.environ, "GOOS":"wasip1", "GOARCH":"wasm", "CGO_ENABLED":"0", "GOTOOLCHAIN":"local",
               "GOWORK":"off", "GOPROXY":"off"}
        env.setdefault("GOCACHE", str(ROOT/"workspace/go-cache"))
        go = os.environ.get("GO", "go")
        subprocess.run([go, "build", "-trimpath", "-buildvcs=false", "-buildmode=c-shared", "-ldflags=-s -w -buildid=",
                        "-o", str(module), str(config/"main.go")], cwd=ROOT/"sdk/go", env=env, check=True)
        fixtures = dest/"cases.json"
        shutil.copyfile(config/"cases.json", fixtures)
        manifest = {"abi":ABI, **spec, "script":describe(raw), "anchors":anchors, "listing":describe(listing),
                    "module":describe(module), "fixtures":describe(fixtures), "forth_inputs":inputs,
                    "wasm_builder":subprocess.check_output([go,"version"],text=True).strip(),
                    "wasm_sources":{str(p.relative_to(ROOT)):sha256(p.read_bytes()).hexdigest()
                                    for p in [config/"main.go", *sorted((ROOT/"sdk/go/contractabi").glob("*.go"))]}}
        m = dest/"manifest.json"
        m.write_text(json.dumps(manifest, indent=2, sort_keys=True)+"\n")
        # A manifest is published only with a complete bundle. Do not overwrite old approvals.
        if output.exists():
            if not all((output/p.name).is_file() and (output/p.name).read_bytes()==p.read_bytes() for p in dest.iterdir()):
                raise ValueError("output already contains a different bundle; select another directory")
        else:
            dest.rename(output)
        return describe(output/"manifest.json")


def main(argv=None):
    cli = argparse.ArgumentParser()
    cli.add_argument("project", choices=("p2pkh-r1","pels-counter"))
    cli.add_argument("output", type=Path)
    mode = cli.add_mutually_exclusive_group()
    mode.add_argument("--smoke", action="store_true", help="verify this local build with disposable fixture keys")
    mode.add_argument("--verify", action="store_true", help="verify the fixed fixture with pinned chain-gang")
    cli.add_argument("--with-bsv-node", action="store_true", help="also verify on the configured local BSV Node")
    args = cli.parse_args(argv)
    if args.with_bsv_node and not (args.smoke or args.verify):
        cli.error("--with-bsv-node requires --verify or --smoke")
    result = build(args.project, args.output)
    if args.smoke or args.verify:
        from verify_project_contract import RECEIPT_SCHEMA, VerificationFailure, diagnostic_value, optional_bsv_node, verify_bundle

        try:
            node = optional_bsv_node(args.with_bsv_node)
            receipt = verify_bundle(args.output/"manifest.json", result["sha256"], node, ephemeral=args.smoke)
        except VerificationFailure as exc:
            print(json.dumps(exc.report, sort_keys=True), file=sys.stderr)
            return 1
        except (ValueError, OSError, KeyError, TypeError, RuntimeError, ImportError) as exc:
            report = VerificationFailure(RECEIPT_SCHEMA, getattr(exc, "status", type(exc).__name__), diagnostic_value(str(exc))).report
            print(json.dumps(report, sort_keys=True), file=sys.stderr)
            return 1
        path = args.output/("smoke.json" if args.smoke else "receipt.json")
        with TemporaryDirectory(dir=args.output) as tmp:
            temp = Path(tmp)/path.name
            temp.write_text(json.dumps(receipt, indent=2, sort_keys=True)+"\n")
            temp.replace(path)
        result["receipt"] = describe(path)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
