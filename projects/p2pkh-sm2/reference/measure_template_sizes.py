"""Replay two SM2 templates with the same payment shapes and signing modes."""
import argparse
import json
import os
from pathlib import Path

from assemble import AFFINE_GENERATOR_TEMPLATE_VERSION, CARRIED_FIELD_TEMPLATE_VERSION, TEMPLATE_PROFILES
from assemble import PUBLIC_TABLE_TEMPLATE_VERSION, TEMPLATE_VERSIONS, VERSION_DIRECTORY, forth_compiler
from benchmark_adapter import TEMPLATES
from fourthgraph import PROJECT_VERSION
from fourthgraph.benchmark.cases import batch
from fourthgraph.benchmark.run import dump_json
from fourthgraph.benchmark.validation import Node, chain_metadata, measure_leg


def compare(node, compiler_commit, baseline=AFFINE_GENERATOR_TEMPLATE_VERSION,
            candidate=CARRIED_FIELD_TEMPLATE_VERSION):
    sizes = {}
    payments = {"bip143-all": {}, "otda-all": {}}
    fan_in = {f"{inputs}x1": {} for inputs in (12, 24, 40)}
    fixed_fixture = TEMPLATE_PROFILES[baseline] if candidate >= PUBLIC_TABLE_TEMPLATE_VERSION else None
    for version in (baseline, candidate):
        profile = TEMPLATE_PROFILES[version]
        layout = json.loads((VERSION_DIRECTORY / profile / "layout.json").read_text(encoding="utf-8"))
        compiler = forth_compiler(bytes(20), version)
        sizes[profile] = {
            "lock_bytes": layout["script_bytes"], "otda_program_bytes": layout["otda_constructor"]["bytes"],
            "window_bytes": len(compiler.emit("sm2-window", b"")),
            "window_step_bytes": len(compiler.emit("sm2-step-split5", b"")),
        }
        if candidate >= PUBLIC_TABLE_TEMPLATE_VERSION:
            sizes[profile]["window_table_bytes"] = len(compiler.emit("sm2-window-table", b""))
        for mode, name in ((0x41, "bip143-all"), (0x61, "otda-all")):
            shapes = ("2x2", *fan_in) if mode == 0x61 else ("2x2",)
            for shape in shapes:
                label = f"p2pkh-sm2/{fixed_fixture or profile}/{mode:02x}/batch/{shape}"
                leg = batch(TEMPLATES[profile], mode, tuple(map(int, shape.split("x"))), label, None)
                baseline_shape = shape == "2x2"
                stats = measure_leg(leg, node, samples=0, profile_stack=baseline_shape, check_control=baseline_shape)
                row = {key: stats[key] for key in ("transaction_bytes", "unlock_bytes", "txid")}
                if baseline_shape:
                    row["peak_stack_payload_bytes"] = stats["stack_input_zero"]["combined_payload_bytes"]
                    payments[name][profile] = row
                else:
                    fan_in[shape][profile] = row
    return {
        **({"fixture_label_profile": fixed_fixture} if fixed_fixture else {}),
        "baseline": TEMPLATE_PROFILES[baseline],
        "compiler_version": PROJECT_VERSION, "compiler_commit": compiler_commit,
        "bsv_node_version": "1.2.3", "chain_gang_commit": chain_metadata()["commit"],
        "validation": "Peerless regtest script replay with supplied prevouts",
        "component_bytes": sizes, "payments_2x2": payments, "otda_all_fan_in": fan_in,
        "source": "README.md#" + TEMPLATE_PROFILES[candidate].replace(".", ""),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler-commit", required=True)
    choices = tuple(version for version in TEMPLATE_VERSIONS if version >= AFFINE_GENERATOR_TEMPLATE_VERSION)
    parser.add_argument("--baseline", type=int, choices=choices, default=AFFINE_GENERATOR_TEMPLATE_VERSION)
    parser.add_argument("--candidate", type=int, choices=choices, default=CARRIED_FIELD_TEMPLATE_VERSION)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.baseline >= args.candidate:
        parser.error("candidate must follow baseline")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    dump_json(args.report, compare(node, args.compiler_commit, args.baseline, args.candidate))
