"""Build the exact dual-mode settlement lock and its local WASM policy."""

from pathlib import Path

from fourthgraph.compiler.source import SourceCompiler
from fourthgraph.workflow.pels import compile_pels
from fourthgraph.workflow.project_contract import SETTLEMENT_FIELDS
from fourthgraph.workflow.protocol import build_artifact


def build():
    source = Path(__file__).resolve().parent.parent / "pels-settle.fth"
    raw = source.read_bytes()
    compiler = SourceCompiler(raw.decode(), source_path=source, bindings={"recipient-lock": b"\x51"})
    artifact = build_artifact(compile_pels(compiler.words["settle"].pels, "chronicle-v2", "both"), raw)
    paths = {}
    for name, row in artifact["paths"].items():
        paths[name] = {"mode": row["sighash"], "signatures": 0, "requires_chronicle": row["requires_chronicle"],
                       "script_code_offset": row["script_code_offset"], "script_code_sha256": row["script_code_sha256"],
                       "witness_layout": row["layout"],
                       "authenticated_fields": list(SETTLEMENT_FIELDS) + (["previous_amount"] if name == "bip143" else [])}
    policy = {"paths": paths, "template_sha256": artifact["script_sha256"], "constraints": artifact["constraints"]}
    return bytes.fromhex(artifact["script_hex"]), {"source_sha256": artifact["source_sha256"],
                                                   "artifact_sha256": artifact["artifact_sha256"],
                                                   "settlement_policy": policy}
