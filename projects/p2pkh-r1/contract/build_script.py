"""Rebuild the approved ordinary-path template and cross-check the frozen bytes."""
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(PROJECT/"forth"), str(PROJECT/"reference")]
from msm_compiler import R1MSMCompiler


def build():
    compiler = R1MSMCompiler()
    lock, _ = compiler.link(compiler.lower(compiler.plan("split-5x4-affine-g")))
    if lock.script != bytes.fromhex((PROJECT/"versions/v0.6.0/template.hex").read_text()):
        raise ValueError("rebuilt lock differs from v0.6.0")
    return lock.script, {"source_sha256": sha256(compiler.source).hexdigest(),
                         "dependencies": [asdict(dep) for dep in compiler.frontend.library_imports]}
