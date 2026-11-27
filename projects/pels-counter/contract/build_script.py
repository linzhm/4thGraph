"""Compile the fixed-fee full-preimage variant using the existing project builder."""
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from pels_counter import PelsSource, SOURCE, counter_builds


def build():
    raw = SOURCE.read_bytes()
    source = PelsSource(raw.decode(), source_path=SOURCE)
    _, builds = counter_builds(source.words["advance"], source.amount_rule)
    first = builds[0]
    assert first.authentication == "baseline" and first.witness == "full-preimage"
    return first.root.script, {"source_sha256": sha256(raw).hexdigest(),
                               "dependencies": [asdict(dep) for dep in source.library_imports]}
