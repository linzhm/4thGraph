"""Generate 4thGraph profiles in the native compiler's Python environment."""

import argparse
from hashlib import sha256
import json
from pathlib import Path

from bls12381.verifier import Dynamic, bind_public_output, input_sources, public_packet
from build_verifier import ForthVerifier, SOURCE

TERMINAL_VALUE = 75_000


def generate(material):
    key, source = json.dumps(material["key"]), SOURCE.read_bytes()
    script_era = material.get("script_era", "genesis")
    projective = ForthVerifier(key, source, script_era=script_era)
    statements = tuple(tuple(map(int, case["signals"])) for case in material["cases"])
    proofs = tuple(json.dumps(case["proof"]) for case in material["cases"])
    inputs = material.get("input_sources")
    dynamic = input_sources(json.dumps(inputs)) if inputs is not None else (Dynamic(128),) * len(statements[0])
    full = {
        "4thgraph-dynamic": dynamic,
        "4thgraph-dynamic-baseline": dynamic,
        "4thgraph-affine-inline": dynamic,
        "4thgraph-affine-witness": dynamic,
        "4thgraph-hybrid": (statements[0][0], *dynamic[1:]),
        "4thgraph-fixed": statements[0],
        "4thgraph-bound": dynamic,
    }
    if inputs is not None:
        full = {name: dynamic for name in ("4thgraph-dynamic", "4thgraph-affine-inline", "4thgraph-affine-witness")}
    profiles = {}
    for name, sources in full.items():
        if name.startswith("4thgraph-affine-"):
            verifier = ForthVerifier(key, source, witness_layout=name.removeprefix("4thgraph-"), script_era=script_era)
        else:
            verifier = projective
        compact = name != "4thgraph-dynamic-baseline"
        lock = verifier.compile(sources, compact=compact)
        if name == "4thgraph-bound":
            lock = bind_public_output(lock, sources, TERMINAL_VALUE)
        indices = range(len(statements)) if sources == dynamic else (0,)
        profiles[name] = {
            "artifact": verifier.artifact(sources, None, lock, compact=compact),
            "lock_sha256": sha256(lock).hexdigest(),
            "witness": {i: verifier.witness(statements[i], proofs[i], sources=sources).hex() for i in indices},
            "packets": {i: public_packet(sources, statements[i]).hex() for i in indices},
        }
    return profiles


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("material", type=Path)
    cli.add_argument("output", type=Path)
    args = cli.parse_args()
    result = generate(json.loads(args.material.read_text()))
    args.output.write_text(json.dumps(result) + "\n")
