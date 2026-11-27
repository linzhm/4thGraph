"""Build the example lock and its witness from the pinned proof-counter fixture."""

import json
from pathlib import Path

from fourthgraph.verification.bls12381.build import layout_candidates, select_layout
from fourthgraph.verification.bls12381.verifier import input_sources, public_signals


PROJECT = Path(__file__).resolve().parents[1]
FIXTURE = PROJECT.parent / "proof-counter" / "versions/v0.1.0/bls12381-counter.json"


def main():
    fixture = json.loads(FIXTURE.read_bytes())
    source = PROJECT / "verifier.fth"
    sources = input_sources((PROJECT / "versions/v0.1.0/input-sources.json").read_bytes())
    candidates = layout_candidates(json.dumps(fixture["verification_key"]), source.read_bytes(), sources,
                                   script_era="genesis", entry="verify-proof", source_path=source)
    verifier, artifact = select_layout(candidates, "path-bytes")
    sample = fixture["wrap"]
    signals = public_signals(json.dumps(sample["public"]))
    witness = verifier.witness(signals, json.dumps(sample["proof"]), sources=sources)

    output = PROJECT / "workspace/build"
    output.mkdir(parents=True, exist_ok=True)
    (output / "lock.json").write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    (output / "witness.hex").write_text(witness.hex() + "\n", encoding="utf-8")
    print(output / "lock.json")
    print(output / "witness.hex")


if __name__ == "__main__":
    main()
