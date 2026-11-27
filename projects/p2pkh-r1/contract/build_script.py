"""Use the frozen v0.6.0 ordinary-path lock for its approved wallet bundle."""
from hashlib import sha256
import json
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "reference"))
from fixed_templates import read_compiled_template


def build():
    release = PROJECT / "versions/v0.6.0"
    layout = json.loads((release / "layout.json").read_bytes())
    approved = json.loads((release / "contract/manifest.json").read_bytes())
    lock = read_compiled_template(release, layout).script
    if sha256(lock).hexdigest() != approved["script"]["sha256"]:
        raise ValueError("frozen v0.6.0 lock differs from the approved wallet bundle")
    return lock, approved["forth_inputs"]
