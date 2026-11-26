"""Compare the published Deferred lock with three builds of the same Forth source."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
from textwrap import wrap

from deferred import (
    ACTIVATION_SIGHASH, OPTIMIZATIONS, activate_input, funding_output_from_owner_hash, target_output_from_owner_hash,
)
from fixed_templates import TEMPLATE_VERSION
from forth_lock import SOURCE, compile_template
from fourthgraph import PROJECT_VERSION
from fourthgraph.benchmark.validation import stack_profile
from fourthgraph.bsv.script import asm
from fourthgraph.bsv.transaction import CHRONICLE, FORKID, SIGHASH_ALL, Input, Output, Transaction

RELEASE = Path(__file__).resolve().parents[1] / "template" / f"v{TEMPLATE_VERSION}"
MODES = {
    "BIP143 SINGLE": ACTIVATION_SIGHASH,
    "BIP143 ALL": FORKID | SIGHASH_ALL,
    "OTDA ALL": CHRONICLE | FORKID | SIGHASH_ALL,
}


def comparison():
    layout = json.loads((RELEASE / "layout.json").read_text(encoding="ascii"))
    owners = [(row["value_sats"], bytes.fromhex(row["owner_hash160"])) for row in layout["vectors"][:2]]
    targets = tuple(target_output_from_owner_hash(value, owner) for value, owner in owners)
    sponsor = Output(10_000, asm("OP_1"))
    change = Output(8_000, sponsor.script)
    variants, scripts = {}, {}
    for optimization in (None, *OPTIMIZATIONS):
        name = optimization or "published"
        locks = tuple(funding_output_from_owner_hash(value, owner, optimization=optimization)
                      for value, owner in owners)
        first_lock = locks[0].script
        scripts[name] = first_lock
        funding = Transaction((Input(b"\xf0" * 32, 0),), (*locks, sponsor))
        funding_bytes = len(funding.serialize())
        row = {
            "lock_bytes": len(first_lock),
            "lock_sha256": sha256(first_lock).hexdigest(),
            "funding_txid": funding.txid(),
            "funding_transaction_bytes": funding_bytes,
            "activations": {},
        }
        if optimization is not None:
            row["compiler"] = compile_template(optimization).activation.describe()
        for mode, flag in MODES.items():
            tx = Transaction(tuple(Input(funding.txid_wire(), index) for index in range(3)), (*targets, change))
            for index in range(len(locks)):
                tx = activate_input(tx, index, funding.serialize(), sighash=flag)
            activation_bytes = len(tx.serialize())
            witness = tx.inputs[0].script
            profile = stack_profile(first_lock, witness)
            if "unavailable" in profile:
                raise ValueError(profile["unavailable"])
            row["activations"][mode] = {
                "txid": tx.txid(),
                "sighash": f"{flag:02x}",
                "unlock_bytes": len(witness),
                "transaction_bytes": activation_bytes,
                "funding_and_activation_bytes": funding_bytes + activation_bytes,
                "first_input_stack": profile,
            }
        variants[name] = row
    if bytes.fromhex((RELEASE / "template.hex").read_text(encoding="ascii")) != scripts["published"]:
        raise ValueError("published lock differs from the v0.2.0 template")
    report = {
        "compiler_version": PROJECT_VERSION,
        "forth_source_sha256": sha256(SOURCE.read_bytes()).hexdigest(),
        "target_r1_version": TEMPLATE_VERSION,
        "fixture": {
            "funding_inputs_outputs": [1, 3],
            "activation_inputs_outputs": [3, 3],
            "values_sats": [value for value, _ in owners],
            "target_lock_bytes": [len(output.script) for output in targets],
            "sponsor_value_sats": sponsor.value,
            "sponsor_change_sats": change.value,
            "transaction_version": 2,
        },
        "variants": variants,
    }
    return report, scripts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, help="also write comparison.json and the four fixture locks")
    args = parser.parse_args()
    report, scripts = comparison()
    content = json.dumps(report, indent=2) + "\n"
    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "comparison.json").write_text(content, encoding="ascii")
        for name, script in scripts.items():
            (args.output_dir / f"{name}.hex").write_text("\n".join(wrap(script.hex(), 128)) + "\n", encoding="ascii")
    print(content, end="")


if __name__ == "__main__":
    main()
