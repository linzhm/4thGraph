"""Run the review fixture with the compiler and PELS Forth words from the #83 snapshot."""

from hashlib import sha256
import json
from pathlib import Path
import sys

from fourthgraph.benchmark.validation import CONTEXT_PIN, chain_metadata, chain_verdict
from fourthgraph.bsv.script import push
from fourthgraph.bsv.transaction import Input, Output, Transaction, preimage_forkid
from fourthgraph.compiler.script_builder import ScriptBuilder


def main(project_forth):
    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError("review fixture requires the repository's pinned chain-gang")
    source = Path(__file__).with_name("status-labels.fth")
    builder = ScriptBuilder(source.read_text(), source_path=project_forth / source.name)
    draft, ready = (bytes.fromhex(tag) for tag in ("0300000000", "0900000000"))
    initial = builder.emit("status-lock", b"", draft)
    parent = Transaction((Input(bytes(32), 0),), (Output(10_000, initial),))
    steps = []
    for current, expected in ((draft, ready), (ready, draft)):
        prior = parent.outputs[0]
        assert prior.script[:7] == push(current) + b"\xab"
        # Independent expected successor uses the actual current code and retains the amount.
        successor = push(expected) + prior.script[6:]
        assert successor == builder.emit("status-lock", b"", expected)
        tx = Transaction((Input(parent.txid_wire(), 0),), (Output(prior.value, successor),))
        message = preimage_forkid(tx, 0, prior.value, prior.script[7:], 0x41)
        signed = tx.with_script(0, push(message[-8:]) + push(message[:-40]))
        if not chain_verdict(signed, [parent]):
            raise ValueError("chain-gang rejected the expected transition")
        steps.append({"from": current.hex(), "to": expected.hex(), "txid": signed.txid(),
                      "bytes": len(signed.serialize()), "chain_gang": True, "bsv_node": "not_run"})
        parent = signed
    print(json.dumps({"chain": engine, "source_sha256": sha256(source.read_bytes()).hexdigest(),
                      "initial_lock_bytes": len(initial), "initial_lock_sha256": sha256(initial).hexdigest(),
                      "steps": steps}, indent=2))


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
