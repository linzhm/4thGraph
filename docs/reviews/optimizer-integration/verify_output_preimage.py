"""Exercise the proposed REQUIRE path in an isolated #83 library overlay."""

from hashlib import sha256
import json
from pathlib import Path
import shutil
import sys
from tempfile import TemporaryDirectory

from fourthgraph.benchmark.validation import CONTEXT_PIN, chain_metadata, chain_verdict
from fourthgraph.bsv.script import push
from fourthgraph.bsv.transaction import Input, Output, Transaction, preimage_forkid
from fourthgraph.compiler.script_builder import ScriptBuilder


def main(project_forth):
    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError("review fixture requires pinned chain-gang")
    examples = Path(__file__).resolve().parent
    with TemporaryDirectory() as temp:
        root = Path(temp)
        shutil.copytree(examples / "stdlib", root / "stdlib")
        for name in ("pels-successor.fth", "pels-binding.fth", "pels-verify.fth"):
            shutil.copyfile(project_forth / name, root / "stdlib/pels" / name)
        source = root / "output-preimage.fth"
        shutil.copyfile(examples / source.name, source)
        builder = ScriptBuilder.from_file(source, formula_passes=[])
        lock = builder.emit("example-lock", b"", bytes.fromhex("0300000000"))

    parent = Transaction((Input(bytes(32), 0),), (Output(10_000, lock),))
    cases = []
    for locktime, amount, expected in ((42, 10_000, True), (43, 10_000, False), (42, 9_999, False)):
        tx = Transaction((Input(parent.txid_wire(), 0),), (Output(amount, lock),), locktime=locktime)
        message = preimage_forkid(tx, 0, parent.outputs[0].value, lock[7:], 0x41)
        signed = tx.with_script(0, push(message[-8:]) + push(message[:-40]))
        observed = chain_verdict(signed, [parent])
        if observed != expected:
            raise ValueError(f"unexpected result at locktime {locktime}, output amount {amount}")
        cases.append({"locktime": locktime, "output_sats": amount, "expected": expected,
                      "chain_gang": observed, "bsv_node": "not_run", "txid": signed.txid()})
    print(json.dumps({"chain": engine, "script_bytes": len(lock), "script_sha256": sha256(lock).hexdigest(),
                      "cases": cases}, indent=2))


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
