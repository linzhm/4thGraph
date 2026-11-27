"""Compile and explain a complete preimage witness for a concrete previous output."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

from fourthgraph.bsv.otda_reconstruction import Reconstruction, push_repeated_bytes
from fourthgraph.bsv.spend_authorization import prepare_authorization
from fourthgraph.bsv.transaction import CHRONICLE, Transaction
from fourthgraph.compiler.preimage import compile_preimage


def _pattern(template):
    script = bytes.fromhex(template["script_hex"])
    parts, widths = [], []
    cursor = 0
    for field in template["fields"]:
        offset, length = field["offset"], field["length"]
        if type(offset) is not int or type(length) is not int or not cursor <= offset < offset + length <= len(script):
            raise ValueError("template fields must be ordered, nonoverlapping and within the script")
        parts.append(script[cursor:offset])
        widths.append(length)
        cursor = offset + length
    parts.append(script[cursor:])
    return Reconstruction(b"".join(map(push_repeated_bytes, parts)), tuple(parts), tuple(widths))


def build(request):
    tx = Transaction.parse(bytes.fromhex(request["transaction_hex"]))
    parent = Transaction.parse(bytes.fromhex(request["parent_hex"]))
    index = request["input_index"]
    if type(index) is not int or not 0 <= index < len(tx.inputs):
        raise ValueError("input_index is out of range")
    current = tx.inputs[index]
    if current.script or current.txid != parent.txid_wire() or not 0 <= current.vout < len(parent.outputs):
        raise ValueError("the unsigned input must spend the supplied parent")
    active, flag = request["chronicle_active"], request["sighash"]
    if type(active) is not bool or type(flag) is not int:
        raise ValueError("expected a boolean activation state and an integer sighash")
    if flag & CHRONICLE and not active:
        raise ValueError("OTDA requires active Chronicle")
    # The approved signing path supplies the executed and cleaned scriptCode.
    ordinary = bytes.fromhex(request["script_code_hex"])
    companion = bytes.fromhex(request.get("companion_code_hex", ""))
    auth = prepare_authorization(tx, index, parent.outputs[current.vout].value, flag,
                                 ordinary_code=ordinary, companion_code=companion)
    if auth.companion and not companion:
        raise ValueError("unpaired SINGLE requires the approved companion scriptCode")
    transaction_hash = sha256(tx.serialize()).hexdigest()
    digest = auth.checked_digest().hex()
    if "prepared" in request:
        # The WASM ABI has already computed the preimage and digest for this candidate.
        expected = {"candidate": transaction_hash, "outpoint": current.outpoint().hex(),
                    "input_index": index, "mode": flag, "preimage": auth.preimage.hex(), "digest": digest}
        if any(request["prepared"][key] != value for key, value in expected.items()):
            raise ValueError("WASM prepared result differs from the approved preimage or signing digest")
    plan = compile_preimage(tx, index, auth, tuple(map(_pattern, request.get("templates", ()))),
                            chronicle_active=active, mode=request.get("mode", "auto"),
                            witness_tail_bytes=request.get("witness_tail_bytes", 0),
                            max_payload_bytes=request.get("max_payload_bytes"))
    return {
        "schema": "4thgraph.preimage-constructor/1",
        "transaction_sha256": transaction_hash,
        "parent_txid": parent.txid(), "input_index": index, "sighash": flag, "companion": auth.companion,
        "preimage_bytes": len(auth.preimage), "preimage_sha256": sha256(auth.preimage).hexdigest(),
        "signing_digest_sha256d": digest,
        "selected": plan.selected, "program_hex": plan.program.hex(), "candidates": list(plan.candidates),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(prog="4thgraph preimage-constructor", description=__doc__)
    parser.add_argument("request", help="JSON request file, or - for stdin")
    args = parser.parse_args(argv)
    try:
        request = json.load(sys.stdin) if args.request == "-" else json.loads(Path(args.request).read_text())
        result = build(request)
    except (OSError, TypeError, ValueError, KeyError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))
