"""Build and spend a continuing counter whose covenant preserves its own Script."""

import argparse
from dataclasses import replace
import json
import os
from pathlib import Path
from types import SimpleNamespace

from compiler import SourceCompiler, evaluate
from lowering import compile_word
from protocol import CURRENT_OUTPOINT, FLAG, FLAG_BYTES, PREVOUTS_HASH, ROOT_VALUE, UTXO, field
from shared.benchmark_validation import CONTEXT_PIN, Node, chain_metadata
from shared.pushtx import PUBLIC, binding_der
from shared.script import asm, number, push
from shared.transaction import Input, Output, Transaction, preimage_forkid
from wordsets import U32


SOURCE = Path(__file__).with_name("pels-counter.fth")
STATE_BYTES = 5
FEE = 1_000
VERSION = 2
SEPARATOR = asm("OP_CODESEPARATOR")


def covenant(advance):
    # Stack starts with the supplied preimage and the current counter push.
    start = asm("OP_DEPTH OP_2 OP_NUMEQUALVERIFY OP_SWAP OP_DUP OP_TOALTSTACK")
    one_input = (asm("OP_DUP") + field(CURRENT_OUTPOINT, 36) + asm("OP_HASH256 OP_OVER")
                 + field(PREVOUTS_HASH, 32) + asm("OP_EQUALVERIFY"))
    # The final 52 bytes contain amount, sequence, hashOutputs, locktime and sighash.
    tail = (asm("OP_SIZE") + number(52) + asm("OP_SUB OP_SPLIT OP_DUP") + field(48, 4)
            + push(FLAG_BYTES) + asm("OP_EQUALVERIFY OP_DUP") + field(12, 32) + asm("OP_TOALTSTACK")
            + field(0, 8) + asm("OP_BIN2NUM") + number(FEE) + asm("OP_SUB OP_DUP OP_0 OP_GREATERTHAN OP_VERIFY")
            + number(8) + asm("OP_NUM2BIN"))
    # The current Script code follows the state push and CODESEPARATOR. Its
    # CompactSize uses three bytes. Copy it from the authenticated preimage.
    script_code = asm("OP_SWAP") + number(104) + asm("OP_SPLIT OP_NIP OP_3 OP_SPLIT OP_NIP")
    prefix = (asm("OP_SIZE") + number(1 + STATE_BYTES + len(SEPARATOR)) + asm("OP_ADD OP_2 OP_NUM2BIN")
              + push(b"\xfd") + asm("OP_SWAP OP_CAT OP_ROT OP_SWAP OP_CAT") + number(STATE_BYTES) + asm("OP_CAT"))
    successor = (asm("OP_ROT OP_BIN2NUM") + advance + number(STATE_BYTES) + asm("OP_NUM2BIN OP_CAT")
                 + push(SEPARATOR) + asm("OP_CAT OP_SWAP OP_CAT OP_HASH256 OP_FROMALTSTACK OP_EQUALVERIFY"))
    authenticate = (asm("OP_FROMALTSTACK OP_HASH256") + binding_der() + push(bytes([FLAG])) + asm("OP_CAT")
                    + push(PUBLIC) + asm("OP_CHECKSIG"))
    return start + one_input + tail + script_code + prefix + successor + authenticate


def counter_output(code, value, satoshis):
    return Output(satoshis, push(value.to_bytes(STATE_BYTES, "little")) + SEPARATOR + code)


def spend(parent, code, output):
    tx = Transaction((Input(parent.txid_wire(), 0),), (output,), version=VERSION)
    preimage = preimage_forkid(tx, 0, parent.outputs[0].value, code, FLAG)
    return tx.with_script(0, push(preimage))


def next_counter(parent, code, advance):
    if not parent.outputs:
        raise ValueError("the parent has no output 0")
    output = parent.outputs[0]
    current = int.from_bytes(output.script[1:1 + STATE_BYTES], "little")
    if current >= U32 or output != counter_output(code, current, output.value):
        raise ValueError("parent output 0 does not match this counter")
    if output.value <= FEE:
        raise ValueError("parent output 0 cannot pay another counter fee")
    value, = evaluate(advance, current)
    return current, value, counter_output(code, value, output.value - FEE)


def replay_counter(output_path, root, code, advance, advance_script):
    from replay import Replay

    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError("use the pinned Chronicle-aware chain-gang build")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    if node.call("getblockcount", []) or node.call("getconnectioncount", []):
        raise ValueError("use a fresh peerless regtest")
    replay = Replay(node, 1, "chronicle-v2", int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"]))
    parent, deployment = replay.deploy(SimpleNamespace(root=root, version=VERSION), replay.fund(1), 0)
    steps = []
    for _ in range(2):
        previous = (UTXO(parent, 0),)
        _, value, successor = next_counter(parent, code, advance)
        tx = spend(parent, code, successor)
        wrong_counter = counter_output(code, (value + 1) % U32, successor.value)
        wrong_script = replace(successor, script=successor.script + asm("OP_NOP"))
        wrong_amount = replace(successor, value=successor.value - 1)
        controls = {
            "wrong_counter": spend(parent, code, wrong_counter),
            "changed_script": spend(parent, code, wrong_script),
            "wrong_amount": spend(parent, code, wrong_amount),
            "stale_preimage": replace(tx, outputs=(wrong_amount,)),
        }
        rejected = {name: replay.record(candidate, previous, expected=False) for name, candidate in controls.items()}
        steps.append({"counter": value, "satoshis": successor.value, "fee_satoshis": FEE,
                      "accepted": replay.record(tx, previous), "rejected": rejected})
        parent = tx

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps({"advance_hex": advance_script.hex(), "lock_bytes": len(root.script),
                                       "deployment": deployment, "steps": steps}, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("build", help="compile and print the counter-zero lock")
    spending = actions.add_parser("spend", help="build the next spend from a raw parent transaction")
    spending.add_argument("--parent", type=bytes.fromhex, required=True)
    replay = actions.add_parser("replay", help="fund, spend twice, and verify on regtest")
    replay.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    advance = SourceCompiler(SOURCE.read_text()).words["advance"]
    advance_script = compile_word(advance, "safe").script
    code = covenant(advance_script)
    if not 253 <= len(code) <= 32767 - (1 + STATE_BYTES + len(SEPARATOR)):
        parser.error("the covenant requires three-byte CompactSize lengths and a positive two-byte ScriptNum")
    root = counter_output(code, 0, ROOT_VALUE)
    if args.action == "build":
        result = {"counter": 0, "satoshis": root.value, "fee_satoshis": FEE, "advance_hex": advance_script.hex(),
                  "script_bytes": len(root.script), "script_hex": root.script.hex()}
    elif args.action == "spend":
        try:
            parent = Transaction.parse(args.parent)
            current, value, successor = next_counter(parent, code, advance)
        except ValueError as error:
            parser.error(str(error))
        tx = spend(parent, code, successor)
        result = {"from": current, "to": value, "satoshis": successor.value, "fee_satoshis": FEE,
                  "txid": tx.txid(), "transaction_hex": tx.serialize().hex()}
    else:
        replay_counter(args.output, root, code, advance, advance_script)
        return
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
