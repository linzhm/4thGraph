"""Replay complete baseline and optimized P2PKH-R1 payments on regtest."""

import argparse
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
from unittest.mock import patch

from tx_engine import Script, Tx

from compile_r1 import BASELINE_VERSION, SOURCE, VERSION, compile_source
from fixed_templates import compiled_template, otda_pattern
from reconstruct import shared_kernel_program
from replay import Replay, SOURCE as FUNDING_COIN
from protocol import FLAG, UTXO
from shared.benchmark_validation import CONTEXT_PIN, Node, chain_metadata
from shared.otda_reconstruction import Reconstruction
from shared.script import push
from shared.transaction import Input, Output, Transaction
from signature import authorization, current_input_unlock
from test_payment import fixture_signature, signer
import test_payment_acceptance as acceptance

MODES = {"forkid-all": 0x41, "otda-all": 0x61, "otda-single": 0x63}


def template(source, *, optimize):
    marker = bytes(range(20))
    compiler = compile_source(source, marker, optimize=optimize)
    prefix, suffix = compiler.emit("r1-lock").split(marker)
    reference = compiled_template(scheduled=True)
    raw = prefix + bytes(20) + suffix
    if not optimize and raw != reference.script:
        raise ValueError("the Forth baseline differs from the checked-in v0.2.0 lock")
    blocks = ("ADD_POINTS", "DOUBLE_POINT", "DIGITS_SPLIT4", "STEP_SPLIT4")
    injected = {name: compiler.emit("r1-" + name.lower().replace("_", "-")) for name in blocks}
    program = shared_kernel_program(prefix, suffix, injected=injected)
    pattern = Reconstruction(program, (prefix, suffix), (20,))
    if not optimize and pattern != otda_pattern(scheduled=True)[1]:
        raise ValueError("the Forth baseline differs from the checked-in OTDA reconstruction")
    return replace(reference, script=raw, owner_start=len(prefix)), pattern


def spend(deposit, locks, pattern, owners, mode):
    outputs = tuple(Output(400_000, raw) for raw in locks)
    unsigned = Transaction(tuple(Input(deposit.txid_wire(), index) for index in range(2)), outputs, version=2)
    engine_tx = Tx.parse(unsigned.serialize())
    tx = unsigned
    for index, (key, public, _) in enumerate(owners):
        auth = authorization(engine_tx, index, deposit.outputs[index].value, mode)
        signature = fixture_signature(key, auth.digest())
        witness = current_input_unlock(auth, public, signature).raw_serialize()
        if mode & 0x20:
            selected = outputs if mode == 0x61 else (outputs[index],)
            packed = pattern.build(auth.preimage, selected)
            literal = push(auth.preimage)
            if packed is None or len(packed) >= len(literal) or not witness.startswith(literal):
                raise ValueError("the OTDA fixture should use the smaller reconstruction witness")
            witness = packed + witness[len(literal):]
        tx = tx.with_script(index, witness)
    return tx


def matrix_check(candidate):
    def lock(owner, *, compiled_curve=False):
        out = Script()
        out.append_data(candidate.lock(owner))
        return out

    suite = acceptance.PaymentAcceptanceTests()
    with patch.object(acceptance, "locking_script", lock):
        suite.check_complete_input_acceptance_domain(compiled_curve=None)
        suite.check_nonconforming_witnesses(compiled_curve=None)
    return {"node_payment_cases": 1296, "chain_gang_payment_cases": 432,
            "valid_witness_controls": 4, "invalid_witness_controls": 24}


def compare(source, *, matrix=False):
    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError("use the pinned Chronicle-aware chain-gang")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    if node.call("getblockcount", []) or node.call("getconnectioncount", []):
        raise ValueError("use a fresh peerless regtest")
    layouts = {name: template(source, optimize=optimized)
               for name, optimized in (("baseline", False), ("optimized", True))}
    report = {"baseline_version": BASELINE_VERSION, "experiment_version": VERSION,
              "source_sha256": sha256(source).hexdigest(), "bsv_node_version": node.version, "chain_gang": engine}
    replay = Replay(node, 7, "chronicle-v2", int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"]))
    bootstrap = replay.fund(len(layouts) * len(MODES))
    report["funding_parent_hex"] = bootstrap.serialize().hex()
    owners = (signer(7), signer(19))
    recipients = (signer(23), signer(29))
    rows = {}
    for layout_index, (name, (lock, pattern)) in enumerate(layouts.items()):
        payments = {}
        for mode_index, (label, mode) in enumerate(MODES.items()):
            slot = layout_index * len(MODES) + mode_index
            root = UTXO(bootstrap, slot)
            # Keep both large 2-output transactions above the regtest mining fee floor.
            deposit = Transaction((Input(root.outpoint.txid, root.outpoint.vout),),
                                  tuple(Output(450_000, lock.lock(owner)) for _, _, owner in owners), version=2)
            deposit = FUNDING_COIN.unlock(deposit, 0, bootstrap, FLAG, None)
            funding = replay.record(deposit, (root,))
            payment = spend(deposit, [lock.lock(owner) for _, _, owner in recipients], pattern, owners, mode)
            inputs = tuple(UTXO(deposit, i) for i in range(2))
            rejected = replay.record(replace(payment, locktime=1), inputs, expected=False)
            spent = replay.record(payment, inputs)
            payments[label] = {"deployment": funding, "spend": spent, "changed_locktime": rejected,
                               "unlock_bytes": [len(txin.script) for txin in payment.inputs],
                               "total_bytes": funding["bytes"] + spent["bytes"]}
        rows[name] = {"lock_bytes": len(lock.script), "lock_sha256": sha256(lock.script).hexdigest(),
                      "otda_program_bytes": len(pattern.program), "payments": payments}
    if matrix:
        report["optimized_acceptance"] = matrix_check(layouts["optimized"][0])
    return {**report, "layouts": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--matrix", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = compare(args.source.read_bytes(), matrix=args.matrix)
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
