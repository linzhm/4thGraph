"""Compare complete P2PKH-R1 payment locks on one regtest node."""

import argparse
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tx_engine import Script, Tx

from compile_r1 import BASELINE_VERSION, SOURCE, VERSION, compile_source, previous_build
from fixed_templates import compiled_template, otda_pattern
from reconstruct import shared_kernel_program
from fourthgraph.replay.workflow import Replay, SOURCE as FUNDING_COIN
from fourthgraph.workflow.protocol import FLAG, UTXO
from fourthgraph.benchmark.validation import CONTEXT_PIN, Node, chain_metadata
from fourthgraph.bsv.otda_reconstruction import Reconstruction
from fourthgraph.bsv.script import push
from fourthgraph.bsv.transaction import Input, Output, Transaction
from signature import authorization, current_input_unlock
from test_payment import fixture_signature, signer
import test_payment_acceptance as acceptance

MODES = {"forkid-all": 0x41, "otda-all": 0x61, "otda-single": 0x63}


def template(source, *, mode, source_path=SOURCE):
    marker = bytes(range(20))
    reference = compiled_template(scheduled=True)
    if mode == "baseline":
        return reference, otda_pattern(scheduled=True)[1], {}
    compiler = (previous_build(marker, optimize=True) if mode == "previous-forth"
                else compile_source(source, marker, optimize=mode == "optimized", source_path=source_path))
    prefix, suffix = compiler.emit("r1-lock", b"").split(marker)
    raw = prefix + bytes(20) + suffix
    blocks = ("ADD_POINTS", "DOUBLE_POINT", "DIGITS_SPLIT4", "STEP_SPLIT4")
    injected = {name: compiler.emit("r1-" + name.lower().replace("_", "-"), b"") for name in blocks}
    program = shared_kernel_program(prefix, suffix, injected=injected)
    pattern = Reconstruction(program, (prefix, suffix), (20,))
    return replace(reference, script=raw, owner_start=len(prefix)), pattern, compiler.formulas


def scrypt_template(binary):
    # The optional comparison uses the pinned arithmetic fixture from PR #45.
    try:
        import compare_scrypt
    except ModuleNotFoundError as error:
        if error.name != "compare_scrypt":
            raise
        raise ValueError("the sCrypt benchmark checkout must include PR #45") from error
    from curve_compiler import curve_blocks

    digest = sha256(binary.read_bytes()).hexdigest()
    if digest != compare_scrypt.COMPILER_SHA256:
        raise ValueError("expected the pinned Linux x86-64 scryptc 1.20.0 compiler")
    reference = curve_blocks(scheduled=True)
    with TemporaryDirectory(prefix="r1-scrypt-") as work:
        candidate = reference | compare_scrypt.scrypt_kernels(binary.resolve(), Path(work))
    vectors = compare_scrypt.check_kernels(reference, candidate)
    lock, copies = compare_scrypt.compare_locks(reference, candidate)
    prefix, suffix = lock.script[:lock.owner_start], lock.script[lock.owner_end:]
    program = shared_kernel_program(prefix, suffix, injected=candidate)
    fixture = Path(compare_scrypt.__file__)
    metadata = {
        "compiler_sha256": digest,
        "fixture_sha256": sha256(fixture.read_bytes()).hexdigest(),
        "source_sha256": sha256((fixture.parent / "comparison/projective.scrypt").read_bytes()).hexdigest(),
        "kernel_vectors": vectors,
        "kernel_copies": copies,
    }
    return (lock, Reconstruction(program, (prefix, suffix), (20,))), metadata


def spend(deposit, locks, pattern, owners, mode):
    outputs = tuple(Output(365_000, raw) for raw in locks)
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


def replay_layout(replay, bootstrap, layout_index, lock, pattern):
    owners = (signer(7), signer(19))
    recipients = (signer(23), signer(29))
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
    return payments


def compare(source, *, matrix=False, scryptc=None, source_path=SOURCE):
    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError("use the pinned Chronicle-aware chain-gang")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    if node.call("getblockcount", []) or node.call("getconnectioncount", []):
        raise ValueError("use a fresh peerless regtest")
    layouts = {name: template(source, mode=name, source_path=source_path)
               for name in ("baseline", "previous-forth", "source", "optimized")}
    report = {"baseline_version": BASELINE_VERSION, "experiment_version": VERSION,
              "source_sha256": sha256(source).hexdigest(), "bsv_node_version": node.version, "chain_gang": engine,
              "regtest_profile": os.environ.get("SCRIPT_LAB_REGTEST_PROFILE")}
    if scryptc is not None:
        (lock, pattern), report["scrypt"] = scrypt_template(scryptc)
        layouts["scrypt"] = lock, pattern, {}
    replay = Replay(node, 7, "chronicle-v2", int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"]))
    bootstrap = replay.fund(len(layouts) * len(MODES))
    report["funding_parent_hex"] = bootstrap.serialize().hex()
    rows = {}
    for layout_index, (name, (lock, pattern, formulas)) in enumerate(layouts.items()):
        payments = replay_layout(replay, bootstrap, layout_index, lock, pattern)
        rows[name] = {"lock_bytes": len(lock.script), "lock_sha256": sha256(lock.script).hexdigest(),
                      "otda_program_bytes": len(pattern.program), "formulas": formulas, "payments": payments}
    if matrix:
        report["optimized_acceptance"] = matrix_check(layouts["optimized"][0])
    return {**report, "layouts": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--matrix", action="store_true")
    parser.add_argument("--scryptc", type=Path, help="include the pinned sCrypt arithmetic comparison from PR #45")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = compare(args.source.read_bytes(), matrix=args.matrix, scryptc=args.scryptc, source_path=args.source)
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
