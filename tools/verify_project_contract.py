"""Verify project contract ABI cases or replay the public spends in a receipt."""

import argparse
from dataclasses import replace
from hashlib import new, sha256
import json
import os
from pathlib import Path
import sys

from fourthgraph.benchmark.validation import (ACTIVATION_HEIGHT, CONTEXT_PIN, NODE_FLAGS, SPEND_HEIGHT, UTXO_HEIGHT,
                                              Node, chain_metadata, chain_verdict)
from fourthgraph.bsv.script import push
from fourthgraph.bsv.transaction import Input, Output, Transaction, hash256, preimage_forkid
from fourthgraph.workflow.project_contract import ContractError, ProjectContract, wire_tx

ROOT = Path(__file__).resolve().parents[1]
RECEIPT_SCHEMA = "4thgraph.project-receipt/1"
REPLAY_SCHEMA = "4thgraph.project-replay/1"
FIXTURE_FUNDING = Input(b"\x77" * 32, 0)
FIXTURE_AMOUNT = 100_000
FIXTURE_FEE = 1_000


def canonical(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def digest(value):
    return sha256(canonical(value)).hexdigest()


def diagnostic_value(value):
    encoded = canonical(value)
    if len(encoded) <= 140:
        return value
    return {"json_bytes": len(encoded), "sha256": sha256(encoded).hexdigest()}


class VerificationFailure(ValueError):
    def __init__(self, schema, status, detail, **context):
        super().__init__(detail)
        self.report = {"schema": schema, "status": "failed",
                       "diagnostic": {"status": status, "detail": detail, **context}}


def pinned_chain():
    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError(f"fixture requires chain-gang {CONTEXT_PIN}, got {engine}")
    return engine


def fixture_spec(manifest, host):
    package = host.package
    raw = (Path(manifest).resolve().parent / package["fixtures"]["file"]).read_bytes()
    if sha256(raw).hexdigest() != package["fixtures"]["sha256"]:
        raise ContractError("UnapprovedArtifact", "fixture bytes differ from local approval")
    cases = json.loads(raw)
    fixture = cases["fixture"]
    step_counts = {"r1-ordinary": 1, "counter-successors": 2}
    if (package["fixture"] != fixture or fixture not in step_counts
            or type(cases["steps"]) is not int or cases["steps"] != step_counts[fixture]):
        raise ValueError("unsupported fixture or unexpected step count")
    is_r1 = fixture == "r1-ordinary"
    path, = package["paths"]
    slot, = package["parameters"]
    if (path, slot["name"], slot["length"], package["paths"][path]["signatures"]) != (
        ("ordinary-all", "owner_hash160", 20, 1) if is_r1 else ("advance", "counter_u32_le", 5, 0)
    ):
        raise ValueError("unsupported fixture path or parameter layout")
    return cases, is_r1, path, slice(slot["offset"], slot["offset"] + slot["length"])


def initial_parent(template, slot, pubkey):
    lock = bytearray(template)
    if pubkey:
        lock[slot] = new("ripemd160", sha256(pubkey).digest()).digest()
    return Transaction((FIXTURE_FUNDING,), (Output(FIXTURE_AMOUNT, bytes(lock)),))


def fixture_candidate(parent, slot, is_r1, step):
    prior = parent.outputs[0]
    if is_r1:
        successor = b"\x51"
    else:
        # Evaluate the expected phase independently of WASM and the receipt.
        if int.from_bytes(prior.script[slot], "little") != step:
            raise ValueError("incorrect counter phase in actual parent")
        successor = prior.script[:slot.start] + (step + 1).to_bytes(slot.stop - slot.start, "little") + prior.script[slot.stop:]
    return Transaction((Input(parent.txid_wire(), 0),), (Output(prior.value - FIXTURE_FEE, successor),))


def check_engines(tx, parent, node):
    return {"chain_gang": chain_verdict(tx, [parent]),
            "bsv_node": "not_run" if node is None else node.verdicts(tx, [parent]) == [True]}


def spend_summary(parent, tx):
    return {"prevout": tx.inputs[0].outpoint().hex(), "previous_amount": parent.outputs[0].value,
            "txid": tx.txid(), "tx_bytes": len(tx.serialize()), "unlock_bytes": len(tx.inputs[0].script),
            "next_amount": tx.outputs[0].value}


def resolve(value, names):
    if isinstance(value, str) and value.startswith("$"):
        return names[value[1:]]
    if isinstance(value, dict):
        return {key:resolve(v,names) for key,v in value.items()}
    if isinstance(value, list):
        return [resolve(v,names) for v in value]
    return value


def patch(base, changes):
    if isinstance(changes,dict) and isinstance(base,dict):
        return {**base, **{k:patch(base.get(k),v) for k,v in changes.items()}}
    return changes


def test_keys(ephemeral):
    # Public, deterministic fixture keys. Never use them for a funded wallet.
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    key, other = ((ec.generate_private_key(ec.SECP256R1()) for _ in range(2)) if ephemeral else
                  (ec.derive_private_key(i,ec.SECP256R1()) for i in (7,19)))
    def public(k):
        return k.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
    def sign(message):
        sig = key.sign(message,ec.ECDSA(utils.Prehashed(hashes.SHA256()), deterministic_signing=True))
        return b"".join(x.to_bytes(32,"big") for x in utils.decode_dss_signature(sig))
    return public(key),public(other),sign


def case_failure(case, step, expected, actual, *, detail, engines):
    fields = expected.keys() | set(case.get("absent", [])) | {"status"}
    if expected["status"] not in {"Match", "Prepared", "Assembled", "Verified"}:
        fields |= {"prepared", "unlock"}
    observed = {key: diagnostic_value(actual[key]) for key in sorted(fields) if key in actual}
    wanted = {key: diagnostic_value(value) for key, value in expected.items()}
    return VerificationFailure(RECEIPT_SCHEMA, "fixture_failed", detail, case_id=case["id"],
                               step=step, entry=case["entry"], expected_status=expected["status"],
                               actual_status=actual.get("status"), expected=wanted, actual=observed,
                               expected_absent=case.get("absent", []), engines=engines)


def run_case(host, case, inputs, parent, candidate, signed, preimage, expected_unlock, changed, sign, verdicts, node):
    entry = case["entry"]

    def verify(actual):
        verdicts.update(check_engines(actual, parent, node))
        if node is not None and verdicts["chain_gang"] != verdicts["bsv_node"]:
            raise ValueError("independent engines disagree")
        return verdicts["chain_gang"]

    if entry == "host_spend":
        signer_calls = []

        def authorize(funding, tx, index, path, signing_digest):
            if (funding, tx, index, path, signing_digest) != (parent, candidate, 0, inputs["path"], hash256(preimage)):
                raise ValueError("unexpected signing request")
            signer_calls.append(signing_digest)
            return sign(signing_digest)

        try:
            completed = host.spend(parent, candidate, 0, inputs["path"], bytes.fromhex(inputs["pubkey"]), authorize, verify)
        except ContractError as exc:
            return {"status": exc.status, "signer_calls": len(signer_calls)}, signed
        if completed.inputs[0].script != expected_unlock:
            raise ValueError("actual witness differs from independent reference")
        return {"status": "Verified", "signer_calls": len(signer_calls)}, completed
    if entry == "verify_changed_output":
        if signed is None:
            raise ValueError("covered mutation requires the completed fixture spend")
        return {"status": "Verified" if verify(replace(signed, outputs=changed.outputs)) else "Rejected"}, signed
    return host.call(entry, inputs), signed


def verify_bundle(manifest, approval, node=None, *, ephemeral=False, include_io=False):
    engine = pinned_chain()
    host = ProjectContract(manifest, approval)
    package = host.package
    cases, is_r1, path, slot = fixture_spec(manifest, host)
    pub, other, sign = test_keys(ephemeral)
    parent = initial_parent(host.template, slot, pub if is_r1 else b"")
    rule = package["paths"][path]
    rows, steps = [], []
    for step in range(cases["steps"]):
        prior = parent.outputs[0]
        tx = fixture_candidate(parent, slot, is_r1, step)
        changed = replace(tx, outputs=(replace(tx.outputs[0], value=tx.outputs[0].value - 1),))
        request = host.request(parent,tx,0,path,pub if is_r1 else b"")
        pre = preimage_forkid(tx,0,prior.value,prior.script[rule["script_code_offset"]:],rule["mode"])
        prepared = {"candidate":sha256(tx.serialize()).hexdigest(), "input_index":0, "path":path,"mode":65,
                    "outpoint":tx.inputs[0].outpoint().hex(),"preimage":pre.hex(),"digest":hash256(pre).hex()}
        signatures = [sign(hash256(pre))] if is_r1 else []
        if is_r1:
            sys.path.insert(0,str(ROOT/"projects/p2pkh-r1/reference"))
            from signature import authorization, current_input_unlock
            from tx_engine import Tx
            auth = authorization(Tx.parse(tx.serialize()),0,prior.value,65)
            expected_unlock = current_input_unlock(auth,pub,signatures[0]).raw_serialize()
        else:
            expected_unlock = push(pre)
        names = {"prepared":prepared, "other_key":other.hex(),"changed_tx":wire_tx(changed),
                 "parameters":prior.script[slot].hex(),"expected_unlock":expected_unlock.hex()}
        signed = None
        for case in cases["cases"]:
            entry = case["entry"]
            inputs = dict(request)
            if entry == "assemble_unlock":
                inputs.update(prepared=prepared,authorizations=[s.hex() for s in signatures])
            inputs = patch(inputs, resolve(case.get("patch",{}),names))
            expected = resolve(case["expect"],names)
            verdicts = {}
            try:
                result, signed = run_case(host, case, inputs, parent, tx, signed, pre, expected_unlock,
                                          changed, sign, verdicts, node)
                if not isinstance(result, dict) or not isinstance(result.get("status"), str):
                    raise ValueError("case returned no result status")
            except (ValueError, KeyError, TypeError, OSError, RuntimeError, ImportError) as exc:
                actual = {"status": getattr(exc, "status", type(exc).__name__)}
                raise case_failure(case, step, expected, actual, detail=diagnostic_value(str(exc)), engines=verdicts) from exc
            passed = all(result.get(k)==v for k,v in expected.items()) and all(k not in result for k in case.get("absent", []))
            if expected["status"] not in {"Match","Prepared","Assembled","Verified"}:
                passed = passed and "prepared" not in result and "unlock" not in result
            if not passed:
                raise case_failure(case, step, expected, result, detail="case differs from fixture expectation", engines=verdicts)
            row = {"id":case["id"],"step":step,"entry":entry,"expected_status":expected["status"],
                   "actual_status":result["status"],"passed":passed, "input_sha256":digest(inputs),
                   "result_sha256":digest(result),"engines":verdicts}
            if include_io:
                row.update(input=inputs, expected=expected, actual=result)
            rows.append(row)
        if signed is None:
            raise ValueError("path did not produce a verified transaction")
        steps.append({**spend_summary(parent,signed), "raw_tx":signed.serialize().hex(),
                      "parent_tx":parent.serialize().hex()})
        parent = signed
    return {"schema":RECEIPT_SCHEMA,"profile":package["profile"],"template":package["template_version"],
            "path":path, "manifest_sha256":approval,"module_sha256":package["module"]["sha256"],
            "template_sha256":package["script"]["sha256"],"fixture_sha256":package["fixtures"]["sha256"],
            "fixture_key":("ephemeral" if ephemeral else "fixed-public-test-key") if is_r1 else "not_applicable",
            "public_key":pub.hex() if is_r1 else None,
            "verification_sources":{str(f.relative_to(ROOT)):sha256(f.read_bytes()).hexdigest() for f in
                                    (Path(__file__).resolve(), ROOT/"src/fourthgraph/workflow/project_contract.py",
                                     ROOT/"src/fourthgraph/workflow/contract_runtime.mjs", ROOT/"src/fourthgraph/benchmark/validation.py")},
            "node_version":node.version if node else None, "chain_gang":engine,"flags":NODE_FLAGS,"utxo_height":UTXO_HEIGHT,
            "spend_height":SPEND_HEIGHT,"activation_height":ACTIVATION_HEIGHT,"cases":rows,"steps":steps,"status":"passed"}


def receipt_hex(value, field, **context):
    if isinstance(value, str):
        try:
            raw = bytes.fromhex(value)
            if raw and raw.hex() == value:
                return raw
        except ValueError:
            pass
    raise VerificationFailure(REPLAY_SCHEMA, "invalid_receipt", "expected nonempty canonical hex", field=field, **context)


def receipt_tx(row, field, step):
    raw = receipt_hex(row.get(field), field, step=step)
    try:
        return Transaction.parse(raw)
    except ValueError as exc:
        raise VerificationFailure(REPLAY_SCHEMA, "invalid_transaction", str(exc), field=field, step=step) from exc


def require_fields(received, expected, status, **context):
    for field, wanted in expected.items():
        actual = received.get(field)
        if field not in received or type(actual) is not type(wanted) or actual != wanted:
            raise VerificationFailure(REPLAY_SCHEMA, status, "field differs from replay expectation", field=field,
                                      expected=diagnostic_value(wanted), actual=diagnostic_value(actual), **context)


def check_witness(script, prepared, pubkey, step):
    prefix = push(bytes.fromhex(prepared["preimage"]))
    if pubkey:
        # The ordinary path carries exactly the public key, raw signature, inverse and OP_0.
        prefix += push(pubkey)
        tail = script[len(prefix):]
        matched = script.startswith(prefix) and len(tail) == 99 and tail[0] == 64 and tail[65] == 32 and tail[-1] == 0
    else:
        matched = script == prefix
    if not matched:
        raise VerificationFailure(REPLAY_SCHEMA, "witness_mismatch", "actual witness does not bind the prepared candidate and path", step=step)


def replay_receipt(manifest, approval, receipt, node=None, *, public_key=None):
    """Validate actual fixture spends. Optional public_key is a locally selected R1 key (bytes).

    This replays the transaction steps only. Historical case results and engine claims
    do not contribute to acceptance. No key generation, signing or assembly is performed.
    """
    host = ProjectContract(manifest, approval)
    cases, is_r1, path, slot = fixture_spec(manifest, host)
    package = host.package
    bindings = {"schema": RECEIPT_SCHEMA, "manifest_sha256": approval, "profile": package["profile"],
                "template": package["template_version"], "path": path,
                "module_sha256": package["module"]["sha256"], "template_sha256": package["script"]["sha256"],
                "fixture_sha256": package["fixtures"]["sha256"]}
    if not isinstance(receipt, dict):
        raise VerificationFailure(REPLAY_SCHEMA, "invalid_receipt", "receipt must be an object")
    require_fields(receipt, bindings, "receipt_binding_mismatch")
    steps = receipt.get("steps")
    if not isinstance(steps, list) or len(steps) != cases["steps"]:
        raise VerificationFailure(REPLAY_SCHEMA, "step_count_mismatch", "receipt must contain every approved fixture step",
                                  expected=cases["steps"], actual=len(steps) if isinstance(steps, list) else None)
    pubkey = b""
    if is_r1:
        pubkey = receipt_hex(receipt.get("public_key"), "public_key")
        if len(pubkey) != 65 or pubkey[0] != 4:
            raise VerificationFailure(REPLAY_SCHEMA, "invalid_receipt", "R1 requires an uncompressed P-256 public key", field="public_key")
        if public_key is not None and pubkey != public_key:
            raise VerificationFailure(REPLAY_SCHEMA, "owner_mismatch", "receipt key differs from the locally selected public key")
    else:
        require_fields(receipt, {"public_key": None}, "receipt_binding_mismatch")
        if public_key is not None:
            raise VerificationFailure(REPLAY_SCHEMA, "unexpected_public_key", "approved fixture has no wallet owner key")

    engine = pinned_chain()
    previous = None
    observed = []
    for step, row in enumerate(steps):
        if not isinstance(row, dict):
            raise VerificationFailure(REPLAY_SCHEMA, "invalid_receipt", "step must be an object", step=step)
        parent = receipt_tx(row, "parent_tx", step)
        signed = receipt_tx(row, "raw_tx", step)
        if previous is not None and parent != previous:
            raise VerificationFailure(REPLAY_SCHEMA, "phase_mismatch", "parent must be the previous verified transaction", step=step)
        if len(parent.outputs) != 1 or not host.matches(parent.outputs[0].script):
            raise VerificationFailure(REPLAY_SCHEMA, "template_mismatch", "actual parent does not carry the approved lock template", step=step)
        if step == 0:
            expected_parent = initial_parent(host.template, slot, pubkey)
            if is_r1 and parent.outputs[0].script[slot] != expected_parent.outputs[0].script[slot]:
                raise VerificationFailure(REPLAY_SCHEMA, "owner_mismatch", "public key does not own the actual lock", step=step)
            if parent != expected_parent:
                raise VerificationFailure(REPLAY_SCHEMA, "funding_mismatch", "actual funding amount, framing or template parameters differ from the fixture", step=step)
        if len(signed.inputs) != 1 or len(signed.outputs) != 1:
            raise VerificationFailure(REPLAY_SCHEMA, "candidate_mismatch", "fixture requires one input and one output", step=step)
        candidate = signed.with_script(0, b"")
        if candidate != fixture_candidate(parent, slot, is_r1, step):
            raise VerificationFailure(REPLAY_SCHEMA, "candidate_mismatch", "outpoint, successor or unsigned bytes differ from the approved fixture", step=step)
        summary = spend_summary(parent, signed)
        require_fields(row, summary, "step_binding_mismatch", step=step)
        try:
            recognized = host.recognize(parent, 0, pubkey)
            if not isinstance(recognized, dict):
                raise ContractError("InvalidResult", "approved module returned no recognition result")
            if recognized.get("status") != "Match" or recognized.get("parameters") != parent.outputs[0].script[slot].hex():
                raise ContractError(recognized.get("status", "InvalidResult"), "approved module did not recognize the actual lock and parameters")
            prepared = host.prepare(parent, candidate, 0, path, pubkey)
        except (ContractError, KeyError, TypeError) as exc:
            raise VerificationFailure(REPLAY_SCHEMA, "contract_mismatch", diagnostic_value(str(exc)), step=step,
                                      actual_status=getattr(exc, "status", type(exc).__name__)) from exc
        check_witness(signed.inputs[0].script, prepared, pubkey, step)
        try:
            verdicts = check_engines(signed, parent, node)
        except (ValueError, OSError, RuntimeError, ImportError) as exc:
            raise VerificationFailure(REPLAY_SCHEMA, "engine_error", diagnostic_value(str(exc)), step=step) from exc
        if verdicts["chain_gang"] is not True or (node is not None and verdicts["bsv_node"] is not True):
            status = "engine_disagreement" if node is not None and verdicts["chain_gang"] != verdicts["bsv_node"] else "engine_rejected"
            raise VerificationFailure(REPLAY_SCHEMA, status, "independent verification rejected the actual signed spend",
                                      step=step, engines=verdicts)
        observed.append({**summary, "step": step, "input_index": prepared["input_index"],
                         "candidate_sha256": prepared["candidate"], "coverage": prepared["mode"], "engines": verdicts})
        previous = signed
    return {**bindings, "schema": REPLAY_SCHEMA, "receipt_schema": RECEIPT_SCHEMA, "status": "passed",
            "verification_level": "chain-only" if node is None else "dual-engine", "scope": "fixture_transactions",
            "receipt_payload_sha256": digest(receipt), "public_key": pubkey.hex() if pubkey else None, "steps": observed,
            "local_public_key_checked": public_key is not None,
            "node_version": node.version if node is not None else None, "chain_gang": engine,
            "flags": NODE_FLAGS, "utxo_height": UTXO_HEIGHT, "spend_height": SPEND_HEIGHT, "activation_height": ACTIVATION_HEIGHT}


def main(argv=None):
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("manifest", type=Path)
    cli.add_argument("--approved-sha256", required=True)
    cli.add_argument("--output", type=Path, required=True)
    cli.add_argument("--include-io", action="store_true")
    cli.add_argument("--smoke", action="store_true", help="chain-gang only; fresh in-memory P-256 key for the R1 fixture")
    cli.add_argument("--replay", metavar="RECEIPT", type=Path, help="validate signed spends without generating keys or calling a signer")
    cli.add_argument("--chain-only", action="store_true", help="in replay, run chain-gang without local BSV Node")
    cli.add_argument("--public-key", metavar="HEX", help="in R1 replay, require this locally selected public key")
    args = cli.parse_args(argv)
    if args.replay is None and (args.chain_only or args.public_key is not None):
        cli.error("--chain-only and --public-key require --replay")
    if args.replay is not None and (args.smoke or args.include_io):
        cli.error("--replay cannot be combined with --smoke or --include-io")
    if args.replay is not None and args.output.resolve() == args.replay.resolve():
        cli.error("replay output must be distinct from the source receipt")

    schema = REPLAY_SCHEMA if args.replay is not None else RECEIPT_SCHEMA
    try:
        node = None if args.smoke or args.chain_only else Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
        if args.replay is None:
            report = verify_bundle(args.manifest, args.approved_sha256, node, ephemeral=args.smoke, include_io=args.include_io)
        else:
            receipt = json.loads(args.replay.read_bytes())
            pubkey = receipt_hex(args.public_key, "public_key") if args.public_key is not None else None
            report = replay_receipt(args.manifest, args.approved_sha256, receipt, node, public_key=pubkey)
    except VerificationFailure as exc:
        report = exc.report
    except (ValueError, OSError, KeyError, TypeError, RuntimeError, ImportError) as exc:
        report = VerificationFailure(schema, getattr(exc, "status", type(exc).__name__), diagnostic_value(str(exc))).report

    if args.replay is not None:
        report.setdefault("verification_level", "chain-only" if args.chain_only else "dual-engine")
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if report["status"] == "failed":
        print(json.dumps(report, sort_keys=True), file=sys.stderr)
        return 1
    if args.replay is not None:
        print(json.dumps({"profile": report["profile"], "status": report["status"], "steps": len(report["steps"]),
                          "verification_level": report["verification_level"], "report_sha256": sha256(args.output.read_bytes()).hexdigest()}))
    else:
        print(json.dumps({"profile": report["profile"], "passed": len(report["cases"]), "steps": len(report["steps"]),
                          "receipt_sha256": sha256(args.output.read_bytes()).hexdigest()}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
