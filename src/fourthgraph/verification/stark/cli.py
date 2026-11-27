"""Build a fixed-statement STARK lock and replay its accepted and rejected witnesses."""

import argparse
from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import os
from pathlib import Path

from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.bsv.script import number, push
from fourthgraph.compiler.script_builder import ScriptBuilder
from fourthgraph.compiler.source import PROJECT_VERSION

from .proof import DIGEST, LOG_BLOWUP, LOG_LDE, LOG_TRACE, QUERIES, witness_packet
from .script import DEFAULT_PLAN, PLANS, Script


def digest(raw):
    return sha256(raw).hexdigest()


def write_json(path, document):
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


@dataclass(frozen=True)
class Build:
    forth: str
    lock: bytes
    unlock: bytes
    report: dict


def build_artifacts(profile, source, public, proof, *, plan=DEFAULT_PLAN):
    forth = Script(profile, source, plan=plan).generate(public)
    builder = ScriptBuilder(forth, source_path=source)
    lock = builder.emit("stark-lock")
    unlock = push(witness_packet(profile, public, proof))
    report = {
        "profile": profile.name,
        "field_modulus": str(profile.modulus),
        "extension_degree": profile.dimension,
        "trace_rows": 1 << LOG_TRACE,
        "log_blowup": LOG_BLOWUP,
        "queries": QUERIES,
        "script_era": "genesis",
        "compiler_version": PROJECT_VERSION,
        "compiler_plan": plan,
        "forth_sha256": digest(forth.encode("utf-8")),
        "forth_template_sha256": digest(source.read_bytes()),
        "libraries": [asdict(library) for library in builder.library_imports],
        "public": list(map(str, public)),
        "proof_bytes": len(proof),
        "proof_sha256": digest(proof),
        "lock_bytes": len(lock),
        "lock_sha256": digest(lock),
        "unlock_bytes": len(unlock),
        "unlock_sha256": digest(unlock),
    }
    return Build(forth, lock, unlock, report)


def artifacts(profile, source, public, proof, *, plan=DEFAULT_PLAN):
    build = build_artifacts(profile, source, public, proof, plan=plan)
    return build.lock, build.unlock, build.report


def fixture(project):
    versions = project / "versions"
    current = json.loads((versions / "index.json").read_text(encoding="utf-8"))["current"]
    release = versions / f"v{current}"
    manifest = json.loads((release / "manifest.json").read_text(encoding="utf-8"))
    statements_path = release / "statements.json"
    if "statements.json" not in manifest["fixtures"]:
        statements_path, = (project / path for path in manifest["shared_data"]
                            if Path(path).name == "statements.json")
    statements = json.loads(statements_path.read_text(encoding="utf-8"))
    return {name: (tuple(map(int, public)), (statements_path.parent / f"{name}.proof").read_bytes())
            for name, public in statements.items()}


def flip(packet, offset):
    return packet[:offset] + bytes([packet[offset] ^ 1]) + packet[offset + 1:]


def controls(profile, cases):
    public, proof = cases["valid"]
    wrapped, wrap_proof = cases["wrap"]
    other_public, other_proof = cases["wrong-air"]
    if other_public != public:
        raise ValueError("the shifted AIR control must have the same public inputs")
    packet = witness_packet(profile, public, proof)
    first_query = profile.header_size
    trace_row = first_query + profile.extension_width
    trace_path = trace_row + 2 * profile.width
    quotient_path = trace_path + LOG_LDE * DIGEST + profile.extension_width
    fri_path = quotient_path + LOG_LDE * DIGEST + profile.extension_width
    first_opening = (2 + LOG_TRACE) * DIGEST
    noncanonical = profile.modulus.to_bytes(profile.width, "little")
    return {
        "wrong_statement": push(witness_packet(profile, wrapped, wrap_proof)),
        "wrong_air_same_statement": push(witness_packet(profile, public, other_proof)),
        "trace_merkle_path": push(flip(packet, trace_path)),
        "quotient_merkle_path": push(flip(packet, quotient_path)),
        "fri_merkle_path": push(flip(packet, fri_path)),
        "last_query_merkle_path": push(flip(packet, len(packet) - 1)),
        "fri_final_coefficient": push(flip(packet, first_query - profile.extension_width)),
        "reciprocal": push(flip(packet, first_query)),
        "noncanonical_opening": push(packet[:first_opening] + noncanonical
                                     + packet[first_opening + profile.width:]),
        "truncated_packet": push(packet[:-1]),
        "trailing_packet_data": push(packet + b"\x00"),
        "extra_stack_item": number(1) + push(packet),
    }


def script_verdict(lock, unlock, *, observe=None):
    try:
        stack, alt = evaluate(unlock, observe_stack=observe)
        if alt:
            return False
        stack, alt = evaluate(lock, stack, observe_stack=observe)
        return stack == [b"\x01"] and not alt
    except ScriptError:
        return False


def check(profile, source, cases, lock, unlock, rejected, *, plan=DEFAULT_PLAN):
    peaks = {"main_items": 0, "alt_items": 0, "combined_payload_bytes": 0}

    def observe(main, alt):
        peaks["main_items"] = max(peaks["main_items"], len(main))
        peaks["alt_items"] = max(peaks["alt_items"], len(alt))
        peaks["combined_payload_bytes"] = max(peaks["combined_payload_bytes"],
                                              sum(map(len, main)) + sum(map(len, alt)))

    public, proof = cases["wrap"]
    wrapped_lock, wrapped_unlock, _ = artifacts(profile, source, public, proof, plan=plan)
    verified = {
        "valid": script_verdict(lock, unlock, observe=observe),
        "wrapping_statement": script_verdict(wrapped_lock, wrapped_unlock),
        **{name: script_verdict(lock, witness) for name, witness in rejected.items()},
    }
    expected = {"valid": True, "wrapping_statement": True, **dict.fromkeys(rejected, False)}
    if verified != expected:
        failed = [name for name, verdict in verified.items() if verdict != expected[name]]
        raise ValueError(f"unexpected Script verdict for {', '.join(failed)}")
    return {"verdicts": verified, "valid_stack_peaks": peaks}


def compare(profile, source, cases):
    public, proof = cases["valid"]
    rejected = controls(profile, cases)
    reports = []
    for plan in PLANS:
        build = build_artifacts(profile, source, public, proof, plan=plan)
        build.report["script_checks"] = check(profile, source, cases, build.lock, build.unlock, rejected, plan=plan)
        reports.append(build.report)
    selected = min(reports, key=lambda report: report["lock_bytes"] + report["unlock_bytes"])
    return {"objective": "lock_plus_unlock_bytes", "selected": selected["compiler_plan"], "candidates": reports}


def replay(lock, unlock, rejected):
    from fourthgraph.benchmark.admission import submit_and_mine
    from fourthgraph.benchmark.validation import CONTEXT_PIN, Node, chain_metadata
    from fourthgraph.bsv.transaction import Input, Output, Transaction
    from fourthgraph.replay.groth16_bn254 import LOCK_VALUE, SPEND_FEE, fund, verify_spend
    from fourthgraph.workflow.protocol import FLAG

    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError(f"use the pinned chain-gang build {CONTEXT_PIN}")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    if node.call("getblockcount", []) or node.call("getconnectioncount", []):
        raise ValueError("the replay requires a fresh peerless regtest")
    activation = int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"])
    version = 2
    native, funding = fund(node, version)
    deployment = Transaction((Input(funding.txid_wire(), 0),), (Output(LOCK_VALUE, lock),), version=version)
    deployment = native.unlock(deployment, 0, funding, FLAG, None)
    deployed = submit_and_mine(node, deployment)
    if not deployed["mined"]:
        raise ValueError(f"could not deploy verifier: {deployed}")
    draft = Transaction((Input(deployment.txid_wire(), 0),),
                        (Output(LOCK_VALUE - SPEND_FEE, native.output.script),), version=version)

    results = {}
    for name, witness in {**rejected, "valid": unlock}.items():
        spend = draft.with_script(0, witness)
        result = verify_spend(node, activation, spend, deployment, deployed["height"],
                              expected=name == "valid", timeout_us=500_000)
        del result["raw"]
        results[name] = result
    return {
        "node_version": node.version,
        "chain_gang": engine,
        "chronicle_activation_height": activation,
        "regtest_policy": os.environ["SCRIPT_LAB_REGTEST_PROFILE"],
        "transaction_version": version,
        "deployment": deployed,
        "spends": results,
    }


def main(profile, project):
    cli = argparse.ArgumentParser(description=__doc__)
    commands = cli.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="emit the lock and the encoded witness")
    verify = commands.add_parser("verify", help="verify an exported proof with the local Script evaluator")
    generate = commands.add_parser("generate", help="generate a complete Forth verifier for a public statement")
    for parser in (build, verify, generate):
        parser.add_argument("--public", nargs=3, type=int, metavar=("SEED_A", "SEED_B", "RESULT"),
                            required=parser is verify)
    for parser in (build, verify):
        parser.add_argument("--proof", type=Path, help="raw proof exported by the pinned native prover",
                            required=parser is verify)
    check_cli = commands.add_parser("check", help="run the checked-in Script fixtures")
    replay_cli = commands.add_parser("replay", help="fund and spend the fixture on regtest")
    compare_cli = commands.add_parser("compare", help="build and check each lowering plan")
    for parser in (build, verify, generate, check_cli, replay_cli):
        parser.add_argument("--plan", choices=PLANS, default=DEFAULT_PLAN)
    for parser in (build, verify, generate, check_cli, replay_cli, compare_cli):
        parser.add_argument("--output", type=Path, default=project / "workspace" / "build")
    args = cli.parse_args()
    source = project / "verifier.fth"
    try:
        if args.command == "compare":
            report = compare(profile, source, fixture(project))
            args.output.mkdir(parents=True, exist_ok=True)
            write_json(args.output / "compare.json", report)
            print(f"{profile.name}: selected {report['selected']}. {args.output}")
            return
        if args.command == "generate":
            public = args.public if args.public is not None else fixture(project)["valid"][0]
            forth = Script(profile, source, plan=args.plan).generate(public)
            args.output.mkdir(parents=True, exist_ok=True)
            output = args.output / "verifier.fth"
            output.write_text(forth, encoding="utf-8")
            print(output)
            return
        proof_path = getattr(args, "proof", None)
        if args.command == "build" and (args.public is None) != (proof_path is None):
            cli.error("provide --public and --proof together")
        if proof_path is not None:
            public, proof = tuple(args.public), proof_path.read_bytes()
        else:
            cases = fixture(project)
            public, proof = cases["valid"]
        result = build_artifacts(profile, source, public, proof, plan=args.plan)
        lock, unlock, report = result.lock, result.unlock, result.report
        if args.command == "verify":
            if not script_verdict(lock, unlock):
                raise ValueError("proof rejected for the supplied public statement")
            report["script_verified"] = True
        if args.command in {"check", "replay"}:
            rejected = controls(profile, cases)
            report["script_checks"] = check(profile, source, cases, lock, unlock, rejected, plan=args.plan)
        if args.command == "replay":
            report["regtest"] = replay(lock, unlock, rejected)
    except (KeyError, OSError, ValueError) as error:
        cli.error(str(error))
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "verifier.fth").write_text(result.forth, encoding="utf-8")
    (args.output / "lock.bin").write_bytes(lock)
    (args.output / "unlock.bin").write_bytes(unlock)
    write_json(args.output / f"{args.command}.json", report)
    print(f"{profile.name}: {len(lock):,} lock bytes, {len(unlock):,} unlock bytes. {args.output}")
