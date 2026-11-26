"""Plan a transaction-bound verifier for one public Forth state relation."""

import argparse
from dataclasses import dataclass, replace
from hashlib import sha256
import json
import os
from pathlib import Path
from shutil import copyfile
from zipimport import zipimporter
from tempfile import TemporaryDirectory, mkdtemp

from fourthgraph.verification.circuit_backend import emit_circuit, select_circuit
from fourthgraph.verification.circuit_tools import CircuitBuild, CircuitFixture, SNARKJS_PACKAGE
from fourthgraph.compiler.source import MAX_EXPANSION, PROJECT_NAME, PROJECT_VERSION, CompileError, SourceCompiler, bounded_expansion, evaluate
from fourthgraph.compiler.lowering import compile_word
from fourthgraph.verification.proof_contract import ProofContract, StateContract
from fourthgraph.workflow.protocol import (
    DEFAULT_TARGET, ROOT_VALUE, TARGETS, UTXO, begin, build_artifact, copy_preimage, field, finish, single_input,
)
from fourthgraph.bsv.script import asm, number, push
from fourthgraph.bsv.transaction import Output, compact

POLICIES = ("allow-direct", "require-proof", "require-groth16")
OBJECTIVES = ("path-bytes", "lock-bytes")
SPEND_FEE = 100_000
BLS_SOURCE = b"REQUIRE groth16-bls12-381/verifier.fth\n"
BLS_LAYOUTS = ("projective", "affine-inline", "affine-witness")


class DirectContract(StateContract):
    def __init__(self, program, current, keys, *, target, terminal_value, max_expansion):
        self.circuit = program
        super().__init__(program.route, current, keys, target=target, terminal_value=terminal_value)
        advance = compile_word(self.circuit.transition, "stack", max_expansion=max_expansion).script
        route = compile_word(self.route, "stack", max_expansion=max_expansion).script
        lock = (begin(self.versions) + single_input() + number(current) + advance + asm("OP_DUP") + route
                + self.check_successor() + finish())
        self.root = Output(ROOT_VALUE, lock)

    def seal(self, tx):
        return tx.with_script(0, push(self.binding_preimage(tx)))


class Groth16Contract(StateContract):
    def __init__(self, program, current, keys, verifier, sources, artifact, *, target, terminal_value):
        self.circuit = program
        super().__init__(program.route, current, keys, target=target, terminal_value=terminal_value)
        self.verifier, self.sources, self.verifier_artifact = verifier, sources, artifact
        predicate = bytes.fromhex(artifact["script_hex"])
        # Shared verifier packet: next (4), route (1), preimage hash (32).
        binding = (asm("OP_DUP") + field(5, 32) + copy_preimage() + asm("OP_HASH256 OP_EQUALVERIFY"))
        successor = (asm("OP_DUP") + field(0, 4) + push(b"\0") + asm("OP_CAT OP_BIN2NUM OP_OVER")
                     + field(4, 1) + asm("OP_BIN2NUM") + self.check_successor())
        lock = (begin(self.versions) + single_input() + binding + successor
                + predicate + asm("OP_VERIFY") + finish())
        self.root = Output(ROOT_VALUE, lock)

    def seal(self, tx, proof):
        next_state, = evaluate(self.circuit.transition, self.current)
        route, = evaluate(self.route, next_state)
        signals = (next_state, route, self.current, *self.public_binding(tx))
        packet = self.verifier.witness(signals, proof, sources=self.sources)
        return tx.with_script(0, packet + push(self.binding_preimage(tx)))


class Groth16Setup(CircuitBuild):
    def __init__(self, source, directory, zkey, ptau):
        super().__init__(source, directory, has_route=True, prime="bls12381")
        self.zkey = self.directory / "setup.zkey"
        copyfile(zkey, self.zkey)
        try:
            self.run(SNARKJS_PACKAGE, "snarkjs", "zkey", "verify", "counter.r1cs", str(Path(ptau).resolve()), str(self.zkey))
        except ValueError as error:
            raise ValueError("external Groth16 setup did not verify against the generated BLS12-381 R1CS") from error
        self.run(SNARKJS_PACKAGE, "snarkjs", "zkey", "export", "verificationkey", str(self.zkey), "vk.json")
        self.key = (self.directory / "vk.json").read_bytes()

    def prove(self, contract, tx):
        lo, hi = contract.public_binding(tx)
        current = contract.current
        next_state, = evaluate(contract.circuit.transition, current)
        route, = evaluate(contract.route, next_state)
        inputs = {"current": str(current), "bindLo": str(lo), "bindHi": str(hi)}
        with TemporaryDirectory(prefix="witness-", dir=self.directory) as temporary:
            folder = Path(temporary)
            (folder / "input.json").write_text(json.dumps(inputs))
            self.run(SNARKJS_PACKAGE, "snarkjs", "groth16", "fullprove", "input.json",
                     str(self.directory / "counter_js/counter.wasm"), str(self.zkey), "proof.json", "public.json",
                     cwd=folder)
            self.run(SNARKJS_PACKAGE, "snarkjs", "groth16", "verify", str(self.directory / "vk.json"), "public.json",
                     "proof.json", cwd=folder)
            values = json.loads((folder / "public.json").read_bytes())
            if values != list(map(str, (next_state, route, current, lo, hi))):
                raise ValueError("Groth16 prover returned different public signals")
            return (folder / "proof.json").read_bytes()

    def describe(self):
        return {**super().describe(), "verification_key_sha256": sha256(self.key).hexdigest(),
                "zkey_sha256": sha256(self.zkey.read_bytes()).hexdigest(), "setup_matches_generated_r1cs": True}


@dataclass(frozen=True)
class Candidate:
    contract: StateContract
    witness_bytes: int
    circuit_build: CircuitBuild | None = None

    def cost(self):
        lock = len(self.contract.root.script)
        witness = self.witness_bytes
        return {"lock_bytes": lock, "witness_bytes_upper_bound": witness,
                "script_field_path_bytes_upper_bound": lock + len(compact(lock)) + witness + len(compact(witness))}

    def seal(self, tx):
        if isinstance(self.contract, Groth16Contract):
            return self.contract.seal(tx, self.circuit_build.prove(self.contract, tx))
        if isinstance(self.contract, ProofContract):
            proof = self.circuit_build.prove(current=self.contract.current, binding=self.contract.public_binding(tx))
            return self.contract.seal(tx, proof)
        return self.contract.seal(tx)

    def describe(self):
        row = {"eligible": True, "cost": self.cost(), "lock_sha256": sha256(self.contract.root.script).hexdigest()}
        if self.circuit_build:
            row["circuit_build"] = self.circuit_build.describe()
        if isinstance(self.contract, Groth16Contract):
            artifact = self.contract.verifier_artifact
            row["verifier_artifact_sha256"] = artifact["artifact_sha256"]
        return row


def compile_solutions(source, keys, current, scratch, *, target=DEFAULT_TARGET, policy="allow-direct",
                      objective="path-bytes", r1cs=False, groth16=None, spend_fee=SPEND_FEE,
                      max_lock_bytes=None, max_expansion=MAX_EXPANSION, source_path=None):
    frontend = source if isinstance(source, SourceCompiler) else SourceCompiler(source.decode(), source_path=source_path)
    if policy not in POLICIES or objective not in OBJECTIVES:
        raise ValueError("unknown verification policy or objective")
    if type(spend_fee) is not int or not 0 < spend_fee < ROOT_VALUE:
        raise ValueError(f"spend fee must be from 1 to {ROOT_VALUE - 1} satoshis")
    if type(max_expansion) is not int or max_expansion <= 0:
        raise ValueError("max expanded operations must be positive")
    if max_lock_bytes is not None and (type(max_lock_bytes) is not int or max_lock_bytes <= 0):
        raise ValueError("max lock bytes must be positive")
    if not frontend.relation:
        raise CompileError("expected relation: TRANSITION ROUTE ; with REQUIRE stdlib/verify.fth")
    source = frontend.source.encode()
    program = select_circuit(frontend)
    expansion = bounded_expansion(program.transition.body, program.route.body, limit=max_expansion)
    if expansion > max_expansion:
        raise frontend.relation[0].error(
            f"verification relation exceeds the {max_expansion}-operation expansion budget before lowering",
        )
    scratch = Path(scratch)
    candidates, rejected = {}, {
        "groth16-bn254": "the fixed-statement adapter requires owner authorization and lacks this spend binding",
    }
    base_witness = len(push(bytes(158)))
    parameters = {"target": target, "terminal_value": ROOT_VALUE - spend_fee}
    try:
        direct = DirectContract(program, current, keys, max_expansion=max_expansion, **parameters)
        script_build = {"status": "built", "script_hex": direct.root.script.hex(),
                        "script_bytes": len(direct.root.script)}
        if policy == "allow-direct":
            candidates["script"] = Candidate(direct, base_witness)
        else:
            rejected["script"] = "the policy requires a proof"
    except CompileError as error:
        script_build = {"status": "unsupported", "reason": str(error)}
        rejected["script"] = str(error)
    try:
        circom = emit_circuit(program, max_expansion=max_expansion)
        circuit_error = None
    except CompileError as error:
        circom, circuit_error = None, str(error)

    if policy == "require-groth16":
        rejected["r1cs"] = "the policy requires Groth16"
    elif circuit_error or (not r1cs and policy != "require-proof"):
        rejected["r1cs"] = circuit_error or "R1CS proving was not enabled"
    else:
        try:
            directory = mkdtemp(prefix="r1cs-", dir=scratch)
            circuit = CircuitFixture(circom, directory, has_route=True)
            contract = ProofContract(program, circuit, current, keys, optimization="stack",
                                     max_expansion=max_expansion, **parameters)
            candidates["r1cs"] = Candidate(contract, base_witness + 33 * (circuit.key.signals - 1), circuit)
        except (OSError, ValueError) as error:
            rejected["r1cs"] = str(error)

    if groth16 and not circuit_error:
        try:
            from fourthgraph.verification.bls12381.verifier import Dynamic
            from fourthgraph.verification.bls12381.build import layout_candidates

            directory = mkdtemp(prefix="bls12381-", dir=scratch)
            setup = Groth16Setup(circom, directory, *groth16)
            sources = (Dynamic(32), Dynamic(1), current, Dynamic(128), Dynamic(128))
            for item in layout_candidates(setup.key, BLS_SOURCE, sources):
                contract = Groth16Contract(program, current, keys, item.verifier, sources, item.artifact, **parameters)
                name = "groth16-bls12-381/" + item.verifier.witness_layout
                candidates[name] = Candidate(contract, base_witness + item.cost["witness_bytes"], setup)
        except (ImportError, OSError, ValueError) as error:
            for layout in BLS_LAYOUTS:
                rejected["groth16-bls12-381/" + layout] = str(error)
    else:
        for layout in BLS_LAYOUTS:
            rejected["groth16-bls12-381/" + layout] = circuit_error or "no matching external setup was supplied"

    oversized = {}
    if max_lock_bytes is not None:
        for name, candidate in tuple(candidates.items()):
            if candidate.cost()["lock_bytes"] > max_lock_bytes:
                oversized[name] = {**candidate.describe(), "eligible": False,
                                   "reason": f"lock exceeds the {max_lock_bytes}-byte budget"}
                del candidates[name]
    if not candidates:
        reasons = {**rejected, **{name: row["reason"] for name, row in oversized.items()}}
        raise CompileError("no verification path is eligible (" + "; ".join(f"{k}: {v}" for k, v in reasons.items()) + ")")
    metric = "lock_bytes" if objective == "lock-bytes" else "script_field_path_bytes_upper_bound"
    selected = min(candidates, key=lambda name: (candidates[name].cost()[metric], name))
    chosen = candidates[selected].contract
    report = {
        "project": PROJECT_NAME, "compiler_version": PROJECT_VERSION, "schema_version": 1,
        "statement": program.describe(), "target": target, "current": current, "policy": policy,
        "objective": objective, "selected": selected, "spend_fee_satoshis": spend_fee,
        "limits": {"lock_bytes": max_lock_bytes, "expanded_operations": max_expansion},
        "expanded_operations": expansion,
        "compilations": {
            "script": script_build,
            "circuit": ({"status": "built", "format": "circom", "source": circom.decode(),
                         "sha256": sha256(circom).hexdigest()} if circom is not None
                        else {"status": "unsupported", "reason": circuit_error}),
        },
        "candidates": {**{name: {"eligible": False, "reason": reason} for name, reason in rejected.items()},
                       **oversized, **{name: case.describe() for name, case in candidates.items()}},
        "binding": "ForkID ALL; committed current state; exact terminal and state receipt outputs",
        "deploy_output": {"satoshis": chosen.root.value, "script_hex": chosen.root.script.hex()},
    }
    return candidates[selected], build_artifact(report, source)


def funded_replay(candidate, target):
    from fourthgraph.replay.workflow import Replay
    from fourthgraph.benchmark.cases import native_coin
    from fourthgraph.benchmark.validation import CONTEXT_PIN, Node, chain_metadata

    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError("verification replay requires the pinned chain-gang build")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    if node.call("getblockcount", []) or node.call("getconnectioncount", []):
        raise ValueError("verification replay requires a fresh peerless regtest")
    replay = Replay(node, 3, target, int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"]))
    contract = candidate.contract
    next_state, = evaluate(contract.circuit.transition, contract.current)
    route, = evaluate(contract.route, next_state)
    # Use one funding input for every path, with enough fee for a large verifier lock.
    coin = native_coin("forth/verification/funding", ROOT_VALUE + 1_000_000, p2pk=True)
    bootstrap = replay.fund(2, coin=coin)
    parent, deploy = replay.deploy(contract, bootstrap, 0, coin=coin)
    foreign, other_deploy = replay.deploy(contract, bootstrap, 1, coin=coin)
    tx = contract.unsigned(parent, next_state, version=contract.versions[0])
    previous = (UTXO(parent, 0),)
    signed = candidate.seal(tx)
    wrong = replace(tx, outputs=(contract.terminals[1 - route], tx.outputs[1]))
    other_previous = (UTXO(foreign, 0),)
    other_unsigned = contract.unsigned(foreign, next_state, version=tx.version)
    swapped = other_unsigned.with_script(0, signed.inputs[0].script)
    rejected = {
        "wrong_terminal_with_recomputed_witness": replay.record(candidate.seal(wrong), previous, expected=False),
        "witness_from_another_outpoint": replay.record(swapped, other_previous, expected=False),
    }
    if candidate.circuit_build:
        old_preimage = push(contract.binding_preimage(tx))
        new_preimage = push(contract.binding_preimage(other_unsigned))
        stale_proof = signed.inputs[0].script[:-len(old_preimage)] + new_preimage
        rejected["proof_from_another_outpoint_with_correct_preimage"] = replay.record(
            other_unsigned.with_script(0, stale_proof), other_previous, expected=False,
        )
    accepted = replay.record(signed, previous)
    other = replay.record(candidate.seal(contract.unsigned(foreign, next_state)), other_previous)
    return {"bsv_node": node.version, "chain_gang": engine, "next": next_state, "route": route,
            "deployment": deploy, "spend": accepted, "foreign_deployment": other_deploy, "foreign_spend": other,
            "deployment_plus_spend_bytes": deploy["bytes"] + accepted["bytes"], "rejections": rejected}


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("source", type=Path)
    cli.add_argument("--current", type=int, required=True)
    cli.add_argument("--keys", type=Path, required=True)
    cli.add_argument("--target", choices=TARGETS, default=DEFAULT_TARGET)
    cli.add_argument("--policy", choices=POLICIES, default=POLICIES[0])
    cli.add_argument("--objective", choices=OBJECTIVES, default=OBJECTIVES[0])
    cli.add_argument("--spend-fee", type=int, default=SPEND_FEE, help="same spend fee in satoshis for every candidate")
    cli.add_argument("--max-lock-bytes", type=int, help="exclude locks above a serialized Script byte budget")
    cli.add_argument("--max-expanded-ops", type=int, default=MAX_EXPANSION,
                     help="bound expanded definitions and branches before running the backends")
    cli.add_argument("--r1cs", action="store_true", help="enable the pinned Circom/snarkjs prover")
    cli.add_argument("--groth16", nargs=2, type=Path, metavar=("ZKEY", "PHASE2_PTAU"))
    cli.add_argument("--replay", action="store_true")
    cli.add_argument("--output", type=Path)
    args = cli.parse_args()
    if args.replay and isinstance(__loader__, zipimporter):
        cli.error("funded replay requires fourthgraph.verification.plan from the source checkout")
    try:
        source = args.source.read_bytes()
        frontend = SourceCompiler(source.decode(), source_path=args.source)
        keys = {role: bytes.fromhex(key) for role, key in json.loads(args.keys.read_bytes()).items()}
        with TemporaryDirectory(prefix="4thgraph-verification-") as scratch:
            candidate, report = compile_solutions(
                frontend, keys, args.current, scratch, target=args.target, policy=args.policy, objective=args.objective,
                r1cs=args.r1cs, groth16=args.groth16, spend_fee=args.spend_fee,
                max_lock_bytes=args.max_lock_bytes, max_expansion=args.max_expanded_ops,
            )
            if args.replay:
                report = {"build": report, "replay": funded_replay(candidate, args.target)}
        text = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(text)
        else:
            print(text, end="")
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        cli.error(str(error))


if __name__ == "__main__":
    main()
