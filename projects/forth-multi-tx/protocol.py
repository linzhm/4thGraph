"""ForkID transaction templates and covenants for the two-branch program."""

import argparse
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from pathlib import Path
from types import MappingProxyType

from shared.pushtx import PUBLIC, binding_der
from shared.script import asm, encode_num, number, push
from shared.transaction import FORKID, SIGHASH_ALL, Input, Output, Transaction, hash256, preimage_forkid

from compiler import (
    PROJECT_DESCRIPTION, PROJECT_NAME, PROJECT_VERSION, CompileError, Plan, SourceCompiler, Template, evaluate, schedule,
)
from lowering import BASELINE, OPTIMIZATIONS, compile_word
from wordsets import U32, capabilities, push_value

DEFAULT_TARGET = "chronicle-v2"
TARGETS = {"forkid-v1": ((1,), "genesis"), DEFAULT_TARGET: ((2,), "chronicle"),
           "both": ((1, 2), "genesis")}
FLAG = FORKID | SIGHASH_ALL
FLAG_BYTES = FLAG.to_bytes(4, "little")
BINDING_CODE = asm("OP_CHECKSIG")
ZERO_INDEX = bytes(4)
ROOT_VALUE, WORK_VALUE, RESULT_VALUE, TERMINAL_VALUE = 1_020_000, 507_500, 502_500, 1_000_000
GATED_FORK_VALUE = ROOT_VALUE - 1_000
RESULT_WIDTH = 5  # Four unsigned payload bytes plus a zero sign byte.
PREVOUTS_HASH = 4
CURRENT_OUTPOINT = 68
OUTPUTS_HASH = 118
JOIN_WITNESSES = ("full", "shared")
SECP256K1_FIELD = (1 << 256) - (1 << 32) - 977


def is_compressed_public_key(encoded):
    if not isinstance(encoded, bytes) or len(encoded) != 33 or encoded[0] not in (2, 3):
        return False
    x = int.from_bytes(encoded[1:], "big")
    if x >= SECP256K1_FIELD:
        return False
    # A nonzero quadratic residue has one root of each parity.
    square = (pow(x, 3, SECP256K1_FIELD) + 7) % SECP256K1_FIELD
    if square == 0:
        return encoded[0] == 2
    return pow(square, (SECP256K1_FIELD - 1) // 2, SECP256K1_FIELD) == 1


def field(offset, width):
    prefix = number(offset) + asm("OP_SPLIT OP_NIP") if offset else b""
    return prefix + number(width) + asm("OP_SPLIT OP_DROP")


def copy_preimage():
    return asm("OP_FROMALTSTACK OP_DUP OP_TOALTSTACK")


def check_version(versions, suffix=b""):
    expected = [push(version.to_bytes(4, "little") + suffix) for version in versions]
    if len(expected) == 1:
        return expected[0] + asm("OP_EQUALVERIFY")
    first, second = expected
    return (asm("OP_DUP") + first + asm("OP_EQUAL OP_SWAP") + second
            + asm("OP_EQUAL OP_BOOLOR OP_VERIFY"))


def begin(versions):
    # Fixed BIP143 shape: the executed CODESEPARATOR leaves a one-byte scriptCode.
    return (asm("OP_SIZE") + number(158) + asm("OP_NUMEQUALVERIFY OP_DUP OP_TOALTSTACK OP_DUP")
            + field(0, 4) + check_version(versions)
            + field(154, 4) + push(FLAG_BYTES) + asm("OP_EQUALVERIFY"))


def check_field(offset, width=32):
    return copy_preimage() + field(offset, width) + asm("OP_EQUALVERIFY")


def single_input():
    return copy_preimage() + field(CURRENT_OUTPOINT, 36) + asm("OP_HASH256") + check_field(PREVOUTS_HASH)


def finish():
    return (asm("OP_FROMALTSTACK OP_HASH256") + binding_der() + push(bytes([FLAG])) + asm("OP_CAT")
            + push(PUBLIC) + asm("OP_CODESEPARATOR") + BINDING_CODE)


def authorize(public):
    # Check the signature's actual sighash before passing it to native CHECKSIG.
    return (asm("OP_SIZE OP_1SUB OP_SPLIT") + push(bytes([FLAG])) + asm("OP_EQUALVERIFY")
            + push(bytes([FLAG])) + asm("OP_CAT") + push(public) + asm("OP_CHECKSIGVERIFY"))


def validate_u32():
    return (asm("OP_DUP OP_DUP OP_BIN2NUM OP_EQUALVERIFY OP_DUP OP_0")
            + number(U32) + asm("OP_WITHIN OP_VERIFY"))


def output_hash(outputs):
    return hash256(b"".join(output.serialize() for output in outputs))


def route_check(terminals):
    review, settle = (output_hash((output,)) for output in terminals)
    return (asm("OP_IF") + push(settle) + asm("OP_ELSE") + push(review) + asm("OP_ENDIF")
            + check_field(OUTPUTS_HASH))


def p2pk(public):
    return push(public) + asm("OP_CHECKSIG")


def proof(index, data_prefix, versions):
    # Entry rawWork splitTxid. The first input must spend the indicated split slot.
    bound_prefix = (asm("OP_OVER") + field(0, 5) + check_version(versions, b"\x01")
                    + push(index.to_bytes(4, "little")) + asm("OP_CAT OP_OVER")
                    + field(5, 36) + asm("OP_EQUALVERIFY"))
    # The branch covenant fixes both outputs and the exact last output layout.
    # The 4 bytes after the fixed-width value are the transaction locktime.
    tail = (asm("OP_SIZE") + number(len(data_prefix) + RESULT_WIDTH + 4)
            + asm("OP_SUB OP_SPLIT OP_NIP") + number(len(data_prefix)) + asm("OP_SPLIT OP_SWAP")
            + push(data_prefix) + asm("OP_EQUALVERIFY") + field(0, RESULT_WIDTH) + asm("OP_BIN2NUM"))
    return bound_prefix + tail


def reconstruct_parents():
    # Entry: aHead aTail bHead bTail common preimage splitTxid.
    # The supplied common bytes acquire authority only through hashPrevouts.
    return asm("OP_TOALTSTACK OP_TOALTSTACK OP_DUP OP_TOALTSTACK OP_SWAP OP_CAT OP_CAT "
               "OP_FROMALTSTACK OP_2SWAP OP_ROT OP_SWAP OP_CAT OP_CAT OP_SWAP "
               "OP_FROMALTSTACK OP_FROMALTSTACK")


def join_lock(code, terminals, data_prefix, versions, witness):
    # Lock prefix pushes splitTxid above witness rawA rawB P.
    read_results = (asm("OP_2 OP_PICK OP_OVER") + proof(0, data_prefix, versions)
                    + asm("OP_TOALTSTACK OP_OVER OP_OVER") + proof(1, data_prefix, versions)
                    + asm("OP_FROMALTSTACK OP_SWAP"))
    bind_prevouts = (asm("OP_DROP OP_HASH256") + push(ZERO_INDEX) + asm("OP_CAT OP_SWAP OP_HASH256")
                     + push(ZERO_INDEX) + asm("OP_CAT OP_SWAP OP_CAT OP_HASH256") + check_field(PREVOUTS_HASH))
    reconstruct = reconstruct_parents() if witness == "shared" else b""
    return (reconstruct + asm("OP_SWAP") + begin(versions) + read_results + code
            + route_check(terminals) + bind_prevouts + finish())


def work_lock(index, code, owner, join_code, data_prefix, versions):
    example = Output(RESULT_VALUE, push(bytes(32)) + join_code)
    result_prefix = example.serialize()[:-(32 + len(join_code))]
    # From the branch result, build the whole output vector as it must appear on wire.
    output_vector = (number(RESULT_WIDTH) + asm("OP_NUM2BIN") + push(data_prefix) + asm("OP_SWAP OP_CAT")
                     + copy_preimage() + field(CURRENT_OUTPOINT, 32) + push(result_prefix) + asm("OP_SWAP OP_CAT")
                     + push(join_code) + asm("OP_CAT OP_SWAP OP_CAT OP_HASH256"))
    return (begin(versions) + single_input() + push(index.to_bytes(4, "little")) + check_field(CURRENT_OUTPOINT + 32, 4)
            + authorize(owner) + validate_u32() + code + output_vector + check_field(OUTPUTS_HASH) + finish())


@dataclass(frozen=True)
class Outpoint:
    txid: bytes  # Transaction hash in wire order.
    vout: int

    def text(self):
        return f"{self.txid[::-1].hex()}:{self.vout}"


@dataclass(frozen=True)
class UTXO:
    parent: Transaction
    vout: int

    @property
    def outpoint(self):
        return Outpoint(self.parent.txid_wire(), self.vout)

    @property
    def output(self):
        return self.parent.outputs[self.vout]


@dataclass(frozen=True)
class SignRequest:
    step: str
    outpoint: Outpoint
    authorizer: str
    public_key: bytes
    sighash: int
    digest: bytes
    transaction: Transaction
    previous_output: Output
    witness_data: tuple[bytes, ...]


@dataclass(frozen=True)
class Draft:
    template: Template
    tx: Transaction
    previous: tuple[UTXO, ...]
    payload: tuple[tuple[bytes, ...], ...]
    keys: Mapping[str, bytes]

    @property
    def parents(self):
        return tuple(utxo.parent for utxo in self.previous)

    def signing_requests(self):
        if len(self.tx.inputs) != len(self.previous) or len(self.previous) != len(self.payload):
            raise ValueError("draft inputs, previous outputs and witnesses must have the same length")
        for txin, utxo, fields in zip(self.tx.inputs, self.previous, self.payload, strict=True):
            if not 0 <= utxo.vout < len(utxo.parent.outputs):
                raise ValueError("draft previous output index is out of range")
            if (txin.txid, txin.vout) != (utxo.outpoint.txid, utxo.vout):
                raise ValueError("draft input does not match its bound previous output")
            if any(not isinstance(value, bytes) for value in fields):
                raise ValueError("draft witness fields must be bytes")
        if not self.template.authorizers:
            return ()
        if len(self.previous) != 1:
            raise ValueError("an authorized draft must have exactly one input")
        utxo = self.previous[0]
        digest = hash256(preimage_forkid(self.tx, 0, utxo.output.value, utxo.output.script, FLAG))
        return tuple(SignRequest(self.template.name, utxo.outpoint, owner, self.keys[owner], FLAG, digest,
                                 self.tx, utxo.output, self.payload[0])
                     for owner in self.template.authorizers)

    def seal(self, sign: Callable[[SignRequest], bytes]):
        # The external callback returns DER. Append the required sighash in the runner.
        requests = self.signing_requests()
        preimages = tuple(preimage_forkid(self.tx, i, utxo.output.value, BINDING_CODE, FLAG)
                          for i, utxo in enumerate(self.previous))
        signatures = tuple(sign(request) + bytes([request.sighash]) for request in requests)
        tx = self.tx
        for i, (fields, preimage) in enumerate(zip(self.payload, preimages, strict=True)):
            if i == 0:
                fields = (*fields, *reversed(signatures))
            tx = tx.with_script(i, b"".join(push_value(value) for value in (*fields, preimage)))
        return tx


def invalidated(plan, step, before, after):
    """Identify descendants to rebind and the affected external authorizations."""
    if before.txid_wire() == after.txid_wire():
        return {}
    changed = {step}
    results = {}
    for template in plan.templates:
        if any(ref.step in changed for ref in template.inputs):
            changed.add(template.name)
            results[template.name] = template.authorizers
    return results


@dataclass(frozen=True)
class Host:
    """Providers for the Forth host vocabulary. The signer returns DER bytes."""

    lookup: Callable[[Outpoint], UTXO]
    sign: Callable[[SignRequest], bytes]
    submit: Callable[[Transaction], bytes]

    def outpoint(self, utxo):
        return utxo.outpoint

    def script(self, utxo):
        return utxo.output.script


class Contracts:
    def __init__(self, plan: Plan, keys, task_id, *, target=DEFAULT_TARGET, optimization=BASELINE,
                 join_witness="full"):
        if target not in TARGETS:
            raise ValueError(f"unknown compilation target {target!r}")
        self.target = target
        self.optimization = optimization
        if join_witness not in JOIN_WITNESSES:
            raise ValueError(f"unknown join witness format {join_witness!r}")
        self.join_witness = join_witness
        self.versions, self.era = TARGETS[target]
        self.version = self.versions[-1]
        if not isinstance(task_id, bytes) or len(task_id) != 32:
            raise ValueError("task id must be 32 bytes")
        required = {name for step in plan.templates for name in step.authorizers} | {"settle", "review"}
        keys = dict(keys)
        for name in sorted(required):
            if not is_compressed_public_key(keys.get(name)):
                raise ValueError(f"{name} requires a valid compressed secp256k1 public key")
        self.plan = plan
        self.keys = MappingProxyType(keys)
        self.terminals = tuple(Output(TERMINAL_VALUE, p2pk(keys[name])) for name in ("review", "settle"))
        if self.terminals[0] == self.terminals[1]:
            raise ValueError("settle and review require distinct terminal scripts")
        data_script = asm("OP_0 OP_RETURN") + push(task_id) + push(bytes(RESULT_WIDTH))
        self.data_script_prefix = data_script[:-RESULT_WIDTH]
        self.data_prefix = Output(0, data_script).serialize()[:-RESULT_WIDTH]
        self.templates = {step.name: step for step in plan.templates}
        a, b = plan.program.work
        self.words = {step.name: compile_word(step.word, optimization) for step in (a, b)}
        self.words[plan.program.join_name] = compile_word(plan.program.join, optimization)
        select_route = self.words[plan.program.join_name].script
        gate = plan.program.gate
        guard = b""
        if gate is not None:
            self.words[gate.name] = compile_word(gate.word, optimization)
            guard = validate_u32() + self.words[gate.name].script + asm("OP_VERIFY")
        if plan.mode == "fused":
            # Optional z is above x/y, and its authorization follows both workers.
            authorizations = b"".join(authorize(keys[owner]) for owner in self.templates["fused"].authorizers)
            code = (begin(self.versions) + single_input() + authorizations + guard
                    + validate_u32() + asm("OP_SWAP") + validate_u32() + self.words[a.name].script
                    + asm("OP_SWAP") + self.words[b.name].script + select_route + route_check(self.terminals) + finish())
        else:
            self.join_code = join_lock(select_route, self.terminals, self.data_prefix, self.versions, join_witness)
            self.work_outputs = tuple(
                Output(WORK_VALUE, work_lock(i, self.words[step.name].script, keys[step.owner], self.join_code,
                                             self.data_prefix, self.versions))
                for i, step in enumerate(plan.program.work)
            )
            separate_gate = gate is not None and gate.name in self.templates
            fork_guard = b"" if separate_gate else guard
            code = (begin(self.versions) + single_input() + authorize(keys[plan.program.operator]) + fork_guard
                    + push(output_hash(self.work_outputs)) + check_field(OUTPUTS_HASH) + finish())
            if separate_gate:
                self.fork_output = Output(GATED_FORK_VALUE, code)
                code = (begin(self.versions) + single_input() + authorize(keys[gate.owner]) + guard
                        + push(output_hash((self.fork_output,))) + check_field(OUTPUTS_HASH) + finish())
        self.root = Output(ROOT_VALUE, code)

    def describe(self):
        def describe_output(output):
            return {"satoshis": output.value, "script_hex": output.script.hex()}

        spec = {
            "project": PROJECT_NAME,
            "compiler_version": PROJECT_VERSION,
            "schema_version": 1,
            "target": self.target,
            "optimization": self.optimization,
            "join_witness": self.join_witness,
            "word_builds": {name: word.describe() for name, word in self.words.items()},
            "era": self.era,
            "transaction_version": self.version,
            "supported_transaction_versions": self.versions,
            "sighash": f"{FLAG:02x}",
            "enabled_optional_wordsets": self.plan.program.optional_wordsets,
            "schedule": self.plan.mode,
            "fusion_blockers": self.plan.fusion_blockers,
            "boundary_reasons": self.plan.boundary_reasons,
            "topology": "gated-parallel" if self.plan.program.gate is not None else "parallel",
            "estimated_cost": estimate_cost(self),
            "templates": [asdict(template) for template in self.plan.templates],
            "deploy_output": describe_output(self.root),
            "terminal_outputs": {route: describe_output(output)
                                 for route, output in zip(("review", "settle"), self.terminals, strict=True)},
        }
        if self.plan.mode == "split":
            spec.update(
                work_outputs=[describe_output(output) for output in self.work_outputs],
                result_output={"satoshis": RESULT_VALUE, "first_push": "split txid in wire order",
                               "script_suffix_hex": self.join_code.hex()},
                data_output={"satoshis": 0, "script_prefix_hex": self.data_script_prefix.hex(),
                             "suffix": "u32 ScriptNum encoded in five bytes"},
            )
            if self.plan.program.gate is not None and self.plan.program.gate.name in self.templates:
                spec["gated_fork_output"] = describe_output(self.fork_output)
        return spec

    def result_output(self, split):
        return self.result_output_for(split.txid_wire())

    def result_output_for(self, split_txid):
        return Output(RESULT_VALUE, push(split_txid) + self.join_code)

    def data_output(self, value):
        encoded = encode_num(value).ljust(RESULT_WIDTH, b"\0")
        return Output(0, self.data_script_prefix + encoded)

    def result_value(self, parent):
        if len(parent.outputs) != 2:
            raise ValueError("result transaction must have two outputs")
        encoded = parent.outputs[1].serialize()
        if (len(encoded) != len(self.data_prefix) + RESULT_WIDTH
                or not encoded.startswith(self.data_prefix) or encoded[-1] != 0):
            raise ValueError("incorrect result data output")
        return int.from_bytes(encoded[-RESULT_WIDTH:-1], "little")

    def join_payload(self, parents):
        if self.join_witness == "full":
            return tuple(parent.serialize() for parent in parents)
        fields = []
        for parent in parents:
            if len(parent.outputs) != 2 or not parent.outputs[0].script.endswith(self.join_code):
                raise ValueError("result parent has no common join script")
            raw = parent.serialize()
            end = len(raw) - len(parent.outputs[1].serialize()) - 4  # Ends before output 1 and locktime.
            fields.extend((raw[:end - len(self.join_code)], raw[end:]))
        return (*fields, self.join_code)

    def bound_input(self, reference, completed):
        parent = completed.get(reference.step)
        if not isinstance(parent, Transaction) or not 0 <= reference.vout < len(parent.outputs):
            raise ValueError(f"missing bound output {reference.step}:{reference.vout}")
        utxo = UTXO(parent, reference.vout)
        if reference.step == "deploy":
            if utxo.output != self.root:
                raise ValueError("deployment output does not match this contract")
            return utxo
        template = self.templates[reference.step]
        if parent.version not in self.versions or len(parent.inputs) != len(template.inputs):
            raise ValueError(f"{reference.step} has an unexpected version or input count")
        for txin, dependency in zip(parent.inputs, template.inputs, strict=True):
            ancestor = completed.get(dependency.step)
            if (txin.vout != dependency.vout or dependency.step in completed
                    and (not isinstance(ancestor, Transaction) or txin.txid != ancestor.txid_wire())):
                raise ValueError(f"{reference.step} does not spend its bound {dependency.step}:{dependency.vout}")
        if template.outputs == ("split-lock",):
            expected = (self.fork_output,)
        elif template.outputs == ("work", "work"):
            expected = self.work_outputs
        elif template.outputs == ("result", "data"):
            expected = (self.result_output_for(parent.inputs[0].txid), self.data_output(self.result_value(parent)))
        else:
            raise ValueError(f"{reference.step} cannot be used as a parent of another contract step")
        if parent.outputs != expected:
            raise ValueError(f"{reference.step} outputs do not match this contract")
        return utxo

    def prepare(self, name, completed, data=None, *, version=None):
        return self._prepare(name, completed, data, version=version)

    def _prepare(self, name, completed, data, *, version=None, estimate=False):
        version = self.version if version is None else version
        if type(version) is not int or version not in self.versions:
            raise ValueError(f"transaction version {version} is unavailable for target {self.target}")
        template = self.templates[name]
        previous = tuple(self.bound_input(ref, completed) for ref in template.inputs)
        inputs = tuple(Input(utxo.outpoint.txid, utxo.outpoint.vout) for utxo in previous)
        a, b = self.plan.program.work
        gate = self.plan.program.gate
        gate_payload = ()
        if gate is not None and gate.name in template.executes:
            value = input_value(data, gate.input)
            if not estimate:
                accepted, = evaluate(gate.word, value)
                if not accepted:
                    raise ValueError(f"gate {gate.name} rejected input {gate.input}")
            gate_payload = (encode_num(value),)
        if name == "fused":
            x, y = input_value(data, a.input), input_value(data, b.input)
            result_a, = evaluate(a.word, x)
            result_b, = evaluate(b.word, y)
            route, = evaluate(self.plan.program.join, result_a, result_b)
            outputs, payload = (self.terminals[route],), ((encode_num(x), encode_num(y), *gate_payload),)
        elif name == "split":
            outputs, payload = self.work_outputs, (gate_payload,)
        elif gate is not None and name == gate.name:
            outputs, payload = (self.fork_output,), (gate_payload,)
        elif name == self.plan.program.join_name:
            parents = tuple(utxo.parent for utxo in previous)
            if parents[0].inputs[0].txid != parents[1].inputs[0].txid:
                raise ValueError("join results must spend the same split transaction")
            route, = evaluate(self.plan.program.join, *(self.result_value(parent) for parent in parents))
            outputs, payload = (self.terminals[route],), (self.join_payload(parents),) * 2
        else:
            step = a if name == a.name else b
            value = input_value(data, step.input)
            result, = evaluate(step.word, value)
            outputs = (self.result_output(previous[0].parent), self.data_output(result))
            payload = ((encode_num(value),),)
        return Draft(template, Transaction(inputs, outputs, version=version), previous, payload, self.keys)


def input_value(data, name):
    if data is None or name not in data:
        raise ValueError(f"missing input {name}")
    value = data[name]
    if type(value) is not int or not 0 <= value < U32:
        raise ValueError(f"{name} must be a u32")
    return value


def estimate_cost(contracts):
    # Fixed fixture for plan comparison. ECDSA signature size and input
    # encoding may vary in a signed transaction, so this is not a fee quote.
    fake_der = bytes(71)
    deploy = Transaction((Input(bytes(32), 0, push(fake_der + bytes([FLAG]))),),
                         (contracts.root,), version=contracts.version)
    done = {"deploy": deploy}
    depths = {"deploy": 1}
    rows = {"deploy": {"bytes": len(deploy.serialize()), "signature_checks": 1,
                       "depends_on": [], "decision": "fund the first lock"}}
    program = contracts.plan.program
    data = {step.input: 0 for step in program.work}
    if program.gate is not None:
        data[program.gate.input] = 0
    for step in contracts.plan.templates:
        draft = contracts._prepare(step.name, done, data, estimate=True)
        tx = draft.seal(lambda _: fake_der)
        done[step.name] = tx
        depths[step.name] = 1 + max(depths[ref.step] for ref in step.inputs)
        decision = {
            ("terminal",): "choose the terminal under the verified route",
            ("work", "work"): "create separately spendable work outputs",
            ("result", "data"): "materialize a result for the join",
            ("split-lock",): "verify the gate before creating a separately authorized fork",
        }[step.outputs]
        rows[step.name] = {
            "bytes": len(tx.serialize()),
            "signature_checks": len(step.inputs) + len(step.authorizers),
            "depends_on": [asdict(ref) for ref in step.inputs],
            "executes": step.executes,
            "decision": decision,
        }
    return {
        "assumptions": {"external_u32_values": data, "ecdsa_der_bytes": len(fake_der), "deployment_inputs": 1},
        "whole_path_bytes": sum(step["bytes"] for step in rows.values()),
        "max_transaction_bytes": max(step["bytes"] for step in rows.values()),
        "max_signature_checks": max(step["signature_checks"] for step in rows.values()),
        "dependency_depth_including_deploy": max(depths.values()),
        "steps": rows,
    }


def compile_candidates(program, keys, task_id, *, mode, available_data, available_authorizers, **options):
    available_data = None if available_data is None else frozenset(available_data)
    available_authorizers = None if available_authorizers is None else frozenset(available_authorizers)
    if mode != "auto":
        schedule(program, mode, available_data=available_data, available_authorizers=available_authorizers)
    viable, evidence = {}, {}
    for candidate in ("fused", "split"):
        try:
            plan = schedule(program, candidate, available_data=available_data,
                            available_authorizers=available_authorizers)
            contract = Contracts(plan, keys, task_id, **options)
        except ValueError as error:
            evidence[candidate] = {"eligible": False, "reason": str(error)}
            continue
        evidence[candidate] = {"eligible": True, "cost": estimate_cost(contract)}
        viable[candidate] = contract
    if mode == "auto" and viable:
        order = ("whole_path_bytes", "max_signature_checks", "dependency_depth_including_deploy")
        mode = min(viable, key=lambda name: tuple(evidence[name]["cost"][metric] for metric in order))
    if mode not in viable:
        reasons = ", ".join(f"{name}: {row.get('reason')}" for name, row in evidence.items() if not row["eligible"])
        raise CompileError(f"no requested transaction plan is eligible ({reasons})")
    return viable[mode], {"selected": mode, "candidates": evidence}


def main():
    cli = argparse.ArgumentParser(prog=PROJECT_NAME, description=PROJECT_DESCRIPTION)
    cli.add_argument("source", type=Path, nargs="?")
    action = cli.add_mutually_exclusive_group()
    action.add_argument("--capabilities", action="store_true", help="list the supported Forth and BSV words")
    action.add_argument("--entry", help="compile one annotated Forth word to Script without a transaction plan")
    cli.add_argument("--version", action="version", version=f"%(prog)s {PROJECT_VERSION}")
    cli.add_argument("--mode", choices=("auto", "fused", "split"), default="auto")
    cli.add_argument("--target", choices=TARGETS, default=DEFAULT_TARGET, help="permitted transaction versions")
    cli.add_argument("--optimize", choices=OPTIMIZATIONS, default=BASELINE)
    cli.add_argument("--join-witness", choices=JOIN_WITNESSES, default="full")
    cli.add_argument("--explain", action="store_true", help="show both candidates and how the plan was chosen")
    cli.add_argument("--keys", type=Path, help="JSON map of role to compressed public key hex")
    cli.add_argument("--task-id", help="32-byte hex data identifier")
    cli.add_argument("--available-data", nargs="*")
    cli.add_argument("--available-authorizers", nargs="*")
    args = cli.parse_args()
    if args.capabilities:
        print(json.dumps({"project": PROJECT_NAME, "compiler_version": PROJECT_VERSION, "description": PROJECT_DESCRIPTION,
                          **capabilities(), "optimizations": OPTIMIZATIONS, "join_witnesses": JOIN_WITNESSES,
                          "topologies": ("parallel", "gated-parallel"), "targets": {
            name: {"transaction_versions": versions, "era": era} for name, (versions, era) in TARGETS.items()
        }}, indent=2))
        return
    if args.source is None:
        cli.error("a Forth source file is required")
    if args.entry is None and (args.keys is None or args.task_id is None):
        cli.error("transaction builds require --keys and --task-id")
    try:
        source_bytes = args.source.read_bytes()
        source = SourceCompiler(source_bytes.decode())
        if args.entry is not None:
            word = source.words.get(args.entry.casefold())
            if word is None:
                raise CompileError(f"undefined entry word {args.entry!r}")
            compiled = compile_word(word, args.optimize)
            result = {"project": PROJECT_NAME, "compiler_version": PROJECT_VERSION, "schema_version": 1,
                      "entry": args.entry, "takes": word.takes, "gives": word.gives,
                      "enabled_optional_wordsets": source.optional_wordsets, "optimization": args.optimize,
                      "script_hex": compiled.script.hex(), **compiled.describe()}
        else:
            raw_keys = json.loads(args.keys.read_text())
            if not isinstance(raw_keys, dict) or any(not isinstance(key, str) for key in raw_keys.values()):
                raise ValueError("keys must be a JSON object mapping roles to public key hex strings")
            keys = {name: bytes.fromhex(key) for name, key in raw_keys.items()}
            contract, explanation = compile_candidates(
                source.program(), keys, bytes.fromhex(args.task_id), mode=args.mode, available_data=args.available_data,
                available_authorizers=args.available_authorizers, target=args.target, optimization=args.optimize,
                join_witness=args.join_witness,
            )
            result = contract.describe()
            if args.explain:
                result["schedule_explanation"] = explanation
        result["source_sha256"] = sha256(source_bytes).hexdigest()
        canonical = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        result["artifact_sha256"] = sha256(canonical).hexdigest()
    except CompileError as error:
        cli.error(f"{args.source}: {error}")
    except (OSError, ValueError) as error:
        cli.error(str(error))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
