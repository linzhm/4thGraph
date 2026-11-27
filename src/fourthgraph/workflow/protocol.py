"""BIP143 transaction templates and covenants for the two-branch program."""

import argparse
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, replace
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
from types import MappingProxyType

from fourthgraph.bsv.pushtx import PUBLIC, binding_der
from fourthgraph.bsv.script import asm, encode_num, is_compressed_public_key, number, push, without_codeseparators
from fourthgraph.bsv.transaction import CHRONICLE, FORKID, SIGHASH_ALL, Input, Output, Transaction, hash256, preimage_forkid, preimage_otda

from fourthgraph.compiler.ranges import NUMERIC_TYPES
from fourthgraph.compiler.source import (
    GATE_BOUNDARIES, PROJECT_DESCRIPTION, PROJECT_NAME, PROJECT_VERSION, CompileError, ParentOutput, Plan,
    SourceCompiler, Template, Workflow, WORKFLOW_MODES, availability, evaluate, fused_template, fusion_constraints, gate_constraints,
    schedule, split_templates,
)
from fourthgraph.compiler.lowering import BASELINE, OPTIMIZATIONS, compile_word
from fourthgraph.compiler.pels_language import WORDS as PELS_WORDS
from fourthgraph.compiler.stack_schedule import Graph
from fourthgraph.stdlib import capabilities as library_capabilities, describe_export
from fourthgraph.workflow.transaction_graph import TransactionGraph
from fourthgraph.workflow.cpn import from_build as transaction_plan, mermaid as plan_mermaid
from fourthgraph.compiler.wordsets import U32, capabilities, push_value

DEFAULT_TARGET = "chronicle-v2"
TARGETS = {"bip143-v1": ((1,), "genesis"), DEFAULT_TARGET: ((2,), "chronicle"),
           "both": ((1, 2), "genesis")}
FLAG = FORKID | SIGHASH_ALL
SIGHASH_FAMILIES = {"bip143": FLAG, "otda": FLAG | CHRONICLE}
SIGHASH_FAMILY_OPTIONS = (*SIGHASH_FAMILIES, "both")
FLAG_BYTES = FLAG.to_bytes(4, "little")
BINDING_CODE = asm("OP_CHECKSIG")
ZERO_INDEX = bytes(4)
ROOT_VALUE, WORK_VALUE, RESULT_VALUE, TERMINAL_VALUE = 1_020_000, 507_500, 502_500, 1_000_000
GATED_FORK_VALUE = ROOT_VALUE - 1_000
GATED_RECOVERY_WORK_VALUE = 507_000
RESULT_WIDTH = 5  # Four unsigned payload bytes plus a zero sign byte.
PREVOUTS_HASH = 4
CURRENT_OUTPOINT = 68
OUTPUTS_HASH = 118
CURRENT_SEQUENCE, LOCKTIME = 114, 150
REFUND_SEQUENCE = 0xFFFFFFFE
REFUND_FEE = 1_000
JOIN_WITNESSES = ("full", "shared")
CANDIDATE_ORDER = ("fused", "split")
RANK_ORDER = ("whole_path_bytes", "max_signature_checks", "dependency_depth_including_deploy")
OBJECTIVES = {
    "path-bytes": RANK_ORDER,
    "peak-validation": ("max_signature_checks", "max_input_script_bytes", "whole_path_bytes",
                        "dependency_depth_including_deploy"),
}


def normalize_target(value):
    return "bip143-v1" if value == "forkid-v1" else value


def normalize_sighash_family(value):
    return {"forkid": "bip143", "chronicle": "otda"}.get(value, value)


def candidate_sighash_families(target, policy):
    if policy != "auto":
        return (policy,)
    return ("bip143", "otda") if TARGETS[target][1] == "chronicle" else ("bip143",)


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


def finish(flag=FLAG, *, flag_script=None):
    suffix = push(bytes([flag])) if flag_script is None else flag_script
    return (asm("OP_FROMALTSTACK OP_HASH256") + binding_der() + suffix + asm("OP_CAT")
            + push(PUBLIC) + asm("OP_CODESEPARATOR") + BINDING_CODE)


def authorize(public, flag=FLAG, *, flag_script=None):
    # Check the signature's actual sighash before passing it to native CHECKSIG.
    split = asm("OP_SIZE OP_1SUB OP_SPLIT")
    if flag == FLAG and flag_script is None:
        expected = push(bytes([FLAG]))
        check = expected + asm("OP_EQUALVERIFY") + expected
    else:
        expected = push(bytes([flag])) if flag_script is None else flag_script
        check = asm("OP_DUP") + expected + asm("OP_EQUALVERIFY")
    return split + check + asm("OP_CAT") + push(public) + asm("OP_CHECKSIGVERIFY")


def validate_u32():
    return (asm("OP_DUP OP_DUP OP_BIN2NUM OP_EQUALVERIFY OP_DUP OP_0")
            + number(U32) + asm("OP_WITHIN OP_VERIFY"))


def output_hash(outputs):
    return hash256(b"".join(output.serialize() for output in outputs))


@dataclass(frozen=True)
class OutputLayout:
    """Outputs whose designated locks begin with the same fixed-width u32."""

    base: tuple[Output, ...]
    committed: tuple[int, ...] = ()

    def bind(self, value=None):
        if not self.committed:
            return self.base
        if type(value) is not int or not 0 <= value < U32:
            raise ValueError("shared input must be a u32")
        prefix = push(value.to_bytes(RESULT_WIDTH, "little"))
        return tuple(Output(out.value, prefix + out.script) if i in self.committed else out
                     for i, out in enumerate(self.base))

    @staticmethod
    def read(output):
        data = output.script[:1 + RESULT_WIDTH]
        if len(data) != 1 + RESULT_WIDTH or data[0] != RESULT_WIDTH or data[-1] != 0:
            raise ValueError("invalid shared input in previous output")
        return int.from_bytes(data[1:], "little")

    def matches(self, outputs):
        if len(outputs) != len(self.base):
            return False
        value = self.read(outputs[self.committed[0]]) if self.committed else None
        return self.bind(value) == outputs

    def hash_script(self):
        if not self.committed:
            return push(output_hash(self.base))
        # Split the canonical serialization exactly at the u32 fields. This
        # includes amounts, CompactSize lengths, and the fixed-width push opcodes.
        parts = [bytearray()]
        for i, out in enumerate(self.bind(0)):
            raw = out.serialize()
            if i in self.committed:
                offset = len(raw) - len(out.script) + 1
                parts[-1].extend(raw[:offset])
                parts.append(bytearray(raw[offset + RESULT_WIDTH:]))
            else:
                parts[-1].extend(raw)
        code = number(RESULT_WIDTH) + asm("OP_NUM2BIN") + push(bytes(parts[0]))
        for tail in parts[1:]:
            code += asm("OP_OVER OP_CAT") + push(bytes(tail)) + asm("OP_CAT")
        return code + asm("OP_NIP OP_HASH256")


def route_check(terminals):
    review, settle = (output_hash((output,)) for output in terminals)
    return (asm("OP_IF") + push(settle) + asm("OP_ELSE") + push(review) + asm("OP_ENDIF")
            + check_field(OUTPUTS_HASH))


def p2pk(public):
    return push(public) + asm("OP_CHECKSIG")


def refund_output(value, public):
    return Output(value - REFUND_FEE, p2pk(public))


def recoverable_lock(normal, value, public, height, versions, *, prefixed=0):
    suffix = finish()
    if not normal.endswith(suffix):
        raise ValueError("recoverable covenant requires the shared BIP143 verification suffix")
    # Both branches converge before CODESEPARATOR to preserve the scriptCode.
    select = asm(("OP_IF", "OP_SWAP OP_IF OP_DROP", "OP_ROT OP_IF OP_2DROP")[prefixed])
    refund = (begin(versions) + single_input() + authorize(public)
              + push(REFUND_SEQUENCE.to_bytes(4, "little")) + check_field(CURRENT_SEQUENCE, 4)
              + push(height.to_bytes(4, "little")) + check_field(LOCKTIME, 4)
              + push(output_hash((refund_output(value, public),))) + check_field(OUTPUTS_HASH))
    return select + refund + asm("OP_ELSE") + normal[:-len(suffix)] + asm("OP_ENDIF") + suffix


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
    input_index: int = 0


@dataclass(frozen=True)
class Draft:
    template: Template
    tx: Transaction
    previous: tuple[UTXO, ...]
    payload: tuple[tuple[bytes, ...], ...]
    keys: Mapping[str, bytes]
    recovery_selector: bool | None = None
    input_authorizers: tuple[tuple[str, ...], ...] | None = None
    context_encoder: Callable[[bytes], bytes] | None = None
    sighash: int = FLAG

    @property
    def parents(self):
        return tuple(utxo.parent for utxo in self.previous)

    def preimage(self, index, script_code):
        if self.sighash & CHRONICLE:
            return preimage_otda(self.tx, index, without_codeseparators(script_code), self.sighash)
        return preimage_forkid(self.tx, index, self.previous[index].output.value, script_code, self.sighash)

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
        roles = self.input_authorizers
        if roles is None:
            if not self.template.authorizers:
                return ()
            if len(self.previous) == 1:
                roles = (self.template.authorizers,)
            else:
                raise ValueError("multi-input authorized drafts require roles per input")
        if (len(roles) != len(self.previous)
                or tuple(owner for owners in roles for owner in owners) != self.template.authorizers):
            raise ValueError("input authorization does not match the transaction template")
        requests = []
        for index, (utxo, owners) in enumerate(zip(self.previous, roles, strict=True)):
            if not owners:
                continue
            digest = hash256(self.preimage(index, utxo.output.script))
            requests.extend(SignRequest(self.template.name, utxo.outpoint, owner, self.keys[owner], self.sighash, digest,
                                        self.tx, utxo.output, self.payload[index], index) for owner in owners)
        return tuple(requests)

    def seal(self, sign: Callable[[SignRequest], bytes]):
        # The external callback returns DER. Append the required sighash in the runner.
        requests = self.signing_requests()
        preimages = tuple(self.preimage(i, BINDING_CODE) for i in range(len(self.previous)))
        if self.context_encoder is not None:
            preimages = tuple(map(self.context_encoder, preimages))
        signatures = [[] for _ in self.previous]
        for request in requests:
            signatures[request.input_index].append(sign(request) + bytes([request.sighash]))
        tx = self.tx
        selector = () if self.recovery_selector is None else (encode_num(int(self.recovery_selector)),)
        for i, (fields, preimage) in enumerate(zip(self.payload, preimages, strict=True)):
            fields = (*fields, *reversed(signatures[i]))
            tx = tx.with_script(i, b"".join(push_value(value) for value in (*fields, preimage, *selector)))
        return tx

    def binding_evidence(self, tx):
        unsigned_inputs = tuple(replace(item, script=b"") for item in tx.inputs)
        if replace(tx, inputs=unsigned_inputs) != self.tx:
            raise ValueError("sealed transaction does not match its draft inputs and outputs")
        requests = self.signing_requests()
        return {
            "step": self.template.name, "executes": self.template.executes,
            "inputs": [{"input_index": index, "from": asdict(ref), "outpoint": utxo.outpoint.text(),
                        "authorizers": [{"role": req.authorizer, "digest": req.digest.hex()}
                                        for req in requests if req.input_index == index]}
                       for index, (ref, utxo) in enumerate(zip(self.template.inputs, self.previous, strict=True))],
            "outputs": [{"vout": index, "kind": kind, "outpoint": Outpoint(tx.txid_wire(), index).text(),
                         "satoshis": output.value}
                        for index, (kind, output) in enumerate(zip(self.template.outputs, tx.outputs, strict=True))],
        }


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


def template_external_inputs(program, template):
    gate = program.gate
    shared = program.shared_input
    if template.name == "fused":
        return tuple(dict.fromkeys(program.input_order))
    if template.name == "split":
        inputs = (shared,) if shared is not None else ()
        if gate is None:
            return inputs
        if gate.name not in template.executes:
            return () if gate.input == shared else inputs
        return inputs if gate.input == shared else (*inputs, gate.input)
    if gate and template.name == gate.name:
        return (gate.input,)
    return tuple(step.input for step in program.work if step.name == template.name and step.input != shared)


class Contracts:
    def __init__(self, plan: Plan, keys, task_id, *, target=DEFAULT_TARGET, optimization=BASELINE,
                 join_witness="full"):
        target = normalize_target(target)
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
        self.recovery = plan.program.recovery
        if self.recovery is not None:
            required.add(self.recovery.owner)
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
        self.unique_inputs = tuple(dict.fromkeys(plan.program.input_order))
        self.shared_input = plan.program.shared_input
        self.separate_gate = gate is not None and gate.name in self.templates
        gate_code = b""
        if gate is not None:
            self.words[gate.name] = compile_word(gate.word, optimization)
            gate_code = self.words[gate.name].script + asm("OP_VERIFY")
        guard = validate_u32() + gate_code if gate is not None else b""
        if plan.mode == "fused":
            # Optional z is above x/y, and its authorization follows both workers.
            authorizations = b"".join(authorize(keys[owner]) for owner in self.templates["fused"].authorizers)
            graph = Graph(len(self.unique_inputs))
            slots = dict(zip(self.unique_inputs, graph.inputs, strict=True))
            distribute = graph.emit([slots[name] for name in plan.program.input_order])
            code = (begin(self.versions) + single_input() + authorizations + distribute + guard
                    + validate_u32() + asm("OP_SWAP") + validate_u32() + self.words[a.name].script
                    + asm("OP_SWAP") + self.words[b.name].script + select_route + route_check(self.terminals) + finish())
        else:
            self.join_code = join_lock(select_route, self.terminals, self.data_prefix, self.versions, join_witness)
            self.join_code = self.state_lock(self.join_code, RESULT_VALUE, prefixed=True)
            work_value = GATED_RECOVERY_WORK_VALUE if gate is not None and self.recovery else WORK_VALUE
            # A committed prefix leaves [signature preimage fixed-u32]. Move its
            # canonical ScriptNum into the old input position before verification.
            from_lock = asm("OP_BIN2NUM OP_ROT OP_ROT")
            committed = tuple(i for i, step in enumerate(plan.program.work) if step.input == self.shared_input)
            work_outputs = []
            for i, step in enumerate(plan.program.work):
                script = work_lock(i, self.words[step.name].script, keys[step.owner], self.join_code,
                                   self.data_prefix, self.versions)
                if i in committed:
                    script = from_lock + script
                work_outputs.append(Output(work_value, self.state_lock(script, work_value, prefixed=i in committed)))
            self.work_layout = OutputLayout(tuple(work_outputs), committed)
            gate_shares = gate is not None and gate.input == self.shared_input
            if gate_shares:
                guard = validate_u32() + asm("OP_DUP") + gate_code
            split_code = begin(self.versions) + single_input() + authorize(keys[plan.program.operator])
            if not self.separate_gate:
                split_code += guard
            if committed and (self.separate_gate or not gate_shares):
                split_code += validate_u32()
            code = split_code + self.work_layout.hash_script() + check_field(OUTPUTS_HASH) + finish()
            if self.separate_gate:
                # Both transactions carry the work locks. With recovery the
                # larger scripts need 3,000 sat each in the regtest fixture.
                fork_value = ((ROOT_VALUE + 2 * work_value) // 2
                              if committed or self.recovery else GATED_FORK_VALUE)
                fork_code = (from_lock if gate_shares else b"") + code
                fork = Output(fork_value, self.state_lock(fork_code, fork_value, prefixed=gate_shares))
                self.fork_layout = OutputLayout((fork,), (0,) if gate_shares else ())
                code = (begin(self.versions) + single_input() + authorize(keys[gate.owner]) + guard
                        + self.fork_layout.hash_script() + check_field(OUTPUTS_HASH) + finish())
        self.root = Output(ROOT_VALUE, self.state_lock(code, ROOT_VALUE))

    def state_lock(self, code, value, *, prefixed=False):
        if self.recovery is None:
            return code
        return recoverable_lock(code, value, self.keys[self.recovery.owner], self.recovery.height,
                                self.versions, prefixed=prefixed)

    def recovery_refs(self):
        return tuple(dict.fromkeys(ref for step in self.plan.templates for ref in step.inputs))

    def recovery_status(self, completed, live_outpoints, *, tip_height):
        if self.recovery is None:
            raise ValueError("this program has no recovery policy")
        live = set(live_outpoints)
        state = {}
        for ref in self.recovery_refs():
            if ref.step not in completed:
                continue
            utxo = self.bound_input(ref, completed)
            if utxo.outpoint in live:
                state[ref] = utxo
        return {
            "tip_height": tip_height,
            "advance": [{"step": step.name, "authorizers": step.authorizers,
                         "inputs": [state[ref].outpoint.text() for ref in step.inputs],
                         "external_inputs": self.external_inputs(step)}
                        for step in self.plan.templates if all(ref in state for ref in step.inputs)],
            "refund": [{"from": asdict(ref), "outpoint": utxo.outpoint.text(), "satoshis": utxo.output.value,
                        "refund_satoshis": utxo.output.value - REFUND_FEE, "authorizer": self.recovery.owner,
                        "height_reached": tip_height >= self.recovery.height}
                       for ref, utxo in state.items()],
        }

    @property
    def work_outputs(self):
        return self.work_layout.bind()

    @property
    def fork_output(self):
        return self.fork_layout.bind()[0]

    def output_layout(self, step):
        if step == "split":
            return self.work_layout
        if self.separate_gate and step == self.plan.program.gate.name:
            return self.fork_layout
        return None

    def external_inputs(self, template):
        return template_external_inputs(self.plan.program, template)

    def describe(self, *, cost=None):
        def describe_output(output):
            return {"satoshis": output.value, "script_hex": output.script.hex()}

        def describe_layout(layout):
            return [{"satoshis": out.value, "prefix_u32_input": self.shared_input,
                     "script_suffix_hex": out.script.hex()} if i in layout.committed else describe_output(out)
                    for i, out in enumerate(layout.base)]

        spec = {
            "project": PROJECT_NAME,
            "compiler_version": PROJECT_VERSION,
            "schema_version": 3 if self.recovery is not None else (2 if self.shared_input is not None else 1),
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
            "estimated_cost": estimate_cost(self) if cost is None else cost,
            "templates": [asdict(template) for template in self.plan.templates],
            "transaction_graph": self.plan.graph.describe(recovery=self.recovery, external_inputs=self.external_inputs),
            "deploy_output": describe_output(self.root),
            "terminal_outputs": {route: describe_output(output)
                                 for route, output in zip(("review", "settle"), self.terminals, strict=True)},
        }
        if self.plan.program.libraries:
            spec["libraries"] = tuple(map(asdict, self.plan.program.libraries))
        if self.plan.mode == "split":
            spec.update(
                work_outputs=describe_layout(self.work_layout),
                result_output={"satoshis": RESULT_VALUE, "first_push": "split txid in wire order",
                               "script_suffix_hex": self.join_code.hex()},
                data_output={"satoshis": 0, "script_prefix_hex": self.data_script_prefix.hex(),
                             "suffix": "u32 ScriptNum encoded in five bytes"},
            )
            if self.separate_gate:
                spec["gated_fork_output"], = describe_layout(self.fork_layout)
        if self.shared_input is not None:
            spec["shared_input"] = self.shared_input
            for row, template in zip(spec["templates"], self.plan.templates, strict=True):
                row["external_inputs"] = self.external_inputs(template)
        if self.recovery is not None:
            spec["recovery"] = {"locktime": self.recovery.height, "sequence": REFUND_SEQUENCE,
                                "authorizer": self.recovery.owner, "fee_satoshis": REFUND_FEE,
                                "destination_script_hex": p2pk(self.keys[self.recovery.owner]).hex(),
                                "recoverable_outputs": [asdict(ref) for ref in self.recovery_refs()]}
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
                    and (not isinstance(ancestor, Transaction) or dependency.vout >= len(ancestor.outputs)
                         or txin.txid != ancestor.txid_wire())):
                raise ValueError(f"{reference.step} does not spend its bound {dependency.step}:{dependency.vout}")
        layout = self.output_layout(reference.step)
        if layout is not None:
            matches = layout.matches(parent.outputs)
            if matches and reference.step == "split" and self.separate_gate and self.fork_layout.committed:
                gate_tx = completed.get(self.plan.program.gate.name)
                if gate_tx is not None:
                    matches = parent.outputs == layout.bind(self.fork_layout.read(gate_tx.outputs[0]))
        elif template.outputs == ("result", "data"):
            matches = parent.outputs == (self.result_output_for(parent.inputs[0].txid),
                                         self.data_output(self.result_value(parent)))
        else:
            raise ValueError(f"{reference.step} cannot be used as a parent of another contract step")
        if not matches:
            raise ValueError(f"{reference.step} outputs do not match this contract")
        return utxo

    def prepare(self, name, completed, data=None, *, version=None):
        return self._prepare(name, completed, data, version=version)

    def resolve_version(self, version):
        version = self.version if version is None else version
        if type(version) is not int or version not in self.versions:
            raise ValueError(f"transaction version {version} is unavailable for target {self.target}")
        return version

    def prepare_refund(self, step, completed, *, vout=0, version=None):
        ref = ParentOutput(step, vout)
        if self.recovery is None or ref not in self.recovery_refs():
            raise ValueError(f"{step}:{vout} has no recovery path")
        utxo = self.bound_input(ref, completed)
        owner = self.recovery.owner
        tx = Transaction((Input(utxo.outpoint.txid, vout, sequence=REFUND_SEQUENCE),),
                         (refund_output(utxo.output.value, self.keys[owner]),),
                         version=self.resolve_version(version), locktime=self.recovery.height)
        template = Template("refund", (ref,), (owner,), ("refund",))
        return Draft(template, tx, (utxo,), ((),), self.keys, recovery_selector=True)

    def _prepare(self, name, completed, data, *, version=None, estimate=False):
        version = self.resolve_version(version)
        template = self.templates[name]
        previous = tuple(self.bound_input(ref, completed) for ref in template.inputs)
        inputs = tuple(Input(utxo.outpoint.txid, utxo.outpoint.vout) for utxo in previous)
        a, b = self.plan.program.work
        gate = self.plan.program.gate
        values = {key: input_value(data, key) for key in self.external_inputs(template)}
        payload = (tuple(map(encode_num, values.values())),)
        first_input = template.inputs[0]
        layout = self.output_layout(first_input.step)
        if layout is not None and first_input.vout in layout.committed:
            committed = OutputLayout.read(previous[0].output)
            if data is not None and self.shared_input in data and input_value(data, self.shared_input) != committed:
                raise ValueError(f"input {self.shared_input} differs from the bound previous output")
            values[self.shared_input] = committed
        if gate is not None and gate.name in template.executes and not estimate:
            accepted, = evaluate(gate.word, values[gate.input])
            if not accepted:
                raise ValueError(f"gate {gate.name} rejected input {gate.input}")
        if name == "fused":
            result_a, = evaluate(a.word, values[a.input])
            result_b, = evaluate(b.word, values[b.input])
            route, = evaluate(self.plan.program.join, result_a, result_b)
            outputs = (self.terminals[route],)
        elif name == "split":
            outputs = self.work_layout.bind(values.get(self.shared_input))
        elif gate is not None and name == gate.name:
            outputs = self.fork_layout.bind(values.get(self.shared_input))
        elif name == self.plan.program.join_name:
            parents = tuple(utxo.parent for utxo in previous)
            if parents[0].inputs[0].txid != parents[1].inputs[0].txid:
                raise ValueError("join results must spend the same split transaction")
            route, = evaluate(self.plan.program.join, *(self.result_value(parent) for parent in parents))
            outputs, payload = (self.terminals[route],), (self.join_payload(parents),) * 2
        else:
            step = a if name == a.name else b
            result, = evaluate(step.word, values[step.input])
            outputs = (self.result_output(previous[0].parent), self.data_output(result))
        return Draft(template, Transaction(inputs, outputs, version=version), previous, payload, self.keys,
                     recovery_selector=False if self.recovery is not None else None)


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
    program = contracts.plan.program
    workflow = isinstance(program, Workflow)
    fake_der = bytes(72 if workflow else 71)
    deploy = Transaction((Input(bytes(32), 0, push(fake_der + bytes([FLAG]))),),
                         contracts.deployment_outputs if workflow else (contracts.root,), version=contracts.version)
    done = {"deploy": deploy}
    depths = {"deploy": 1}
    rows = {"deploy": {"bytes": len(deploy.serialize()), "signature_checks": 1,
                       "input_script_bytes": len(deploy.inputs[0].script) + 35,  # P2PK funding lock
                       "depends_on": [], "decision": "fund the first lock"}}
    data = {} if workflow else {step.input: 0 for step in program.work}
    if not workflow and program.gate is not None:
        data[program.gate.input] = 0
    for step in contracts.plan.templates:
        draft = contracts.prepare(step.name, done) if workflow else contracts._prepare(step.name, done, data, estimate=True)
        tx = draft.seal(lambda _: fake_der)
        done[step.name] = tx
        depths[step.name] = 1 + max(depths[ref.step] for ref in step.inputs)
        decision = {
            ("terminal",): "choose the terminal under the verified route",
            ("work", "work"): "create separately spendable work outputs",
            ("result", "data"): "materialize a result for the join",
            ("split-lock",): "verify the gate before creating a separately authorized fork",
            ("state",): "commit the verified state to the next transaction's input",
            ("terminal", "receipt"): "choose the successor and record its workflow root and state",
        }[step.outputs]
        rows[step.name] = {
            "bytes": len(tx.serialize()),
            "signature_checks": len(step.inputs) + len(step.authorizers),
            "input_script_bytes": sum(len(txin.script) + len(utxo.output.script)
                                      for txin, utxo in zip(tx.inputs, draft.previous, strict=True)),
            "depends_on": [asdict(ref) for ref in step.inputs],
            "executes": step.executes,
            "decision": decision,
        }
    return {
        "assumptions": {"external_u32_values": data, "ecdsa_der_bytes": len(fake_der), "deployment_inputs": 1},
        "whole_path_bytes": sum(step["bytes"] for step in rows.values()),
        "max_transaction_bytes": max(step["bytes"] for step in rows.values()),
        "max_signature_checks": max(step["signature_checks"] for step in rows.values()),
        "max_input_script_bytes": max(step["input_script_bytes"] for step in rows.values()),
        "dependency_depth_including_deploy": max(depths.values()),
        "steps": rows,
    }


def artifact_digest(document):
    fields = {key: value for key, value in document.items() if key != "artifact_sha256"}
    return sha256(json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def build_artifact(document, source_bytes):
    artifact = {**document, "source_sha256": sha256(source_bytes).hexdigest()}
    if "transaction_graph" in artifact:
        artifact["plan_sha256"] = transaction_plan(artifact).digest
    return {**artifact, "artifact_sha256": artifact_digest(artifact)}


def display_build(document, args):
    if args.cpn or args.cpn_plan:
        plan = transaction_plan(document)
        if args.cpn:
            print(plan_mermaid(plan))
        else:
            sys.stdout.buffer.write(plan.encode())
    else:
        print(json.dumps(document, indent=2, sort_keys=True))


def candidate_rank(cost, order=RANK_ORDER):
    return tuple(cost[metric] for metric in order)


def select_candidate(candidates, mode):
    eligible = [name for name in CANDIDATE_ORDER if candidates[name]["eligible"]]
    selected = mode
    if mode == "auto" and eligible:
        selected = min(eligible, key=lambda name: candidate_rank(candidates[name]["cost"]))
    if selected not in eligible:
        reasons = ", ".join(f"{name}: {row['reason']}" for name, row in candidates.items() if not row["eligible"])
        raise CompileError(f"no requested transaction plan is eligible ({reasons})")
    basis = "explicit_request" if mode != "auto" else ("only_eligible_candidate" if len(eligible) == 1 else "lowest_rank")
    return selected, basis


def availability_report(data, authorizers, available_data, available_authorizers):
    return {"data": sorted(data), "authorizers": sorted(authorizers),
            "data_defaulted": available_data is None, "authorizers_defaulted": available_authorizers is None}


def candidate_evidence(contract, spec, order):
    plan = contract.plan
    program = plan.program
    words = {step.name: step.word.name for step in program.work}
    words[program.join_name] = program.join.name
    if program.gate is not None:
        words[program.gate.name] = program.gate.word.name
    cost = spec["estimated_cost"]
    return {
        "eligible": True, "static_check": "passed", "cost": cost, "boundary_reasons": plan.boundary_reasons,
        "graph": describe_graph(program, plan.templates),
        "transaction_graph": spec["transaction_graph"],
        "words": {step: {"word": words[step], **build} for step, build in spec["word_builds"].items()},
        "rank": candidate_rank(cost, order),
    }


def describe_graph(program, templates):
    return [{**asdict(step), "external_inputs": template_external_inputs(program, step)} for step in templates]


def excluded_parallel_graph(program, templates):
    graph = TransactionGraph(program.stage_graph(), ("root-lock",), templates, executable=False)
    return graph.describe(recovery=program.recovery, external_inputs=lambda step: template_external_inputs(program, step))


def compile_decision(program, keys, task_id, *, mode, available_data=None, available_authorizers=None,
                     source_bytes=None, gate_boundary="auto", **options):
    data, authorizers = availability(program, available_data, available_authorizers)
    if gate_boundary != "auto":
        schedule(program, mode, available_data=data, available_authorizers=authorizers, gate_boundary=gate_boundary)
        mode = "split"
    elif mode != "auto":
        schedule(program, mode, available_data=data, available_authorizers=authorizers)
    blockers = fusion_constraints(program, data, authorizers)
    viable, artifacts, evidence = {}, {}, {}
    for candidate in CANDIDATE_ORDER:
        if candidate == "fused" and blockers:
            evidence[candidate] = {
                "eligible": False, "static_check": "excluded",
                "reason": "fusion excluded: " + "; ".join(row["message"] for row in blockers),
                "exclusions": blockers, "graph": describe_graph(program, (fused_template(program),)),
                "transaction_graph": excluded_parallel_graph(program, (fused_template(program),)),
                "boundary_reasons": [],
            }
            continue
        plan = schedule(program, candidate, available_data=data, available_authorizers=authorizers,
                        gate_boundary=gate_boundary if candidate == "split" else "auto")
        try:
            contract = Contracts(plan, keys, task_id, **options)
            cost = estimate_cost(contract)
        except ValueError as error:
            evidence[candidate] = {
                "eligible": False, "static_check": "excluded", "reason": str(error),
                "exclusions": [{"code": "build_error", "message": str(error)}],
                "graph": describe_graph(program, plan.templates), "boundary_reasons": plan.boundary_reasons,
                "transaction_graph": excluded_parallel_graph(program, plan.templates),
            }
            continue
        spec = contract.describe(cost=cost)
        evidence[candidate] = candidate_evidence(contract, spec, RANK_ORDER)
        if source_bytes is not None:
            artifacts[candidate] = build_artifact(spec, source_bytes)
            evidence[candidate]["artifact_sha256"] = artifacts[candidate]["artifact_sha256"]
        viable[candidate] = contract
    selected, basis = select_candidate(evidence, mode)
    explanation = {
        "requested": mode, "selected": selected, "selection_basis": basis, "rank_order": RANK_ORDER,
        "tie_break_order": CANDIDATE_ORDER,
        "availability": availability_report(data, authorizers, available_data, available_authorizers),
        "candidates": evidence,
    }
    if selected in artifacts:
        explanation["selected_artifact_sha256"] = artifacts[selected]["artifact_sha256"]
    return viable, artifacts, explanation


def compile_candidates(program, keys, task_id, **options):
    viable, _, explanation = compile_decision(program, keys, task_id, **options)
    return viable[explanation["selected"]], explanation


def search_selection(candidates, objective):
    eligible = sorted(name for name, row in candidates.items() if row["eligible"])
    if not eligible:
        reasons = ", ".join(f"{name}: {row['reason']}" for name, row in candidates.items())
        raise CompileError(f"no eligible transaction plan ({reasons})")
    selected = min(eligible, key=lambda name: candidate_rank(candidates[name]["cost"], OBJECTIVES[objective]))
    return selected, "lowest_rank" if len(eligible) > 1 else "only_eligible_candidate"


def check_result_sources(plan):
    if plan.mode == "fused":
        return
    a, b = plan.program.work
    steps = {step.name: step for step in plan.templates}
    join = steps[plan.program.join_name]
    if (steps["split"].outputs != ("work", "work")
            or join.inputs != (ParentOutput(a.name, 0), ParentOutput(b.name, 0))
            or any(steps[work.name].inputs != (ParentOutput("split", slot),)
                   or steps[work.name].outputs != ("result", "data")
                   for slot, work in enumerate((a, b)))):
        raise CompileError("join must consume the two ordered results of the same split")


def compile_search(program, keys, task_id, *, source_bytes, mode="auto", gate_boundary="auto", join_witness=None,
                   objective="path-bytes", available_data=None, available_authorizers=None, **options):
    if objective not in OBJECTIVES or mode not in ("auto", "fused", "split"):
        raise CompileError("unknown search objective or schedule")
    if join_witness is not None and join_witness not in JOIN_WITNESSES:
        raise CompileError(f"unknown join witness layout {join_witness!r}")
    if gate_boundary not in GATE_BOUNDARIES or (
        gate_boundary != "auto" and (program.gate is None or mode == "fused")
    ):
        raise CompileError("an explicit gate boundary requires a gated split schedule")
    data, authorizers = availability(program, available_data, available_authorizers)
    modes = CANDIDATE_ORDER if mode == "auto" else (mode,)
    boundaries = ((None,) if program.gate is None else
                  ("merged", "separate") if gate_boundary == "auto" else (gate_boundary,))
    witnesses = JOIN_WITNESSES if join_witness is None else (join_witness,)
    viable, artifacts, candidates = {}, {}, {}
    for kind in modes:
        if kind == "fused" and gate_boundary != "auto":
            continue
        layouts = ((None, None),) if kind == "fused" else (
            (boundary, witness) for boundary in boundaries for witness in witnesses
        )
        for boundary, witness in layouts:
            name = "-".join(part for part in (kind, boundary, witness) if part is not None)
            dimensions = {"schedule": kind, "gate_boundary": boundary, "join_witness": witness}
            blockers = fusion_constraints(program, data, authorizers) if kind == "fused" else (
                gate_constraints(program, data, authorizers) if boundary == "merged" else []
            )
            templates = ((fused_template(program),) if kind == "fused" else split_templates(program, boundary == "separate"))
            if not blockers:
                plan = schedule(program, kind, available_data=data, available_authorizers=authorizers,
                                gate_boundary=boundary or "auto")
                try:
                    check_result_sources(plan)
                    contract = Contracts(plan, keys, task_id, join_witness=witness or join_witness or "full", **options)
                    spec = contract.describe()
                except ValueError as error:
                    blockers = [{"code": "build_error", "message": str(error)}]
            if blockers:
                candidates[name] = {**dimensions, "eligible": False, "static_check": "excluded", "exclusions": blockers,
                                    "reason": "; ".join(row["message"] for row in blockers),
                                    "graph": describe_graph(program, templates), "boundary_reasons": [],
                                    "transaction_graph": excluded_parallel_graph(program, templates)}
                continue
            artifact = build_artifact(spec, source_bytes)
            viable[name], artifacts[name] = contract, artifact
            candidates[name] = {**dimensions, **candidate_evidence(contract, spec, OBJECTIVES[objective]),
                                "artifact_sha256": artifact["artifact_sha256"]}
    selected, basis = search_selection(candidates, objective)
    return viable, artifacts, {
        "requested": mode, "selected": selected, "selection_basis": basis, "objective": objective,
        "selected_artifact_sha256": artifacts[selected]["artifact_sha256"],
        "objective_winners": {goal: search_selection(candidates, goal)[0] for goal in OBJECTIVES},
        "rank_order": OBJECTIVES[objective], "tie_break_order": sorted(candidates),
        "search_space": {"gate_boundary": gate_boundary, "join_witness": join_witness or "all"},
        "availability": availability_report(data, authorizers, available_data, available_authorizers),
        "candidates": candidates,
    }


def main():
    if sys.argv[1:2] == ["pels-witness"]:
        from fourthgraph.workflow.pels import witness_main
        return witness_main(sys.argv[2:])
    cli = argparse.ArgumentParser(prog=PROJECT_NAME, description=PROJECT_DESCRIPTION)
    if sys.argv[1:2] == ["experiment"]:
        from fourthgraph.benchmark.experiment import main as experiment_main
        return experiment_main(sys.argv[2:])
    cli.add_argument("source", type=Path, nargs="?")
    action = cli.add_mutually_exclusive_group()
    action.add_argument("--capabilities", action="store_true", help="list the supported Forth and BSV words")
    action.add_argument("--entry", help="compile one annotated Forth word to Script without a transaction plan")
    action.add_argument("--cpn", action="store_true", help="render the selected transaction graph as Mermaid")
    action.add_argument("--cpn-plan", action="store_true", help="emit the selected canonical transaction plan")
    cli.add_argument("--version", action="version", version=f"%(prog)s {PROJECT_VERSION}")
    cli.add_argument("--bind-bytes", metavar="NAME=HEX", action="append", default=[],
                     help="bind a declared byte parameter at compile time (repeatable)")
    cli.add_argument("--assume-input-ranges", action="store_true",
                     help="for --entry, rely on the caller to check numeric input types and ScriptNum encodings")
    cli.add_argument("--mode", choices=("auto", "split", *WORKFLOW_MODES), default="auto")
    cli.add_argument("--target", type=normalize_target, choices=TARGETS, default=DEFAULT_TARGET,
                     help="permitted transaction versions")
    cli.add_argument("--sighash-family", type=normalize_sighash_family, choices=(*SIGHASH_FAMILY_OPTIONS, "auto"),
                     default="bip143", help="preimage policy for staged workflows and PELS locks")
    cli.add_argument("--optimize", choices=OPTIMIZATIONS, default=BASELINE)
    cli.add_argument("--join-witness", choices=JOIN_WITNESSES)
    cli.add_argument("--gate-boundary", choices=GATE_BOUNDARIES, default="auto")
    cli.add_argument("--search", action="store_true", help="enumerate permitted transaction boundaries and witness layouts")
    cli.add_argument("--objective", choices=OBJECTIVES)
    cli.add_argument("--max-tx-bytes", type=int, help="maximum estimated serialized transaction size in a staged workflow")
    cli.add_argument("--explain", action="store_true", help="show the candidates and how the plan was chosen")
    cli.add_argument("--keys", type=Path, help="JSON map of role to compressed public key hex")
    cli.add_argument("--task-id", help="32-byte hex data identifier")
    cli.add_argument("--current", type=int, help="initial deployed u32 for a staged workflow")
    cli.add_argument("--available-data", nargs="*")
    cli.add_argument("--available-authorizers", nargs="*")
    args = cli.parse_args()
    if args.objective and not args.search:
        cli.error("--objective requires --search")
    if args.max_tx_bytes is not None and not args.search:
        cli.error("--max-tx-bytes requires --search")
    if args.entry and (args.search or args.gate_boundary != "auto" or args.current is not None
                       or args.mode in ("serial", "atomic")):
        cli.error("transaction search and boundaries require a transaction build")
    if args.assume_input_ranges and args.entry is None:
        cli.error("--assume-input-ranges requires --entry")
    if args.capabilities:
        print(json.dumps({"project": PROJECT_NAME, "compiler_version": PROJECT_VERSION, "description": PROJECT_DESCRIPTION,
                          **capabilities(), "libraries": library_capabilities(),
                          "optimizations": OPTIMIZATIONS, "join_witnesses": JOIN_WITNESSES,
                          "topologies": ("parallel", "gated-parallel", "workflow"), "workflow_modes": WORKFLOW_MODES,
                          "workflow_sighash_families": {**{name: f"{flag:02x}" for name, flag in SIGHASH_FAMILIES.items()},
                                                       "both": [f"{flag:02x}" for flag in SIGHASH_FAMILIES.values()]},
                          "pels_sighash_policies": (*SIGHASH_FAMILY_OPTIONS, "auto"),
                          "pels_words": tuple(PELS_WORDS),
                          "search_objectives": OBJECTIVES,
                          "gate_boundaries": GATE_BOUNDARIES, "targets": {
            name: {"transaction_versions": versions, "era": era} for name, (versions, era) in TARGETS.items()
        }}, indent=2))
        return
    if args.source is None:
        cli.error("a Forth source file is required")
    try:
        source_bytes = args.source.read_bytes()
        bindings = {}
        for binding in args.bind_bytes:
            name, separator, hexadecimal = binding.partition("=")
            if not name or not separator:
                cli.error("--bind-bytes requires NAME=HEX")
            name = name.casefold()
            if name in bindings:
                cli.error(f"duplicate byte binding {name!r}")
            try:
                bindings[name] = bytes.fromhex(hexadecimal)
            except ValueError:
                cli.error(f"byte binding {name!r} requires hexadecimal byte pairs")
        source = SourceCompiler(source_bytes.decode(), source_path=args.source, bindings=bindings)
        if args.entry is not None:
            entry = args.entry.casefold()
            word = source.words.get(entry)
            if word is None:
                raise CompileError(f"undefined entry word {args.entry!r}")
            if getattr(word, "pels", None) is not None:
                from fourthgraph.workflow.pels import compile_pels

                result = compile_pels(word.pels, args.target, args.sighash_family, explain=args.explain)
                result.update(project=PROJECT_NAME, compiler_version=PROJECT_VERSION, schema_version=1,
                              entry=word.name, libraries=tuple(map(asdict, source.library_imports)))
                display_build(build_artifact(result, source_bytes), args)
                return
            if args.sighash_family != "bip143":
                cli.error("--sighash-family requires a staged workflow or PELS lock")
            compiled = compile_word(word, args.optimize, spend_entry=True,
                                    check_input_ranges=not args.assume_input_ranges)
            result = {"project": PROJECT_NAME, "compiler_version": PROJECT_VERSION, "schema_version": 1,
                      "entry": word.name, "takes": word.takes, "gives": word.gives,
                      "enabled_optional_wordsets": source.optional_wordsets, "optimization": args.optimize,
                      "script_hex": compiled.script.hex(), **compiled.describe()}
            if source.library_imports:
                result["libraries"] = tuple(map(asdict, source.library_imports))
            if entry in source.imported_words:
                result["library_export"] = describe_export(*source.imported_words[entry])
            if word.ranges:
                result["ranges"] = {item.name: {"base": item.base, "lower": item.lower,
                                                "upper_exclusive": item.upper} for item in word.ranges}
            if any(slot.kind in NUMERIC_TYPES for slot in word.slots(word.takes)):
                result["input_range_checks"] = "assumed" if args.assume_input_ranges else "emitted"
        else:
            if args.keys is None:
                cli.error("transaction builds require --keys")
            raw_keys = json.loads(args.keys.read_text())
            if not isinstance(raw_keys, dict) or any(not isinstance(key, str) for key in raw_keys.values()):
                raise ValueError("keys must be a JSON object mapping roles to public key hex strings")
            keys = {name: bytes.fromhex(key) for name, key in raw_keys.items()}
            if source.relation:
                from fourthgraph.verification.plan import compile_solutions

                if args.current is None:
                    cli.error("relation: requires --current")
                if (args.mode != "auto" or args.cpn or args.cpn_plan or args.search or args.task_id is not None
                        or args.join_witness or args.gate_boundary != "auto" or args.sighash_family != "bip143"
                        or args.available_data is not None or args.available_authorizers is not None
                        or args.optimize != BASELINE):
                    cli.error("workflow layout options do not apply to relation: builds. "
                              "Use verification.py to select a proof backend or cost objective")
                with TemporaryDirectory(prefix="4thgraph-verification-") as scratch:
                    _, report = compile_solutions(source, keys, args.current, scratch, target=args.target)
                print(json.dumps(report, indent=2, sort_keys=True))
                return
            if source.workflow_input is not None or source.stages:
                if args.current is None:
                    cli.error("staged workflows require --current")
                if (args.task_id is not None or args.join_witness or args.gate_boundary != "auto"
                        or args.available_data is not None):
                    cli.error("staged workflows do not accept parallel workflow options")
                from fourthgraph.workflow.workflow_contract import compile_workflow

                result, report = compile_workflow(
                    source.workflow(), keys, args.current, source_bytes=source_bytes, mode=args.mode,
                    target=args.target, optimization=args.optimize, available_authorizers=args.available_authorizers,
                    search=args.search, objective=args.objective or "path-bytes", max_tx_bytes=args.max_tx_bytes,
                    sighash_family=args.sighash_family,
                )
                if args.explain:
                    result = build_artifact({**result, "schedule_explanation": report}, source_bytes)
                display_build(result, args)
                return
            if args.task_id is None or args.current is not None:
                cli.error("parallel builds require --task-id and take their u32 values at spend time")
            if args.sighash_family != "bip143":
                cli.error("Chronicle sighashes require a staged workflow")
            if args.max_tx_bytes is not None:
                cli.error("--max-tx-bytes applies to staged workflow search")
            params = dict(mode=args.mode, available_data=args.available_data, available_authorizers=args.available_authorizers,
                          target=args.target, optimization=args.optimize, gate_boundary=args.gate_boundary,
                          source_bytes=source_bytes)
            task_id = bytes.fromhex(args.task_id)
            if args.search:
                _, artifacts, explanation = compile_search(source.program(), keys, task_id,
                                                           join_witness=args.join_witness,
                                                           objective=args.objective or "path-bytes", **params)
            else:
                _, artifacts, explanation = compile_decision(source.program(), keys, task_id,
                                                             join_witness=args.join_witness or "full", **params)
            result = artifacts[explanation["selected"]]
            if args.explain:
                result = {**result, "schedule_explanation": explanation}
        if args.entry is not None or args.explain:
            result = build_artifact(result, source_bytes)
    except CompileError as error:
        cli.error(f"{args.source}: {error}")
    except (OSError, ValueError) as error:
        cli.error(str(error))
    display_build(result, args)


if __name__ == "__main__":
    main()
