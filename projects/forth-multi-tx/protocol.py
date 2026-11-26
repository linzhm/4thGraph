"""ForkID transaction templates and covenants for the two-branch program."""

import argparse
from collections.abc import Callable
from dataclasses import asdict, dataclass
import json
from pathlib import Path

from shared.pushtx import PUBLIC, binding_der
from shared.script import asm, decode_num, encode_num, number, push
from shared.transaction import FORKID, SIGHASH_ALL, Input, Output, Transaction, hash256, preimage_forkid

from compiler import PROJECT_DESCRIPTION, PROJECT_NAME, CompileError, Plan, SourceCompiler, Template, evaluate, schedule
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
RESULT_WIDTH = 5  # Four unsigned payload bytes plus a zero sign byte.
PREVOUTS_HASH = 4
CURRENT_OUTPOINT = 68
OUTPUTS_HASH = 118


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


def join_lock(code, terminals, data_prefix, versions):
    # Lock prefix pushes splitTxid above witness rawA rawB P.
    read_results = (asm("OP_2 OP_PICK OP_OVER") + proof(0, data_prefix, versions)
                    + asm("OP_TOALTSTACK OP_OVER OP_OVER") + proof(1, data_prefix, versions)
                    + asm("OP_FROMALTSTACK OP_SWAP"))
    bind_prevouts = (asm("OP_DROP OP_HASH256") + push(ZERO_INDEX) + asm("OP_CAT OP_SWAP OP_HASH256")
                     + push(ZERO_INDEX) + asm("OP_CAT OP_SWAP OP_CAT OP_HASH256") + check_field(PREVOUTS_HASH))
    return asm("OP_SWAP") + begin(versions) + read_results + code + route_check(terminals) + bind_prevouts + finish()


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
    keys: dict[str, bytes]

    @property
    def parents(self):
        return tuple(utxo.parent for utxo in self.previous)

    def signing_requests(self):
        if not self.template.authorizers:
            return ()
        utxo = self.previous[0]
        digest = hash256(preimage_forkid(self.tx, 0, utxo.output.value, utxo.output.script, FLAG))
        return tuple(SignRequest(self.template.name, utxo.outpoint, owner, self.keys[owner], FLAG, digest,
                                 self.tx, utxo.output, self.payload[0])
                     for owner in self.template.authorizers)

    def seal(self, sign: Callable[[SignRequest], bytes]):
        # The external callback returns DER. Append the required sighash in the runner.
        signatures = tuple(sign(request) + bytes([request.sighash]) for request in self.signing_requests())
        tx = self.tx
        for i, (utxo, fields) in enumerate(zip(self.previous, self.payload, strict=True)):
            preimage = preimage_forkid(self.tx, i, utxo.output.value, BINDING_CODE, FLAG)
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
    def __init__(self, plan: Plan, keys, task_id, *, target=DEFAULT_TARGET, optimization=BASELINE):
        if target not in TARGETS:
            raise ValueError(f"unknown compilation target {target!r}")
        self.target = target
        self.optimization = optimization
        self.versions, self.era = TARGETS[target]
        self.version = self.versions[-1]
        if len(task_id) != 32:
            raise ValueError("task id must be 32 bytes")
        required = {name for step in plan.templates for name in step.authorizers} | {"settle", "review"}
        if any(name not in keys or len(keys[name]) != 33 or keys[name][0] not in (2, 3) for name in required):
            raise ValueError("each required role needs a compressed secp256k1 public key")
        self.plan = plan
        self.keys = dict(keys)
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
        if plan.mode == "fused":
            # Entry x y sigB sigA P. Both values remain in the same Script stack.
            code = (begin(self.versions) + single_input() + authorize(keys[a.owner]) + authorize(keys[b.owner])
                    + validate_u32() + asm("OP_SWAP") + validate_u32() + self.words[a.name].script
                    + asm("OP_SWAP") + self.words[b.name].script + select_route + route_check(self.terminals) + finish())
        else:
            self.join_code = join_lock(select_route, self.terminals, self.data_prefix, self.versions)
            self.work_outputs = tuple(
                Output(WORK_VALUE, work_lock(i, self.words[step.name].script, keys[step.owner], self.join_code,
                                             self.data_prefix, self.versions))
                for i, step in enumerate(plan.program.work)
            )
            code = (begin(self.versions) + single_input() + authorize(keys[plan.program.operator])
                    + push(output_hash(self.work_outputs)) + check_field(OUTPUTS_HASH) + finish())
        self.root = Output(ROOT_VALUE, code)

    def describe(self):
        def describe_output(output):
            return {"satoshis": output.value, "script_hex": output.script.hex()}

        spec = {
            "project": PROJECT_NAME,
            "target": self.target,
            "optimization": self.optimization,
            "word_builds": {name: word.describe() for name, word in self.words.items()},
            "era": self.era,
            "transaction_version": self.version,
            "supported_transaction_versions": self.versions,
            "sighash": f"{FLAG:02x}",
            "enabled_optional_wordsets": self.plan.program.optional_wordsets,
            "schedule": self.plan.mode,
            "fusion_blockers": self.plan.fusion_blockers,
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
        return spec

    def result_output(self, split):
        return Output(RESULT_VALUE, push(split.txid_wire()) + self.join_code)

    def data_output(self, value):
        encoded = encode_num(value).ljust(RESULT_WIDTH, b"\0")
        return Output(0, self.data_script_prefix + encoded)

    def result_value(self, parent):
        encoded = parent.outputs[1].serialize()
        if len(encoded) != len(self.data_prefix) + RESULT_WIDTH or not encoded.startswith(self.data_prefix):
            raise ValueError("incorrect result data output")
        return decode_num(encoded[-RESULT_WIDTH:])

    def prepare(self, name, completed, data=None, *, version=None):
        version = self.version if version is None else version
        if type(version) is not int or version not in self.versions:
            raise ValueError(f"transaction version {version} is unavailable for target {self.target}")
        template = self.templates[name]
        previous = tuple(UTXO(completed[ref.step], ref.vout) for ref in template.inputs)
        inputs = tuple(Input(utxo.outpoint.txid, utxo.outpoint.vout) for utxo in previous)
        a, b = self.plan.program.work
        if name == "fused":
            x, y = input_value(data, a.input), input_value(data, b.input)
            result_a, = evaluate(a.word, x)
            result_b, = evaluate(b.word, y)
            route, = evaluate(self.plan.program.join, result_a, result_b)
            outputs, payload = (self.terminals[route],), ((encode_num(x), encode_num(y)),)
        elif name == "split":
            outputs, payload = self.work_outputs, ((),)
        elif name == self.plan.program.join_name:
            parents = tuple(utxo.parent for utxo in previous)
            route, = evaluate(self.plan.program.join, *(self.result_value(parent) for parent in parents))
            outputs, payload = (self.terminals[route],), (tuple(parent.serialize() for parent in parents),) * 2
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


def main():
    cli = argparse.ArgumentParser(prog=PROJECT_NAME, description=PROJECT_DESCRIPTION)
    cli.add_argument("source", type=Path, nargs="?")
    action = cli.add_mutually_exclusive_group()
    action.add_argument("--capabilities", action="store_true", help="list the supported Forth and BSV words")
    action.add_argument("--entry", help="compile one annotated Forth word to Script without a transaction plan")
    cli.add_argument("--mode", choices=("auto", "fused", "split"), default="auto")
    cli.add_argument("--target", choices=TARGETS, default=DEFAULT_TARGET, help="permitted transaction versions")
    cli.add_argument("--optimize", choices=OPTIMIZATIONS, default=BASELINE)
    cli.add_argument("--keys", type=Path, help="JSON map of role to compressed public key hex")
    cli.add_argument("--task-id", help="32-byte hex data identifier")
    cli.add_argument("--available-data", nargs="*")
    cli.add_argument("--available-authorizers", nargs="*")
    args = cli.parse_args()
    if args.capabilities:
        print(json.dumps({"project": PROJECT_NAME, "description": PROJECT_DESCRIPTION, **capabilities(), "targets": {
            name: {"transaction_versions": versions, "era": era} for name, (versions, era) in TARGETS.items()
        }}, indent=2))
        return
    if args.source is None:
        cli.error("a Forth source file is required")
    if args.entry is None and (args.keys is None or args.task_id is None):
        cli.error("transaction builds require --keys and --task-id")
    try:
        source = SourceCompiler(args.source.read_text())
        if args.entry is not None:
            word = source.words.get(args.entry.casefold())
            if word is None:
                raise CompileError(f"undefined entry word {args.entry!r}")
            compiled = compile_word(word, args.optimize)
            result = {"project": PROJECT_NAME, "entry": args.entry, "takes": word.takes, "gives": word.gives,
                      "enabled_optional_wordsets": source.optional_wordsets, "optimization": args.optimize,
                      "script_hex": compiled.script.hex(), **compiled.describe()}
        else:
            plan = schedule(source.program(), args.mode, available_data=args.available_data,
                            available_authorizers=args.available_authorizers)
            keys = {name: bytes.fromhex(key) for name, key in json.loads(args.keys.read_text()).items()}
            result = Contracts(plan, keys, bytes.fromhex(args.task_id), target=args.target,
                               optimization=args.optimize).describe()
    except CompileError as error:
        cli.error(f"{args.source}: {error}")
    except (OSError, ValueError) as error:
        cli.error(str(error))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
