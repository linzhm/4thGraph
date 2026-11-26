"""Compare scryptc-lowered P-256 kernels in the same P2PKH-R1 payment template."""

import argparse
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
from random import Random
import subprocess
from tempfile import TemporaryDirectory

from tx_engine import Tx

from assemble import assemble
from curve_compiler import B3, FIELD, curve_blocks
from fixed_templates import compiled_template, otda_pattern
from reconstruct import shared_kernel_program
from signature import (COMPRESSIBLE_OTDA_TYPES, GROUP_ORDER_R1, PAIRED_OTDA_SINGLE_TYPES, UNIVERSAL_FLAGS,
                       authorization, current_input_unlock)
from test_payment import fixture_signature, signer
from shared.benchmark import collect, dump_json
from shared.benchmark_cases import Coin, Template, seed, synthetic_parent
from shared.benchmark_validation import CORE_PIN, Node, chain_metadata, chain_verdict
from shared.evaluate import evaluate
from shared.otda_reconstruction import Reconstruction
from shared.script import asm, decode_num, encode_num, push
from shared.transaction import Input, Output, Transaction

COMPILER_SHA256 = "e5e8fa95f0bf4a3ea809dd74b7dcac5b4dbb3a0edb458b469ec1a7dfbb04c4fa"
MARKER = "5b92be8a562533373534b153118deadf"
EMITTER = '''import "projective.scrypt";
contract EmitKernel {{
    static function mark(Point result) : bool {{
        asm {{ {marker} OP_DROP OP_2DROP OP_DROP OP_1 }}
    }}
    public function emit({args}) {{
        require(mark({expression}));
    }}
}}
'''


def compile_kernel(compiler, work, name, args, expression, arg_copy, cleanup):
    source = work / f"{name}.scrypt"
    source.write_text(EMITTER.format(marker=MARKER, args=args, expression=expression), encoding="ascii")
    subprocess.run([str(compiler), "compile", "--asm", "-O", "-o", str(work), str(source)],
                   check=True, stdout=subprocess.PIPE)
    artifact = json.loads((work / f"{name}_asm.json").read_text(encoding="utf-8"))
    tokens = [row["opcode"] for row in artifact["output"]]
    split = tokens.index(MARKER)
    # The ABI duplicates the public arguments and later drops the originals.
    # The caller supplies those arguments directly and consumes them in place.
    expected_tail = [MARKER, "OP_DROP", "OP_2DROP", "OP_DROP", "OP_1", "OP_TOALTSTACK",
                     *["OP_2DROP"] * cleanup, "OP_FROMALTSTACK"]
    if (tokens.count(MARKER) != 1 or tokens[:len(arg_copy)] != arg_copy or tokens[split:] != expected_tail):
        raise ValueError(f"unexpected scryptc kernel ABI for {name}")
    return b"".join(asm(token) if token.startswith("OP_") else push(bytes.fromhex(token))
                    for token in tokens[len(arg_copy):split])


def scrypt_kernels(compiler, work):
    source = Path(__file__).with_name("comparison") / "projective.scrypt"
    (work / source.name).write_bytes(source.read_bytes())
    add = compile_kernel(compiler, work, "add", "Point p, Point q, int field, int b3",
                         "P256.add(p, q, field, b3)", ["OP_7", "OP_PICK"] * 8, 4)
    double = compile_kernel(compiler, work, "double", "Point p, int field", "P256.double(p, field)",
                            ["OP_2OVER", "OP_2OVER"], 2)
    return {
        "ADD_POINTS": asm("OP_DEPTH OP_1SUB OP_PICK OP_DEPTH 2 OP_SUB OP_PICK") + add,
        "DOUBLE_POINT": (asm("OP_DUP OP_0NOTEQUAL OP_IF OP_DEPTH OP_1SUB OP_PICK")
                         + double + asm("OP_ENDIF")),
    }


def check_kernels(reference, candidate):
    rng = Random(256)
    boundaries = (0, 1, -1, FIELD - 1, 1 - FIELD)
    count = 0
    for name, arity in (("ADD_POINTS", 6), ("DOUBLE_POINT", 3)):
        vectors = [tuple([a, b] * arity)[:arity] for a in boundaries for b in boundaries]
        vectors.extend(tuple(rng.randrange(1 - FIELD, FIELD) for _ in range(arity)) for _ in range(200))
        prefix = list(map(encode_num, (FIELD, B3, -100, 77)))
        for index, point in enumerate(vectors):
            start = prefix + list(map(encode_num, point))
            expected, _ = evaluate(reference[name], start)
            actual, alt = evaluate(candidate[name], start)
            if (actual[:len(prefix)] != prefix or len(actual) != len(prefix) + 3 or alt
                    or any(abs(decode_num(value)) >= FIELD for value in actual[len(prefix):])
                    or [decode_num(x) % FIELD for x in actual[len(prefix):]]
                    != [decode_num(x) % FIELD for x in expected[len(prefix):]]):
                raise ValueError(f"{name} stack or field mismatch on vector {index}")
        count += len(vectors)
    return count


def payment_template(lock, reconstruction):
    def coin(label, value):
        scalar = 1 + int.from_bytes(seed(label), "big") % (GROUP_ORDER_R1 - 1)
        private, public, owner = signer(scalar)

        def unlock(tx, index, parent, flag, _scratch):
            amount = parent.outputs[tx.inputs[index].vout].value
            auth = authorization(Tx.parse(tx.serialize()), index, amount, flag)
            signed = fixture_signature(private, auth.digest())
            witness = current_input_unlock(auth, public, signed).raw_serialize()
            literal = push(auth.preimage)
            if tx.version == 2 and not auth.companion:
                if flag in COMPRESSIBLE_OTDA_TYPES:
                    selected = tx.outputs
                elif flag in PAIRED_OTDA_SINGLE_TYPES:
                    selected = (tx.outputs[index],)
                else:
                    selected = ()
                program = reconstruction.build(auth.preimage, selected) if selected else None
                if program is not None and len(program) < len(literal):
                    if not witness.startswith(literal):
                        raise ValueError("unexpected reference witness layout")
                    witness = program + witness[len(literal):]
            return tx.with_script(index, witness)

        return Coin(Output(value, lock(owner)), unlock)

    return Template(coin)


def check_payments(node, template, scratch):
    coins = tuple(template.create(f"matrix/input/{i}", 10_000) for i in range(2))
    parents = tuple(synthetic_parent(f"matrix/parent/{i}", coin) for i, coin in enumerate(coins))
    inputs = tuple(Input(parent.txid_wire(), 0, sequence=0xfffffffe) for parent in parents)
    outputs = tuple(template.create(f"matrix/output/{i}", 9900).output for i in range(2))
    shapes = [(mode, outputs) for mode in sorted(UNIVERSAL_FLAGS)]
    shapes.extend((mode, outputs[:1]) for mode in sorted(UNIVERSAL_FLAGS) if mode & 31 == 3)
    count = 0
    for version in (1, 2):
        for mode, destinations in shapes:
            tx = Transaction(inputs, destinations, version=version)
            for index, coin in enumerate(coins):
                tx = coin.unlock(tx, index, parents[index], mode, scratch)
            changed = replace(tx, outputs=(replace(destinations[0], value=9899), *destinations[1:]))
            expected = {1: [False, False], 2: [True, True], 3: [False, True]}[mode & 31]
            for case, verdict in ((tx, [True, True]), (replace(tx, locktime=1), [False, False]), (changed, expected)):
                if chain_verdict(case, parents) != all(verdict) or node.verdicts(case, parents) != verdict:
                    raise ValueError(f"payment semantics differ for version {version}, sighash {mode:02x}, "
                                     f"{len(destinations)} outputs")
                count += 1
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=15)
    args = parser.parse_args()
    if args.samples < 0:
        parser.error("sample count must be nonnegative")
    compiler = args.compiler.resolve()
    if sha256(compiler.read_bytes()).hexdigest() != COMPILER_SHA256:
        parser.error("expected the pinned Linux x86-64 scryptc 1.20.0 compiler")
    metadata = chain_metadata()
    if metadata["commit"] != CORE_PIN:
        parser.error("install the pinned chain-gang revision from the project requirements")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    with TemporaryDirectory(prefix="r1-scrypt-") as temp:
        scratch = Path(temp)
        reference = curve_blocks(scheduled=True)
        candidate = {**reference, **scrypt_kernels(compiler, scratch)}
        kernel_cases = check_kernels(reference, candidate)
        marker = bytes(range(20))
        prefix, suffix = assemble(marker, compiled_curve=True, injected=candidate).split(marker)
        program = shared_kernel_program(prefix, suffix, injected=candidate)
        patterns = {
            "script_lab": (compiled_template(scheduled=True).lock, otda_pattern(scheduled=True)[1], reference),
            "scrypt_kernels": (lambda owner: prefix + owner + suffix,
                               Reconstruction(program, (prefix, suffix), (20,)), candidate),
        }
        result = {"compiler_sha256": COMPILER_SHA256, "chain_gang": metadata, "kernel_cases": kernel_cases,
                  "samples": args.samples, "implementations": {}}
        for name, (lock, reconstruction, kernels) in patterns.items():
            template = payment_template(lock, reconstruction)
            raw = lock(bytes(20))
            measured_kernels = ("ADD_POINTS", "DOUBLE_POINT")
            result["implementations"][name] = {
                "lock_bytes": len(raw),
                "lock_sha256": sha256(raw).hexdigest(),
                "constructor_bytes": len(reconstruction.program),
                "kernel_bytes": {block: len(kernels[block]) for block in measured_kernels},
                "kernel_copies": {block: raw.count(kernels[block]) for block in measured_kernels},
                "acceptance_transactions": check_payments(node, template, scratch),
                **collect(template, "r1", scratch, node, args.samples, profile_stack=True),
            }
    dump_json(args.output, result)


if __name__ == "__main__":
    main()
