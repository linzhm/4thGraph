"""Build and spend a continuing counter whose covenant preserves its own Script."""

import argparse
from dataclasses import asdict, dataclass, replace
import json
import os
from pathlib import Path
from types import SimpleNamespace

from fourthgraph.compiler.source import CompileError, ParentOutput, Template, evaluate
from fourthgraph.workflow.forkid_lowering import RECONSTRUCTED_FIELDS, ScriptCodeReuse, pack_context, reconstructed_context, repeated_fragment
from fourthgraph.compiler.lowering import compile_word
from fourthgraph.compiler.pels_constraints import DEFAULT_FEE, FeeConstraint, PelsSource, WitnessAmount
from fourthgraph.workflow.protocol import CURRENT_OUTPOINT, FLAG, FLAG_BYTES, PREVOUTS_HASH, ROOT_VALUE, UTXO, field
from fourthgraph.benchmark.validation import CONTEXT_PIN, Node, chain_metadata
from fourthgraph.bsv.pushtx import fixed_key_checksig_parts
from fourthgraph.bsv.script import asm, number, push
from fourthgraph.bsv.transaction import Input, Output, Transaction, blob, compact as compact_size, preimage_forkid
from fourthgraph.compiler.wordsets import U32


SOURCE = Path(__file__).with_name("pels-counter.fth")
STATE_BYTES = 5
FEE = DEFAULT_FEE.minimum
EXAMPLE_FEES = (1_237, 2_311)
VERSION = 2
SEPARATOR = asm("OP_CODESEPARATOR")
TRANSITION = Template("advance", (ParentOutput("counter", 0),), (), ("counter",), ("advance",))
AUTHENTICATIONS = ("baseline", "compact", "compact-reuse-r")
FULL_PREIMAGE, RECONSTRUCTED, LINKED = "full-preimage", "reconstructed", "linked-script-size"
REUSED = "reused-script-fragment"
STATE_PREFIX_BYTES = 1 + STATE_BYTES + len(SEPARATOR)


def successor_hash(advance, *, script_size=None):
    # Input: counter, next amount as eight bytes, raw scriptCode.
    if script_size is None:
        length = (asm("OP_SIZE") + number(STATE_PREFIX_BYTES) + asm("OP_ADD OP_2 OP_NUM2BIN")
                  + push(b"\xfd") + asm("OP_SWAP OP_CAT"))
    else:
        length = push(compact_size(script_size + STATE_PREFIX_BYTES))
    prefix = length + asm("OP_ROT OP_SWAP OP_CAT") + number(STATE_BYTES) + asm("OP_CAT")
    return (prefix + asm("OP_ROT OP_BIN2NUM") + advance + number(STATE_BYTES)
            + asm("OP_NUM2BIN OP_CAT") + push(SEPARATOR) + asm("OP_CAT OP_SWAP OP_CAT OP_HASH256"))


def authentication_parts(authentication):
    return (asm("OP_HASH256"), *fixed_key_checksig_parts(
        FLAG, compact=authentication != "baseline", reuse_r=authentication == "compact-reuse-r",
    ))


def covenant(advance, *, authentication="baseline", context=None, decoder=b"", amount_rule=DEFAULT_FEE):
    depth = 3 if amount_rule.takes_witness else 2
    start = asm("OP_DEPTH") + number(depth) + asm("OP_NUMEQUALVERIFY OP_SWAP")
    authenticate = b"".join(authentication_parts(authentication))
    if context is not None:
        return start + decoder + context + authenticate

    start += asm("OP_DUP OP_TOALTSTACK")
    one_input = (asm("OP_DUP") + field(CURRENT_OUTPOINT, 36) + asm("OP_HASH256 OP_OVER")
                 + field(PREVOUTS_HASH, 32) + asm("OP_EQUALVERIFY"))
    # The final 52 bytes contain amount, sequence, hashOutputs, locktime and sighash.
    tail = (asm("OP_SIZE") + number(52) + asm("OP_SUB OP_SPLIT OP_DUP") + field(48, 4)
            + push(FLAG_BYTES) + asm("OP_EQUALVERIFY OP_DUP") + field(12, 32) + asm("OP_TOALTSTACK")
            + field(0, 8))
    # Strip the ForkID header and the CompactSize from the authenticated scriptCode.
    script_code = asm("OP_SWAP") + number(104) + asm("OP_SPLIT OP_NIP OP_3 OP_SPLIT OP_NIP")
    return (start + one_input + tail + amount_rule.lower_amount() + script_code + successor_hash(advance)
            + asm("OP_FROMALTSTACK OP_EQUALVERIFY OP_FROMALTSTACK") + authenticate)


def counter_output(code, value, satoshis):
    return Output(satoshis, push(value.to_bytes(STATE_BYTES, "little")) + SEPARATOR + code)


def push_witness(context, prefix):
    return prefix + push(context)


def spend(parent, code, output, *, witness=FULL_PREIMAGE, reuse=None, amount_rule=DEFAULT_FEE):
    tx = Transaction((Input(parent.txid_wire(), 0),), (output,), version=VERSION)
    preimage = preimage_forkid(tx, 0, parent.outputs[0].value, code, FLAG)
    if witness != FULL_PREIMAGE:
        script_size = len(code) if witness in (LINKED, REUSED) else None
        preimage = pack_context(preimage, script_size=script_size, reuse=reuse)
    prefix = amount_rule.witness_prefix(parent.outputs[0].value, output.value)
    return tx.with_script(0, push_witness(preimage, prefix))


@dataclass(frozen=True)
class CounterBuild:
    code: bytes
    authentication: str
    witness: str
    reuse: ScriptCodeReuse | None = None
    amount_rule: FeeConstraint | WitnessAmount = DEFAULT_FEE

    @property
    def root(self):
        return counter_output(self.code, 0, ROOT_VALUE)

    def spend(self, parent, output):
        return spend(parent, self.code, output, witness=self.witness, reuse=self.reuse, amount_rule=self.amount_rule)

    def describe(self):
        root = self.root
        parent = Transaction((), (root,), version=VERSION)
        fee = self.amount_rule.minimum if isinstance(self.amount_rule, FeeConstraint) else EXAMPLE_FEES[0]
        tx = self.spend(parent, counter_output(self.code, 1, ROOT_VALUE - fee))
        rewrites = []
        omitted = ()
        if self.authentication != "baseline":
            rewrites.extend(("fixed-width-byte-reversal", "reuse-secp256k1-order"))
        if self.authentication == "compact-reuse-r":
            rewrites.append("reuse-fixed-der-r-in-public-key")
        if self.witness != FULL_PREIMAGE:
            rewrites.append("reconstruct-forkid-all")
            omitted = RECONSTRUCTED_FIELDS
        if self.witness in (LINKED, REUSED):
            rewrites.append("link-script-code-size")
            omitted += ("scriptCodeLength",)
        if self.reuse is not None:
            rewrites.append("reuse-self-script-fragment")
        row = {
            "pushtx": self.authentication,
            "witness": self.witness,
            "reconstructed_fields": omitted,
            "rewrites": rewrites,
            "lock_bytes": len(root.script),
            "witness_bytes": len(tx.inputs[0].script),
            "spend_bytes": len(tx.serialize()),
            "path_bytes": len(blob(root.script)) + len(tx.serialize()),
        }
        if self.reuse is not None:
            row["script_code_reuse"] = asdict(self.reuse)
        return row


def linked_covenant(advance, authentication, amount_rule, *, size=253, repeated=None):
    suffix_size = sum(map(len, authentication_parts(authentication)))
    # Link both the script size and any immutable offsets of repeated code.
    for _ in range(3):
        reuse = repeated.after_prefix(size - suffix_size) if repeated is not None else None
        decoder = reuse.decoder() if reuse is not None else b""
        output_hash = amount_rule.lower_amount() + asm("OP_SWAP") + successor_hash(advance, script_size=size)
        context = reconstructed_context(TRANSITION, FLAG, output_hash, script_size=size)
        linked = covenant(advance, authentication=authentication, context=context, decoder=decoder, amount_rule=amount_rule)
        if len(linked) == size:
            if reuse is None or (linked[reuse.source:reuse.source + reuse.size]
                                 == linked[reuse.repeated:reuse.repeated + reuse.size]):
                return linked, reuse
            break
        size = len(linked)
        if not 253 <= size <= 32767 - STATE_PREFIX_BYTES:
            break
    return None


def counter_builds(advance, amount_rule=DEFAULT_FEE):
    if (advance.takes, advance.gives) != (("u32",), ("u32",)):
        raise ValueError("counter advance must have the stack effect u32 -- u32")
    compiled = compile_word(advance, "safe")
    output_hash = amount_rule.lower_amount() + asm("OP_SWAP OP_3 OP_SPLIT OP_NIP") + successor_hash(compiled.script)
    context = reconstructed_context(TRANSITION, FLAG, output_hash)
    builds = []
    for authentication in AUTHENTICATIONS:
        builds.append(CounterBuild(covenant(compiled.script, authentication=authentication, amount_rule=amount_rule),
                                   authentication, FULL_PREIMAGE, amount_rule=amount_rule))
        if context is not None:
            code = covenant(compiled.script, authentication=authentication, context=context, amount_rule=amount_rule)
            builds.append(CounterBuild(code, authentication, RECONSTRUCTED, amount_rule=amount_rule))
            linked = linked_covenant(compiled.script, authentication, amount_rule)
            if linked is not None:
                code, _ = linked
                builds.append(CounterBuild(code, authentication, LINKED, amount_rule=amount_rule))
                repeated = repeated_fragment(authentication_parts(authentication))
                if repeated is not None:
                    linked = linked_covenant(compiled.script, authentication, amount_rule, size=len(code), repeated=repeated)
                    if linked is not None:
                        code, reuse = linked
                        builds.append(CounterBuild(code, authentication, REUSED, reuse, amount_rule))
    return compiled, tuple(builds)


def next_counter(parent, code, advance, *, fee=FEE, successor_amount=None):
    if not parent.outputs:
        raise ValueError("the parent has no output 0")
    output = parent.outputs[0]
    current = int.from_bytes(output.script[1:1 + STATE_BYTES], "little")
    if current >= U32 or output != counter_output(code, current, output.value):
        raise ValueError("parent output 0 does not match this counter")
    if successor_amount is None:
        if output.value <= fee:
            raise ValueError("parent output 0 cannot pay another counter fee")
        successor_amount = output.value - fee
    if not 0 <= successor_amount <= output.value:
        raise ValueError("successor amount must be between zero and the previous output amount")
    value, = evaluate(advance, current)
    return current, value, counter_output(code, value, successor_amount)


def replay_build(replay, bootstrap, slot, build, advance):
    code = build.code
    parent, deployment = replay.deploy(SimpleNamespace(root=build.root, version=VERSION), bootstrap, slot)
    fee_rule = build.amount_rule if isinstance(build.amount_rule, FeeConstraint) else None
    fixture_fees = (fee_rule.minimum, fee_rule.maximum) if fee_rule is not None else EXAMPLE_FEES
    steps = []
    for requested_fee in fixture_fees:
        previous = (UTXO(parent, 0),)
        old_amount = parent.outputs[0].value
        fee = min(requested_fee, old_amount - 1)
        if fee_rule is not None:
            fee_rule.require(fee)
        _, value, successor = next_counter(parent, code, advance, fee=fee)
        tx = build.spend(parent, successor)
        prefix = build.amount_rule.witness_prefix(old_amount, successor.value)
        wrong_counter = counter_output(code, (value + 1) % U32, successor.value)
        wrong_script = replace(successor, script=successor.script + asm("OP_NOP"))
        wrong_amount = replace(successor, value=successor.value - 1)
        extra_output = Output(0, asm("OP_0 OP_RETURN"))
        controls = {
            "wrong_counter": build.spend(parent, wrong_counter),
            "changed_script": build.spend(parent, wrong_script),
            "wrong_amount": (replace(tx, outputs=(wrong_amount,)) if build.amount_rule.takes_witness
                             else build.spend(parent, wrong_amount)),
            "changed_locktime": replace(tx, locktime=1),
            "extra_output": replace(tx, outputs=(successor, extra_output)),
        }
        if fee_rule is not None and fee_rule.takes_witness:
            context_script = tx.inputs[0].script[len(prefix):]
            controls["fee_below_minimum"] = tx.with_script(0, number(fee_rule.minimum - 1) + context_script)
            controls["fee_above_maximum"] = tx.with_script(0, number(fee_rule.maximum + 1) + context_script)
        elif fee_rule is not None and build.witness == FULL_PREIMAGE:
            controls["stale_preimage"] = replace(tx, outputs=(wrong_amount,))
        if build.witness in (LINKED, REUSED):
            preimage = preimage_forkid(tx, 0, parent.outputs[0].value, code, FLAG)
            context = pack_context(preimage, script_size=len(code), reuse=build.reuse)
            controls["extra_context_byte"] = tx.with_script(0, push_witness(context + b"\0", prefix))
        if build.reuse is not None:
            # Make the fake successor agree with both copies of the changed fragment.
            # Native authentication must still match the scriptCode of the actual input.
            fake_code = bytearray(code)
            fake_code[build.reuse.source] ^= 1
            fake_code[build.reuse.repeated] ^= 1
            fake_code = bytes(fake_code)
            replacement = counter_output(fake_code, value, successor.value)
            changed = replace(tx, outputs=(replacement,))
            preimage = preimage_forkid(changed, 0, parent.outputs[0].value, fake_code, FLAG)
            context = pack_context(preimage, script_size=len(code), reuse=build.reuse)
            controls["forged_preserved_code"] = changed.with_script(0, push_witness(context, prefix))
        rejected = {name: replay.record(candidate, previous, expected=False) for name, candidate in controls.items()}
        steps.append({"counter": value, "satoshis": successor.value, "fee_satoshis": fee,
                      "accepted": replay.record(tx, previous), "rejected": rejected})
        parent = tx
    return {**build.describe(), "deployment": deployment, "steps": steps}


def replay_counter(output_path, selected, builds, advance, compiled, decision):
    from fourthgraph.replay.workflow import Replay

    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError("use the pinned Chronicle-aware chain-gang build")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    if node.call("getblockcount", []) or node.call("getconnectioncount", []):
        raise ValueError("use a fresh peerless regtest")
    replay = Replay(node, 1, "chronicle-v2", int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"]))
    bootstrap = replay.fund(len(builds))
    results = [replay_build(replay, bootstrap, slot, build, advance) for slot, build in enumerate(builds)]
    report = {"advance_hex": compiled.script.hex(), "optimization": decision, **results[builds.index(selected)]}
    if len(results) > 1:
        report["comparison"] = results
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE, help="Forth source for the counter and its fee rule")
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("build", help="compile and print the counter-zero lock")
    spending = actions.add_parser("spend", help="build the next spend from a raw parent transaction")
    spending.add_argument("--parent", type=bytes.fromhex, required=True)
    value = spending.add_mutually_exclusive_group()
    value.add_argument("--fee", type=int, help="fee for a fee-constrained source, defaults to its minimum")
    value.add_argument("--amount", type=int, help="successor amount for a source that takes it from the witness")
    replay = actions.add_parser("replay", help="fund, spend twice, and verify on regtest")
    replay.add_argument("--output", type=Path, required=True)
    replay.add_argument("--compare", action="store_true", help="replay every eligible compiler candidate")
    args = parser.parse_args()

    try:
        source = PelsSource(args.source.read_text(), source_path=args.source)
        advance = source.words.get("advance")
        if advance is None:
            raise ValueError("the counter source must define advance")
        amount_rule = source.amount_rule
        fee_rule = amount_rule if isinstance(amount_rule, FeeConstraint) else None
        if fee_rule is not None and fee_rule.minimum >= ROOT_VALUE:
            raise ValueError("the fee minimum must leave a positive successor in a counter-zero deployment")
        compiled, builds = counter_builds(advance, amount_rule)
    except (CompileError, OSError, ValueError) as error:
        parser.error(str(error))
    eligible = tuple(build for build in builds if 253 <= len(build.code) <= 32767 - STATE_PREFIX_BYTES)
    if not eligible:
        parser.error("no candidate fits the counter's three-byte CompactSize and positive two-byte ScriptNum")
    costs = tuple(build.describe() for build in eligible)
    winner = min(range(len(eligible)), key=lambda index: (costs[index]["path_bytes"], costs[index]["lock_bytes"]))
    selected = eligible[winner]
    assertions = {"counter": "advance", "preserve_script_code": True}
    if fee_rule is None:
        assertions["successor_amount"] = "witness"
    else:
        assertions["fee_satoshis"] = {**asdict(fee_rule), "from_witness": fee_rule.takes_witness}
    decision = {
        "objective": "path-bytes",
        "scope": "serialized_deployment_lock_field_plus_first_spend",
        "template": {"inputs": len(TRANSITION.inputs), "outputs": TRANSITION.outputs,
                     "sighash": f"{FLAG:02x}", "successor_assertions": assertions},
        "advance": compiled.describe(),
        "selected_candidate": winner,
        "candidates": costs,
    }
    if args.action == "build":
        root = selected.root
        result = {"counter": 0, "satoshis": root.value, "advance_hex": compiled.script.hex(),
                  "script_bytes": len(root.script), "script_hex": root.script.hex(), "optimization": decision}
        if fee_rule is not None:
            result["fee_satoshis"] = fee_rule.minimum
    elif args.action == "spend":
        try:
            parent = Transaction.parse(args.parent)
            if not parent.outputs:
                raise ValueError("the parent has no output 0")
            code = parent.outputs[0].script[STATE_PREFIX_BYTES:]
            build = next((build for build in eligible if build.code == code), None)
            if build is None:
                raise ValueError("parent output 0 does not match any compiled counter layout")
            if fee_rule is None:
                if args.amount is None:
                    raise ValueError("provide --amount for the successor specified by the witness")
                current, value, successor = next_counter(parent, build.code, advance, successor_amount=args.amount)
            else:
                if args.amount is not None:
                    raise ValueError("provide --fee for a fee-constrained counter")
                fee = fee_rule.require(fee_rule.minimum if args.fee is None else args.fee)
                current, value, successor = next_counter(parent, build.code, advance, fee=fee)
        except ValueError as error:
            parser.error(str(error))
        tx = build.spend(parent, successor)
        fee = parent.outputs[0].value - successor.value
        result = {"from": current, "to": value, "satoshis": successor.value, "fee_satoshis": fee,
                  "txid": tx.txid(), "transaction_hex": tx.serialize().hex()}
    else:
        replay_counter(args.output, selected, eligible if args.compare else (selected,), advance, compiled, decision)
        return
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
