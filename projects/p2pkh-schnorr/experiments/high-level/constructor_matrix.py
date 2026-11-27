"""Compare constructor selection across concrete Schnorr and P2PKH transactions."""
import argparse
from collections import Counter
from dataclasses import dataclass, replace
from hashlib import sha256
import json
import os
from pathlib import Path

from coincurve import PrivateKey

from compare import compile_candidate, plans
from bip340 import ORDER, lift_x, to_bytes
from payment import WITNESS_TAIL_BYTES
from schnorr_script import (TEMPLATE_DIRS, TEMPLATE_VERSION, authorization_codes, compile_reconstructed_unlock,
                            compile_unlock, compiled_template, lock_for_owner, output_reconstruction, owner_hash,
                            reconstruction_for_version)
from fourthgraph.benchmark.cases import allocations, native_coin, seed
from fourthgraph.benchmark.validation import CONTEXT_PIN, Node, chain_metadata
from fourthgraph.bsv.chain_gang import validate_at_heights
from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.otda_reconstruction import shorter_reconstruction
from fourthgraph.bsv.spend_authorization import prepare_authorization
from fourthgraph.bsv.transaction import (
    ANYONECANPAY, CHRONICLE, SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_TYPES,
    Input, Output, Transaction,
)
from fourthgraph.compiler.preimage import compile_preimage


CURRENT, PREVIOUS, EARLY = TEMPLATE_VERSION, "v0.16.0", "v0.6.0"
NATIVE, AUTO = "native-p2pkh", "compiler-auto"


@dataclass(frozen=True)
class Case:
    label: str
    sources: tuple[str, ...]
    recipients: tuple[str, ...]
    flags: tuple[int, ...]
    version: int = 2
    active: bool = True
    older_funding: bool = False


def cases():
    shapes = (
        ("native-exit", (CURRENT,), (NATIVE,)),
        ("rollover", (CURRENT,), (CURRENT,)),
        ("payment-and-change", (CURRENT,), (NATIVE, CURRENT)),
        ("fan-out", (CURRENT,), (CURRENT,) * 4),
        ("consolidation", (CURRENT, PREVIOUS, EARLY), (CURRENT,)),
        ("same-template-turnover", (CURRENT,) * 2, (CURRENT,) * 2),
        ("three-output-templates", (CURRENT, PREVIOUS), (CURRENT, NATIVE, PREVIOUS, EARLY)),
        ("mixed-native-input", (NATIVE, EARLY, CURRENT), (EARLY, NATIVE, CURRENT, PREVIOUS)),
        ("output-count-252", (CURRENT,), (CURRENT,) + (NATIVE,) * 251),
        ("output-count-253", (CURRENT,), (NATIVE,) * 251 + (CURRENT, PREVIOUS)),
        ("automatic-rollover", (AUTO,), (AUTO,)),
        ("automatic-payment-and-change", (AUTO,), (NATIVE, AUTO)),
        ("automatic-turnover", (AUTO,) * 2, (AUTO,) * 2),
        ("automatic-mixed-output", (AUTO, CURRENT), (CURRENT, AUTO, NATIVE)),
    )
    for label, sources, recipients in shapes:
        for flag in (0x41, 0x61):
            yield Case(f"{label}/{flag:02x}", sources, recipients, (flag,) * len(sources))
    for version in (1, 2):
        for flag in sorted(SIGHASH_TYPES):
            yield Case(f"mixed-mode-v{version}/{flag:02x}", (CURRENT, PREVIOUS, NATIVE),
                       (CURRENT, NATIVE, PREVIOUS, CURRENT), (flag,) * 3, version, older_funding=version == 2)
    yield Case("different-input-modes", (CURRENT, PREVIOUS, NATIVE, CURRENT),
               (CURRENT, NATIVE, PREVIOUS, CURRENT, NATIVE), (0x61, 0xe2, 0x63, 0xc1), older_funding=True)
    yield Case("pre-chronicle", (CURRENT, NATIVE), (CURRENT, PREVIOUS), (0x41, 0xc1), 1, False)


def owned_output(label, value, kind, automatic):
    if kind == NATIVE:
        coin = native_coin(label, value)
        return coin.output, coin
    key = PrivateKey.from_int(1 + int.from_bytes(seed(label), "big") % (ORDER - 1))
    owner = owner_hash(key.public_key_xonly.format())
    if kind == AUTO:
        raw, start = automatic
        lock = raw[:start] + owner + raw[start + len(owner):]
    else:
        lock = lock_for_owner(owner, version=kind)
    return Output(value, lock), key


def build_case(case, automatic):
    label = "constructor-matrix/" + case.label
    parents, inputs, signers = [], [], []
    for i, kind in enumerate(case.sources):
        output, signer = owned_output(f"{label}/fund/{i}", 50_000, kind, automatic)
        # Alternate real vouts to distinguish previous-output and spending-input indices.
        before = () if i % 2 == 0 else (native_coin(f"{label}/sibling/{i}", 500).output,)
        parent = Transaction((Input(seed(f"{label}/parent/{i}"), 0),), before + (output,))
        parents.append(parent)
        inputs.append(Input(parent.txid_wire(), len(before), sequence=0xffffff00 + i))
        signers.append(signer)
    values = allocations(50_000 * len(inputs) - 1_000, len(case.recipients))
    outputs = tuple(owned_output(f"{label}/out/{i}", value, kind, automatic)[0]
                    for i, (value, kind) in enumerate(zip(values, case.recipients, strict=True)))
    return Transaction(tuple(inputs), outputs, version=case.version), tuple(parents), signers


def encodings(case, unsigned, parents, signers, automatic):
    txs = dict.fromkeys(("literal", "template", "auto"), unsigned)
    approved = [(v, reconstruction_for_version(v)) for v in TEMPLATE_DIRS if v in case.recipients]
    if AUTO in case.recipients:
        approved.append((AUTO, output_reconstruction(*automatic)))
    selections, digests = [], []
    ordinary, companion = authorization_codes()
    for index, (source, parent, key, flag) in enumerate(zip(case.sources, parents, signers, case.flags, strict=True)):
        if source == NATIVE:
            for name, tx in txs.items():
                txs[name] = key.unlock(tx, index, parent, flag, None)
            selections.append("native")
            digests.append(None)
            continue

        previous = parent.outputs[unsigned.inputs[index].vout]
        auth = prepare_authorization(unsigned, index, previous.value, flag, ordinary_code=ordinary,
                                     companion_code=companion)
        base = flag & 31
        functional = case.active and case.version == 2 and bool(flag & CHRONICLE) and not auth.companion
        outputs = unsigned.outputs if base == SIGHASH_ALL else unsigned.outputs[index:index + 1] if base == SIGHASH_SINGLE else ()
        patterns = tuple(pattern for _, pattern in approved if any(pattern.match(o.script) is not None for o in outputs))
        plan = compile_preimage(unsigned, index, auth, patterns, chronicle_active=case.active,
                                witness_tail_bytes=WITNESS_TAIL_BYTES)
        old = shorter_reconstruction(auth.preimage, outputs, patterns) if functional and outputs else None
        digest = auth.checked_digest()
        signature = key.sign_schnorr(digest, aux_randomness=bytes(32))
        public = key.public_key_xonly.format()
        witness = public, to_bytes(lift_x(public)[1]), signature, to_bytes(lift_x(signature[:32])[1])
        literal = compile_unlock(auth.preimage, auth.companion, *witness)
        selected = {"literal": literal,
                    "template": compile_reconstructed_unlock(old, *witness) if old is not None else literal,
                    "auto": compile_reconstructed_unlock(plan.program, *witness) if plan.selected != "literal" else literal}
        expected = evaluate(literal)
        for name, script in selected.items():
            if evaluate(script) != expected:
                raise ValueError("encoded unlocking stack or complete preimage differs")
            txs[name] = txs[name].with_script(index, script)
        if len(selected["auto"]) > min(len(selected["template"]), len(literal)):
            raise ValueError("automatic encoding is larger than a control")
        selections.append(plan.selected)
        digests.append(digest.hex())
    return txs, selections, digests


def mutations(tx, flags):
    yield "locktime", replace(tx, locktime=tx.locktime + 1), [False] * len(flags)
    for label, outputs in (
        ("recipient-amount", (replace(tx.outputs[0], value=tx.outputs[0].value - 1), *tx.outputs[1:])),
        ("output-order", tuple(reversed(tx.outputs))),
    ):
        if outputs == tx.outputs:
            continue
        expected = []
        for i, flag in enumerate(flags):
            mode = flag & 31
            expected.append(mode == SIGHASH_NONE or mode == SIGHASH_SINGLE and outputs[i] == tx.outputs[i])
        yield label, replace(tx, outputs=outputs), expected
    last = len(tx.inputs) - 1
    changed = replace(tx.inputs[last], sequence=tx.inputs[last].sequence ^ 1)
    expected = [i != last and (bool(flag & ANYONECANPAY) or flag & 31 != SIGHASH_ALL)
                for i, flag in enumerate(flags)]
    yield "sequence", replace(tx, inputs=(*tx.inputs[:-1], changed)), expected


def verify(node, label, tx, parents, expected, context):
    try:
        validate_at_heights(tx, parents, **context)
        valid = True
    except (ValueError, RuntimeError):
        valid = False
    observed = node.verdicts(tx, parents, timeout_us=1_000_000, **context)
    if valid != all(expected) or observed != expected:
        raise ValueError(f"{label}: expected {expected}, node={observed}, chain-gang={valid}")


def replay(node, case, activation, automatic):
    unsigned, parents, signers = build_case(case, automatic)
    txs, selection, digests = encodings(case, unsigned, parents, signers, automatic)
    spending_height = activation + 1 if case.active else activation - 1
    heights = tuple(activation - 2 if not case.active or case.older_funding and i % 2 == 0 else activation
                    for i in range(len(parents)))
    context = dict(spend_height=spending_height, activation_height=activation, utxo_heights=heights)
    checked = set()
    controls = None
    for name, tx in txs.items():
        if tx.txid() in checked:
            continue
        verify(node, f"{case.label}/{name}", tx, parents, [True] * len(parents), context)
        controls = {}
        for mutation, altered, expected in mutations(tx, case.flags):
            verify(node, f"{case.label}/{name}/{mutation}", altered, parents, expected, context)
            controls[mutation] = expected
        checked.add(tx.txid())

    return {
        "case": case.label, "input_types": case.sources, "output_types": Counter(case.recipients),
        "version": case.version, "spend_height": spending_height, "funding_heights": heights,
        "sighashes": [f"{flag:02x}" for flag in case.flags], "constructor_choices": selection,
        "signing_digests_sha256d": digests, "distinct_signed_encodings": len(checked),
        "transactions": {name: {"bytes": len(tx.serialize()), "txid": tx.txid(),
                                 "unlock_bytes": [len(item.script) for item in tx.inputs]}
                         for name, tx in txs.items()},
        "mutation_input_verdicts": controls,
    }


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--output", required=True, type=Path)
    options = args.parse_args()
    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN or not os.environ.get("REGTEST_URL"):
        args.error("run through tools/verify_node.sh with pinned chain-gang")
    activation = int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"])
    if activation < 3:
        args.error("use REGTEST_CHRONICLE_HEIGHT=5 to exercise pre-activation funding")

    frozen = json.loads(Path(__file__).with_name("measurements.json").read_text())
    _, lock, _, _ = compile_candidate(next(plan for plan in plans() if plan.name == frozen["winner"]))
    if sha256(lock).hexdigest() != frozen["candidates"][AUTO]["lock_sha256"]:
        raise ValueError("automatically compiled Schnorr lock differs from the prior experiment")
    _, offset = compiled_template(bytes(20))
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    rows = []
    for case in cases():
        row = replay(node, case, activation, (lock, offset))
        rows.append(row)
        print(case.label, row["constructor_choices"], row["transactions"]["auto"]["bytes"], flush=True)
    report = {"bsv_node_version": node.version, "chain_gang": engine, "chronicle_height": activation,
              "case_count": len(rows), "automatic_lock_bytes": len(lock), "rows": rows}
    options.output.parent.mkdir(parents=True, exist_ok=True)
    # One independent workload per line keeps large matrices easy to diff.
    header = {k: v for k, v in report.items() if k != "rows"}
    row_text = ",\n".join("    " + json.dumps(row) for row in rows)
    header_text = json.dumps(header, indent=2).removesuffix("\n}")
    options.output.write_text(header_text + ',\n  "rows": [\n' + row_text + "\n  ]\n}\n")


if __name__ == "__main__":
    main()
