"""Select an ALL commitment implementation and assemble its matching witness."""

import argparse
from hashlib import sha256
import json
from pathlib import Path

from fourthgraph.bsv.script import asm, push, without_codeseparators
from fourthgraph.bsv.transaction import MAX_MONEY, Output, Transaction, amount, blob, hash256, preimage_forkid, preimage_otda
from fourthgraph.workflow.forkid_lowering import (
    LINKED_OUTPOINT_OFFSET, SCRIPT_CODE_OFFSET, DualLinkedContext, LinkedContext, PREIMAGE_FIXED_BYTES,
)
from fourthgraph.workflow.protocol import (
    BINDING_CODE, FLAG, LOCKTIME, OUTPUTS_HASH, SIGHASH_FAMILIES, TARGETS, CompileError,
    artifact_digest, begin, candidate_sighash_families, check_field, check_version, field, finish, single_input,
)


ARTIFACT_KIND = "pels-lock"
SUCCESSOR_KIND = "pels-successor"
SUCCESSOR_LIBRARY = "std/wallet/pels-verify"
SUCCESSOR_LAYOUT = "successor-tail-head"
STATE_BYTES = 5
SEPARATOR = asm("OP_CODESEPARATOR")
DEPTH_CHECK = asm("OP_DEPTH OP_1 OP_NUMEQUALVERIFY")


def _eligible_families(target, family, *, requires_previous_amount):
    eligible, exclusions = [], {}
    for name in candidate_sighash_families(target, family):
        if name != "bip143" and target == "bip143-v1":
            raise CompileError("PELS OTDA requires a Chronicle spend target")
        if name != "bip143" and requires_previous_amount:
            message = "OTDA has no authenticated prevout amount for this PELS lock"
            if family != "auto":
                raise CompileError(message)
            exclusions[name] = message
        else:
            eligible.append(name)
    return eligible, exclusions


def make_candidate(family, layout, versions, output_count, outputs, locktime, prev_amount):
    flags = tuple(SIGHASH_FAMILIES.values()) if family == "both" else (SIGHASH_FAMILIES[family],)
    flag = flags[0]
    if layout == "full":
        entry = DEPTH_CHECK + begin(versions) + single_input()
        if locktime is not None:
            entry += push(locktime) + check_field(LOCKTIME, 4)
        if prev_amount is not None:
            entry += push(prev_amount) + check_field(SCRIPT_CODE_OFFSET + len(blob(BINDING_CODE)), 8)
        commitment = push(hash256(outputs)) + check_field(OUTPUTS_HASH)
        binding = finish(flag)
        lengths = (PREIMAGE_FIXED_BYTES + len(blob(BINDING_CODE)),)
    else:
        contexts = tuple(LinkedContext(BINDING_CODE, value, output_count) for value in flags)
        context = DualLinkedContext(*contexts) if family == "both" else contexts[0]
        entry = DEPTH_CHECK + context.check_size() + asm("OP_DUP") + field(0, 4) + check_version(versions)
        if locktime is not None:
            entry += asm("OP_DUP OP_SIZE OP_4 OP_SUB OP_SPLIT OP_NIP") + push(locktime) + asm("OP_EQUALVERIFY")
        if prev_amount is not None:
            entry += asm("OP_DUP") + field(LINKED_OUTPOINT_OFFSET + 36, 8)
            entry += push(prev_amount) + asm("OP_EQUALVERIFY")
        entry += asm("OP_TOALTSTACK")
        commitment = push(outputs) + context.bind_outputs()
        binding = finish(flag, flag_script=asm("OP_FROMALTSTACK") if family == "both" else None)
        lengths = tuple(item.packed_bytes for item in contexts)
    script = entry + commitment + binding
    fragments = []
    offset = 0
    for name, part, depends_on in (
        ("context", entry, ["constraints"]),
        ("outputs", commitment, ["constraints", "context"]),
        ("binding", binding, ["outputs"]),
    ):
        fragments.append({"id": name, "depends_on": depends_on, "offset": offset,
                          "bytes": len(part), "sha256": sha256(part).hexdigest()})
        offset += len(part)
    paths = {}
    for value, length in zip(flags, lengths, strict=True):
        name = next(name for name, code in SIGHASH_FAMILIES.items() if code == value)
        paths[name] = {
            "sighash": value, "requires_chronicle": name == "otda",
            "script_code_offset": len(script) - len(BINDING_CODE),
            "script_code_sha256": sha256(BINDING_CODE).hexdigest(),
            "layout": layout,
            "context_bytes": length,
            "path_script_field_bytes": len(blob(script)) + len(blob(push(bytes(length)))),
        }
    return script, paths, fragments


def compile_pels(constraints, target, family, *, explain=False):
    versions, era = TARGETS[target]
    outputs = b"".join(output.serialize() for output in constraints.outputs)
    total = sum(output.value for output in constraints.outputs)
    if total > MAX_MONEY:
        raise CompileError("PELS output total exceeds the maximum satoshi amount")
    if constraints.previous_amount is not None and total > constraints.previous_amount:
        raise CompileError("PELS output total exceeds the fixed prevout amount")
    locktime = None if constraints.locktime is None else constraints.locktime.to_bytes(4, "little")
    prev_amount = None if constraints.previous_amount is None else amount(constraints.previous_amount)

    families, exclusions = _eligible_families(target, family, requires_previous_amount=prev_amount is not None)
    candidates = []
    for name in families:
        layouts = ("full", "reconstructed") if name == "bip143" else ("reconstructed",)
        for layout in layouts:
            script, paths, fragments = make_candidate(name, layout, versions, len(constraints.outputs), outputs,
                                                      locktime, prev_amount)
            score = max(path["path_script_field_bytes"] for path in paths.values())
            candidates.append((name, layout, script, paths, score, fragments))
    chosen = min(candidates, key=lambda row: (row[4], len(row[2]), row[0], row[1]))
    name, label, script, paths, _, fragments = chosen
    contract = {"input_count": 1, "locktime": constraints.locktime, "previous_amount": constraints.previous_amount,
                "outputs": [{"satoshis": output.value, "script_hex": output.script.hex()}
                            for output in constraints.outputs]}
    entries = []
    for candidate, encoding, code, candidate_paths, cost, parts in candidates:
        row = {"family": candidate, "layout": encoding, "script_bytes": len(code),
               "script_sha256": sha256(code).hexdigest(), "fragments": parts,
               "path_script_field_bytes": cost, "paths": candidate_paths}
        if explain:
            row["script_hex"] = code.hex()
        entries.append(row)
    report = {
        "kind": ARTIFACT_KIND, "target": target, "era": "chronicle" if name == "otda" else era,
        "transaction_versions": versions,
        "script_hex": script.hex(), "script_bytes": len(script), "script_sha256": sha256(script).hexdigest(),
        "constraints": contract, "constraints_sha256": artifact_digest(contract), "fragments": fragments,
        "paths": paths,
        "selection": {
            "requested": family, "selected": name, "layout": label,
            "excluded_families": exclusions,
            "objective": "lock and maximum path witness Script fields including CompactSize",
            "candidates": entries,
        },
    }
    if explain:
        report["constraint_sources"] = {
            key: {"module": module, "line": line, "column": column}
            for key, (module, line, column) in constraints.sources
        }
    return report


def compile_successor(source, entry, state, target, family, *, explain=False):
    """Link the standard BIP143 successor to an application rule and target."""
    if len(state) != STATE_BYTES:
        raise CompileError(f"PELS successor state must contain {STATE_BYTES} bytes")
    families, exclusions = _eligible_families(target, family, requires_previous_amount=True)
    selected, = families
    versions, era = TARGETS[target]
    library, _ = source.imported_words.get("pels-verify", (None, None))
    if library != SUCCESSOR_LIBRARY:
        raise CompileError("PELS successor requires the bundled stdlib/wallet/pels-verify.fth export")
    word = source.words.get(entry)
    if getattr(word, "takes", ()) != ("script",) or getattr(word, "gives", ()) != ("script",):
        raise CompileError("PELS successor rule must have build stack effect ( script -- script )")
    rule = source.emit(entry, b"")
    if without_codeseparators(rule) != rule:
        raise CompileError("PELS successor rule cannot emit OP_CODESEPARATOR")
    # The rule sees the prior amount only through the library. The same head
    # checked here is authenticated by the library's native signature check.
    version_check = asm("OP_OVER") + field(0, 4) + check_version(versions)
    prefix = push(state) + SEPARATOR
    code = source.emit("pels-verify", version_check, rule) + asm("OP_DROP OP_1")
    script = prefix + code
    layout = SUCCESSOR_LAYOUT
    path = {"sighash": FLAG, "requires_chronicle": False, "layout": layout,
            "script_code_offset": len(prefix), "script_code_sha256": sha256(code).hexdigest()}
    constraints = {"input_count": 1, "output_count": 1, "requires_previous_amount": True,
                   "state_hex": state.hex(), "rule_sha256": sha256(rule).hexdigest()}
    candidate = {"family": selected, "layout": layout, "script_bytes": len(script),
                 "script_sha256": sha256(script).hexdigest()}
    report = {
        "kind": SUCCESSOR_KIND, "target": target, "era": era, "transaction_versions": versions,
        "script_hex": script.hex(), "script_bytes": len(script), "script_sha256": candidate["script_sha256"],
        "constraints": constraints, "constraints_sha256": artifact_digest(constraints),
        "paths": {selected: path},
        "selection": {"requested": family, "selected": selected, "layout": layout,
                      "excluded_families": exclusions, "candidates": [candidate]},
    }
    if explain:
        report["rule_script_hex"] = rule.hex()
    return report


def _assemble_successor(script, path, prevout, unsigned):
    """Fill the standard witness. The on-chain rule checks the next state and amount."""
    code_offset = STATE_BYTES + 2  # One state push length and one CODESEPARATOR.
    code = script[code_offset:]
    if (path["layout"] != SUCCESSOR_LAYOUT or path["sighash"] != FLAG
            or path["script_code_offset"] != code_offset
            or script[0:1] != bytes([STATE_BYTES]) or script[code_offset - 1:code_offset] != SEPARATOR
            or path["script_code_sha256"] != sha256(code).hexdigest()):
        raise ValueError("the binding anchor or sighash differs from the selected successor")
    if len(unsigned.outputs) != 1:
        raise ValueError("PELS successor requires one output")
    successor = unsigned.outputs[0].script
    if successor[0:1] != bytes([STATE_BYTES]) or successor[code_offset - 1:] != SEPARATOR + code:
        raise ValueError("the candidate output does not use the selected successor template")
    preimage = preimage_forkid(unsigned, 0, prevout.value, code, FLAG)
    # BIP143 ends with hashOutputs (32 bytes), locktime, and sighash (4 bytes each).
    return unsigned.with_script(0, push(preimage[-8:]) + push(preimage[:-40]))


def assemble_pels(artifact, parent, unsigned, family=None):
    """Fill the sole input of an approved lock, leaving every other field intact."""
    if (not isinstance(artifact, dict) or artifact.get("kind") not in (ARTIFACT_KIND, SUCCESSOR_KIND)
            or artifact.get("artifact_sha256") != artifact_digest(artifact)):
        raise ValueError("expected a PELS lock artifact with its matching build digest")
    paths = artifact["paths"]
    if family is None and len(paths) == 1:
        family, = paths
    if family not in paths:
        raise ValueError("select an available spend family from the artifact")
    path = paths[family]
    script = bytes.fromhex(artifact["script_hex"])
    constraints = artifact["constraints"]
    if len(unsigned.inputs) != 1 or unsigned.inputs[0].script:
        raise ValueError("PELS requires a single unsigned input")
    txin = unsigned.inputs[0]
    if txin.txid != parent.txid_wire() or not 0 <= txin.vout < len(parent.outputs):
        raise ValueError("the supplied parent does not fund this input")
    prevout = parent.outputs[txin.vout]
    if prevout.script != script:
        raise ValueError("the actual prevout does not use the selected PELS lock")
    if unsigned.version not in artifact["transaction_versions"]:
        raise ValueError("transaction version is outside the compiled target")
    if artifact["kind"] == SUCCESSOR_KIND:
        if family != "bip143":
            raise ValueError("PELS successor requires BIP143")
        return _assemble_successor(script, path, prevout, unsigned), family
    expected = tuple(Output(row["satoshis"], bytes.fromhex(row["script_hex"])) for row in constraints["outputs"])
    if unsigned.outputs != expected:
        raise ValueError("ordered outputs do not satisfy the compiled lock")
    if constraints["locktime"] is not None and unsigned.locktime != constraints["locktime"]:
        raise ValueError("locktime does not satisfy the compiled lock")
    if constraints["previous_amount"] is not None and prevout.value != constraints["previous_amount"]:
        raise ValueError("prevout amount does not satisfy the compiled lock")
    if sum(output.value for output in unsigned.outputs) > prevout.value:
        raise ValueError("PELS output total exceeds the actual prevout amount")
    code = script[path["script_code_offset"]:]
    flag = SIGHASH_FAMILIES[family]
    if code != BINDING_CODE or path["sighash"] != flag:
        raise ValueError("the binding anchor or sighash differs from the selected implementation")
    preimage = (preimage_forkid(unsigned, 0, prevout.value, code, flag) if flag == FLAG
                else preimage_otda(unsigned, 0, code, flag))
    context = preimage if path["layout"] == "full" else LinkedContext(code, flag, len(expected)).pack(preimage)
    if len(context) != path["context_bytes"]:
        raise ValueError("witness length differs from the selected implementation")
    return unsigned.with_script(0, push(context)), family


def witness_main(argv):
    cli = argparse.ArgumentParser(prog="4thgraph pels-witness")
    cli.add_argument("artifact", type=Path)
    cli.add_argument("--parent", type=Path, required=True, help="hex file containing the actual parent")
    cli.add_argument("--unsigned", type=Path, required=True, help="hex file containing the candidate")
    cli.add_argument("--sighash-family", choices=tuple(SIGHASH_FAMILIES))
    args = cli.parse_args(argv)
    try:
        artifact = json.loads(args.artifact.read_text())
        parent, tx = (Transaction.parse(bytes.fromhex(path.read_text())) for path in (args.parent, args.unsigned))
        completed, family = assemble_pels(artifact, parent, tx, args.sighash_family)
    except (OSError, TypeError, ValueError, KeyError) as error:
        cli.error(str(error))
    print(json.dumps({"artifact_sha256": artifact["artifact_sha256"], "sighash_family": family,
                      "transaction_hex": completed.serialize().hex()}, sort_keys=True))
