"""Rebuild the v0.6.0 BN254 phase profile with a temporary Rúnar overlay."""

import argparse
from collections import Counter
from hashlib import sha256
from itertools import groupby
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from fourthgraph.bsv.script import asm, script_operations
from fourthgraph.compiler.stack_peephole import compact_stack_moves
from fourthgraph.verification.groth16_bn254 import (
    ADAPTER, COMPACT_MODULO_THRESHOLD, COMPACT_SUBGROUP, RUNAR_REVISION,
    ForthVerifier, build_adapter, checked, public_signals, runar_overlay,
)

PROJECT = Path(__file__).resolve().parents[1]
FIXTURE = PROJECT / "versions/v0.1.0/fixture.json"
RELEASE = PROJECT / "versions/v0.6.0"
SOURCE = PROJECT / "forth/last-use-verifier.fth"

MILLER_PHASES = (
    ('bn254Fp12Sqr(t, "_f", "_f_sq")', "miller-square"),
    ("emitWALineEvalDoubleSparse(t, tpfx,", "miller-var-line"),
    ('bn254Fp12MulSparse(t, "_f", "_ld"+ks,', "miller-var-mul"),
    ("emitCompactDelta(t, fixedDelta.double[", "miller-fixed-line-and-mul"),
    # The archived boundary leaves signed point setup in the preceding block.
    ("emitWALineEvalAddSparse(t, tpfx,", "miller-var-line"),
    ('bn254Fp12MulSparse(t, "_f", "_la"+ks,', "miller-var-mul"),
    ('bn254Fp12MulSparse(t, "_f", "_ls"+ks,', "miller-var-mul"),
    ("emitCompactDelta(t, fixedDelta.add[", "miller-fixed-line-and-mul"),
    ("emitWAResidueFold(t, 1)", "miller-residue-fold"),
    ("emitWAResidueFold(t, -1)", "miller-residue-fold"),
    ("// Clean up -Q_i", "miller-cleanup"),
)


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"profiling anchor is missing or ambiguous: {old!r}")
    return text.replace(old, new, 1)


def instrument_miller(text):
    start = text.index("func emitWAMillerLoop(t")
    end = text.index("\n}", start)
    lines = text[start:end].splitlines(keepends=True)
    for anchor, phase in MILLER_PHASES:
        rows = [i for i, line in enumerate(lines) if line.lstrip().startswith(anchor)]
        expected = 2 if anchor in {"emitWALineEvalAddSparse(t, tpfx,", "emitCompactDelta(t, fixedDelta.add["} else 1
        if len(rows) != expected:
            raise ValueError(f"unexpected Miller profiling anchors for {phase}: {rows}")
        for i in rows:
            indent = lines[i][:-len(lines[i].lstrip())]
            lines[i] = indent + f'profilePhase = "{phase}"\n' + lines[i]
    return text[:start] + "".join(lines) + text[end:]


def instrument_forth(text):
    text = replace_once(text, '"fmt"\n', '"fmt"\n\t"github.com/icellan/runar/compilers/go/ir"\n')
    text = replace_once(text, "func EmitCompactForthVerifier(", "var profilePhase string\n\nfunc EmitCompactForthVerifier(")
    text = replace_once(text, "NewBN254Tracker(forthWitnessSlots(plan.Miller), emit)",
                        'NewBN254Tracker(forthWitnessSlots(plan.Miller), func(op StackOp) {\n'
                        '        op.SourceLoc = &ir.SourceLocation{File: profilePhase, Line: 1}\n'
                        '        emit(op)\n    })')
    text = replace_once(text, "for _, stage := range plan.Stages {",
                        "for _, stage := range plan.Stages {\n\t\tprofilePhase = stage")
    return replace_once(text, "for len(t.nm) > 0 {", 'profilePhase = "cleanup"\n\tfor len(t.nm) > 0 {')


def build_profiler(runar, directory, go):
    with runar_overlay(runar) as (overlay, cwd, env):
        files = json.loads(overlay.read_bytes())["Replace"]

        def instrumented(path, transform):
            key = str(cwd / path)
            copy = directory / Path(path).name
            copy.write_text(transform(Path(files[key]).read_text(encoding="utf-8")), encoding="utf-8")
            files[key] = str(copy)

        instrumented("codegen/forth_groth16.go", instrument_forth)
        instrumented("codegen/bn254_groth16.go", instrument_miller)
        instrumented("compiler/groth16_wa.go", lambda source: replace_once(
            source, "Script:           emitResult.ScriptHex,",
            "Script: emitResult.ScriptHex,\n        SourceMapData: &SourceMap{Mappings: emitResult.SourceMap},",
        ))
        profile_overlay = directory / "profile-overlay.json"
        profile_overlay.write_text(json.dumps({"Replace": files}), encoding="utf-8")
        adapter = directory / "profile_adapter.go"
        adapter.write_text(replace_once(ADAPTER.read_text(), "Encode(artifact.Script)",
                                        'Encode(map[string]any{"script": artifact.Script, '
                                        '"source_map": artifact.SourceMapData.Mappings})'), encoding="utf-8")
        binary = directory / "profile-adapter"
        checked([go, "build", "-overlay", str(profile_overlay), "-o", str(binary), str(adapter)], cwd=cwd, env=env)
        return binary


def witness_sizes(witness, schedule):
    sizes = [len(op) for op in script_operations(witness)]
    result, start = {}, 0
    for phase, count in (("field_modulus", 1), ("miller_slopes", 2 * (len(schedule) + sum(map(bool, schedule)))),
                         ("residue_and_selector", 25), ("proof_points", 8)):
        result[phase] = sum(sizes[start:start + count])
        start += count
    if start != len(sizes):
        raise ValueError("witness framing differs from the v0.6.0 layout")
    return result


def profile_case(profiler, verifier, owner, case, expected):
    signals = public_signals(json.dumps(case["public"]))
    key_path = verifier.directory / "key.json"
    key_path.write_text(json.dumps({**verifier.adapter_key, "pinnedPublicInputs": dict(enumerate(signals))}),
                        encoding="utf-8")
    request = dict(VK=str(key_path), Public=signals, CompactStatement=True, CompactSubgroup=COMPACT_SUBGROUP,
                   ModuloThreshold=COMPACT_MODULO_THRESHOLD, ForthPlan=verifier.forth_plan)
    result = json.loads(checked([profiler], stdin=json.dumps(request)))
    raw = bytes.fromhex(result["script"])
    if not raw.startswith(asm("OP_0 OP_CHECKSIGVERIFY")):
        raise ValueError("unexpected owner constructor slot")
    labels = {entry["opcodeIndex"]: entry["sourceFile"] for entry in result["source_map"]}
    owner_guard = verifier.owner_guard(owner)
    blocks, sizes = Counter(owner=1), Counter(owner=len(owner_guard))
    segments = [owner_guard]
    operations = list(script_operations(raw))
    if min(labels, default=-1) != 2 or max(labels) >= len(operations):
        raise ValueError("unexpected verifier phase offsets")
    # Instructions omitted from source maps, such as OP_ENDIF, stay with the current phase.
    starts = [next(indices) for _, indices in groupby(sorted(labels), key=labels.get)]
    for start, end in zip(starts, starts[1:] + [len(operations)]):
        phase = labels[start]
        segment = b"".join(operations[start:end])
        compact = compact_stack_moves(segment)
        blocks[phase] += 1
        sizes[phase] += len(compact)
        segments.append(compact)
    lock = b"".join(segments)
    digest = sha256(lock).hexdigest()
    if len(lock) != expected["lock_bytes"] or digest != expected["script_sha256"]:
        raise ValueError(f"profiled lock differs from v0.6.0: {len(lock)} bytes, {digest}")
    witness = verifier.witness(signals, json.dumps(case["proof"]))
    if len(witness) != expected["witness_prefix_bytes"] or sha256(witness).hexdigest() != expected["witness_prefix_sha256"]:
        raise ValueError("profiled witness differs from v0.6.0")
    return {
        "compiled_lock_bytes": dict(sizes),
        "blocks": dict(blocks),
        "witness_bytes": witness_sizes(witness, verifier.forth_plan["Miller"]),
        "script_sha256": digest,
        "miller_total_bytes": sum(size for name, size in sizes.items() if name.startswith("miller")),
    }, len(lock) - len(compact_stack_moves(lock))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runar", type=Path, required=True)
    parser.add_argument("--go", default="go")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true", help="check both profiles against the checked-in evidence")
    args = parser.parse_args()
    fixture_bytes = FIXTURE.read_bytes()
    fixture = json.loads(fixture_bytes)
    key = json.dumps(fixture["verification_key"]).encode()
    owner = bytes.fromhex(fixture["owner_public_key"])
    expected = json.loads((RELEASE / "measurements.json").read_bytes())["funded_replays"]
    cases, savings = {}, {}
    with TemporaryDirectory(prefix="bn254-phase-profile-") as tmp:
        work = Path(tmp)
        adapter = work / "adapter"
        build_adapter(args.runar, adapter, go=args.go)
        profiler = build_profiler(args.runar, work, args.go)
        verifier = ForthVerifier(adapter, key, work, SOURCE.read_bytes(), source_path=SOURCE)
        for label in ("wrap", "other"):
            cases[label], savings[label] = profile_case(profiler, verifier, owner, fixture[label], expected[label])
    if args.check:
        archived = json.loads((RELEASE / "optimization-profile.json").read_bytes())
        if cases != archived["phase_measurement"]["cases"] or savings != archived["additional_stack_pass"]["lock_bytes_saved"]:
            parser.error("regenerated phase profile differs from the release record")
    report = dict(version="0.6.0", runar_revision=RUNAR_REVISION, fixture_sha256=sha256(fixture_bytes).hexdigest(),
                  phase_measurement={"cases": cases}, additional_stack_pass={"lock_bytes_saved": savings})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
