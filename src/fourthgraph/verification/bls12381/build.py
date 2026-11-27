"""Compile the typed Forth BLS12-381 Groth16 verifier to BSV Script."""

import argparse
from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from pathlib import Path

from fourthgraph.verification.bls12381.affine_witness import (
    AffineStages, LAYOUTS, MSM_STRATEGIES, affine_witness, line_packet, msm_windows, slope_packet_bytes,
)
from fourthgraph.verification.bls12381.field import FP2_ENTRY, FP2_RULES, fp2_alternatives, fp2_kernel
from fourthgraph.verification.bls12381.verifier import (
    PACKET_BYTES, ScriptVerifier, VerifierStages, _FIXED_WITNESS, dynamic_slots, input_sources, public_signals,
)
from fourthgraph.compiler.formula_experiment import validate_rules
from fourthgraph.compiler.source import MAX_EXPANSION, PROJECT_VERSION, CompileError, Shuffle, SourceCompiler, check_word_expansion, expanded
from fourthgraph.workflow.protocol import build_artifact
from fourthgraph.bsv.script import asm, push
from fourthgraph.bsv.transaction import compact as compact_size
from fourthgraph.stdlib import GROTH16_ENTRY, GROTH16_VERIFY, LEGACY_GROTH16_ENTRY, LIBRARIES, describe_export, interface_digest
from fourthgraph.compiler.wordsets import SHUFFLES, TYPES

SOURCE = LIBRARIES["std/groth16-bls12-381"].source
ENTRY = GROTH16_ENTRY
MODULE = "std/groth16-bls12-381"
SCRIPT_ERAS = ("genesis", "chronicle")
OBJECTIVES = {
    "path-bytes": ("path_bytes", "witness_bytes", "lock_bytes"),
    "lock-bytes": ("lock_bytes", "path_bytes", "witness_bytes"),
    "witness-bytes": ("witness_bytes", "path_bytes", "lock_bytes"),
}
WITNESS_PACKETS = ("pairing_line_packet_bytes", "slope_packet_bytes", "proof_packet_bytes", "public_packet_bytes")
RESIDUE_ASSOCIATIONS = ("left", "right", "accumulator-frobenius-first")


@dataclass(frozen=True)
class ArithmeticPlan:
    fp2_rules: tuple[str, ...] = FP2_RULES
    residue_association: str = "left"
    fp2_selection: str = "uniform"
    msm: str = MSM_STRATEGIES[0]

    def __post_init__(self):
        object.__setattr__(self, "fp2_rules", validate_rules(self.fp2_rules))
        if self.residue_association not in RESIDUE_ASSOCIATIONS:
            raise ValueError(f"residue association must be one of {', '.join(RESIDUE_ASSOCIATIONS)}")
        if self.fp2_selection not in ("uniform", "callsite"):
            raise ValueError("Fp2 selection must be uniform or callsite")
        if self.msm not in MSM_STRATEGIES:
            raise ValueError(f"MSM must be one of {', '.join(MSM_STRATEGIES)}")

    def document(self):
        document = asdict(self)
        if self.fp2_selection == "uniform":
            del document["fp2_selection"]
        if self.msm == MSM_STRATEGIES[0]:
            del document["msm"]
        return document

    @classmethod
    def read(cls, path):
        plan = json.loads(path.read_bytes())
        required = {"fp2_rules", "residue_association"}
        if not isinstance(plan, dict) or not required <= plan.keys() <= required | {"fp2_selection", "msm"}:
            raise ValueError("arithmetic plan requires fp2_rules and residue_association")
        return cls(**plan)


@dataclass(frozen=True)
class Stage:
    takes: tuple[str, ...]
    gives: tuple[str, ...]
    method: str
    argument: str | None = None

    location = "script"
    checked_bounds = None
    comparison = False


VOCABULARY = {
    "bls12-381-read-witness": Stage(
        (), ("groth16-proof", "groth16-public"), "read_witness",
    ),
    "bls12-381-check-public-inputs": Stage(
        ("groth16-public",), ("groth16-pairing-key",), "check_public_inputs",
    ),
    "bls12-381-check-g1-points": Stage(
        ("groth16-proof",), ("groth16-checked-g1",), "check_g1_points",
    ),
    "bls12-381-check-g1-a": Stage(
        ("groth16-proof",), ("groth16-checked-a",), "check_g1_a",
    ),
    "bls12-381-check-g1-c": Stage(
        ("groth16-checked-a",), ("groth16-checked-g1",), "check_g1_c",
    ),
    "bls12-381-miller-loop": Stage(
        ("groth16-pairing-key", "groth16-checked-g1"), ("groth16-miller-state",), "miller_loop",
    ),
    "bls12-381-check-residue": Stage(
        ("groth16-miller-state",), ("groth16-verified",), "check_residue",
    ),
    "bls12-381-miller-begin": Stage(
        ("groth16-pairing-key", "groth16-checked-g1"), ("groth16-miller-plan",), "begin_miller_plan",
    ),
    "bls12-381-miller-zero-bit": Stage(
        ("groth16-miller-plan",), ("groth16-miller-plan",), "append_miller_bit", "0",
    ),
    "bls12-381-miller-one-bit": Stage(
        ("groth16-miller-plan",), ("groth16-miller-plan",), "append_miller_bit", "1",
    ),
    "bls12-381-miller-execute": Stage(
        ("groth16-miller-plan",), ("groth16-miller-state",), "execute_miller_plan",
    ),
    "bls12-381-miller-factors": Stage(
        ("groth16-miller-state",), ("groth16-accumulator", "groth16-key-factor", "groth16-residue-witness"),
        "miller_factors",
    ),
    "bls12-381-frobenius-residue": Stage(
        ("groth16-residue-witness",), ("groth16-frobenius-factor",), "frobenius_residue",
    ),
    "bls12-381-residue-product": Stage(
        ("groth16-accumulator", "groth16-key-factor", "groth16-frobenius-factor"),
        ("groth16-residue-product",), "residue_product",
    ),
    "bls12-381-require-fp6": Stage(
        ("groth16-residue-product",), ("groth16-fp6-residue",), "require_fp6",
    ),
    "bls12-381-require-nonzero": Stage(
        ("groth16-fp6-residue",), ("groth16-verified",), "require_nonzero_fp6",
    ),
}
STACK_TYPES = TYPES | {kind for stage in VOCABULARY.values() for kind in (*stage.takes, *stage.gives)}


class VerifierSource(SourceCompiler):
    def declaration(self, token):
        if token.name not in {"require", "bsv-effect:", ":"}:
            raise token.error(f"{token.text!r} is not a Groth16 verifier declaration")
        super().declaration(token)


class ForthVerifier(ScriptVerifier):
    def __init__(self, verification_key, source, *, witness_layout="projective", script_era="genesis", entry=None,
                 source_path=None, plan=None):
        super().__init__(verification_key)
        if witness_layout not in LAYOUTS:
            raise ValueError(f"unknown witness layout {witness_layout!r}")
        if plan is not None and plan.msm == "signed-radix4" and witness_layout == "projective":
            raise ValueError("signed radix-4 MSM requires an affine witness layout")
        if script_era not in SCRIPT_ERAS:
            raise ValueError(f"unknown Script era {script_era!r}")
        self.witness_layout = witness_layout
        self.script_era = script_era
        self.source = source
        self.plan = plan
        self.msm = plan.msm if plan is not None else MSM_STRATEGIES[0]
        frontend = VerifierSource(source.decode(), vocabulary=VOCABULARY, stack_types=STACK_TYPES,
                                  backend="groth16-bls12-381", source_path=source_path)
        self.libraries = frontend.library_imports
        if entry is None:
            canonical, legacy = (frontend.words.get(name) for name in (ENTRY, LEGACY_GROTH16_ENTRY))
            if canonical is not None and legacy is not None and canonical is not legacy:
                at = frontend.definitions[LEGACY_GROTH16_ENTRY]
                raise at.error(f"{LEGACY_GROTH16_ENTRY!r} and {ENTRY!r} both define the Groth16 entry")
            entry_name, word = ENTRY, canonical or legacy
        else:
            entry_name = entry.casefold()
            word = frontend.words.get(entry_name)
        if word is None:
            raise CompileError(f"undefined Groth16 entry {entry_name!r}")
        if (word.takes, word.gives) != ((), ("groth16-verified",)):
            raise frontend.definitions[word.name].error(f"{word.name} requires the stack effect -- groth16-verified")
        self.entry = ENTRY if word.name == LEGACY_GROTH16_ENTRY else word.name
        check_word_expansion(word, MAX_EXPANSION)
        self.instructions = tuple(expanded(word.body))
        for instruction, token in self.instructions:
            if not isinstance(instruction, (Stage, Shuffle)):
                raise token.error(f"{token.text!r} cannot compile in a Groth16 verifier build")
        if plan is not None and plan.residue_association != "left" and not any(
                isinstance(instruction, Stage) and instruction.method == "residue_product"
                for instruction, _ in self.instructions):
            raise CompileError("changing the association requires an explicit BLS12-381 residue product")

    def lower(self, sources, *, compact, diagnostics=None):
        if self.plan is not None and not compact:
            raise ValueError("an arithmetic plan requires the compact stack schedule")
        chronicle = self.script_era == "chronicle"
        plan = self.plan if self.plan is not None else ArithmeticPlan()
        options = dict(chronicle=chronicle, optimize=compact, fp2_rules=plan.fp2_rules,
                       fp2_selection=plan.fp2_selection)
        if self.witness_layout == "projective":
            stages = VerifierStages(self.key, sources, **options)
        else:
            stages = AffineStages(self.key, sources, lines_in_witness=self.witness_layout == "affine-witness",
                                  msm=self.msm, **options)
        stack = []
        for instruction, _ in self.instructions:
            if isinstance(instruction, Shuffle):
                count, order, _ = SHUFFLES[instruction.name]
                operands = stack[-count:]
                stack[-count:] = [operands[index] for index in order]
            else:
                start = len(stack) - len(instruction.takes)
                operands = stack[start:]
                if instruction.argument is not None:
                    operands.append(instruction.argument)
                method = getattr(stages, instruction.method)
                association = {"association": self.plan.residue_association} if (
                    self.plan is not None and instruction.method == "residue_product") else {}
                value = method(*operands, **association)
                stack[start:] = (value,) if len(instruction.gives) == 1 else value
        if diagnostics is not None and plan.fp2_selection == "callsite":
            diagnostics["fp2_choices"] = [
                {"ordered_rules": rules, "calls": calls} for rules, calls in sorted(stages.field.fp2_choices.items())
            ]
        return stages.compile(compact=compact) + asm("OP_1" if compact else "OP_VERIFY OP_1")

    def witness(self, signals, proof, *, sources=_FIXED_WITNESS):
        if self.witness_layout == "projective":
            return super().witness(signals, proof, sources=sources)
        config = self.sources(None if sources is _FIXED_WITNESS else sources)
        return affine_witness(self.key, config, tuple(signals), proof,
                              lines_in_witness=self.witness_layout == "affine-witness", msm=self.msm)

    def artifact(self, signals, owner, script, *, compact=True):
        result = super().artifact(signals, owner, script, compact=compact)
        result["compiler_version"] = PROJECT_VERSION
        result["stack_schedule"] = "compact" if compact else "baseline"
        if compact:
            rules = self.plan.fp2_rules if self.plan is not None else FP2_RULES
            _, kernel_digest = fp2_kernel(rules)
            result["fp2_kernel"] = {"entry": FP2_ENTRY, "source_sha256": kernel_digest,
                                    "ordered_rules": rules}
            if self.plan is not None and self.plan.fp2_selection == "callsite":
                result["fp2_kernel"].update(selection="callsite", candidates=fp2_alternatives(rules))
        if self.plan is not None:
            result["arithmetic_plan"] = self.plan.document()
        result["forth_entry"] = self.entry
        result["entry_interface"] = describe_export(MODULE, GROTH16_VERIFY)
        result["entry_interface_sha256"] = interface_digest(MODULE, LIBRARIES[MODULE])
        if self.libraries:
            result["libraries"] = tuple(map(asdict, self.libraries))
        if self.script_era == "chronicle":
            result.update(minimum_era="chronicle", minimum_utxo_era="chronicle")
        if self.witness_layout != "projective":
            windows = sum(1 for _ in msm_windows(self.key, self.sources(signals), strategy=self.msm))
            result.update(schema_version=3, witness_layout=self.witness_layout, proof_packet_bytes=PACKET_BYTES,
                          slope_packet_bytes=slope_packet_bytes(windows), msm_slope_count=windows)
            result.pop("vk_claim_bytes", None)
            if self.witness_layout == "affine-witness":
                lines = line_packet(self.key)
                result.update(pairing_line_packet_bytes=len(lines), pairing_line_sha256=sha256(lines).hexdigest())
        return build_artifact(result, self.source)


@dataclass(frozen=True)
class LayoutCandidate:
    verifier: ForthVerifier
    artifact: dict
    cost: dict[str, int]


def layout_candidates(verification_key, source, sources=None, owner=None, *, compact=True, script_era="genesis",
                      entry=None, source_path=None, plan=None):
    """Build the applicable layouts under the same proof and deployment policy."""
    signed_msm = plan is not None and plan.msm == "signed-radix4"
    primary = ForthVerifier(verification_key, source, entry=entry, source_path=source_path, script_era=script_era,
                            witness_layout="affine-inline" if signed_msm else "projective", plan=plan)
    sources = primary.sources(sources)
    if dynamic_slots(sources):
        layouts = LAYOUTS[1:] if signed_msm else LAYOUTS
    else:
        if signed_msm:
            raise ValueError("signed radix-4 MSM requires at least one spend-time public input")
        layouts = (primary.witness_layout,)
    candidates = []
    for layout in layouts:
        verifier = primary if layout == primary.witness_layout else ForthVerifier(
            verification_key, source, witness_layout=layout, script_era=script_era, entry=entry, source_path=source_path,
            plan=plan,
        )
        lock = verifier.compile(sources, owner, compact=compact)
        artifact = verifier.artifact(sources, owner, lock, compact=compact)
        witness_bytes = sum(len(push(bytes(artifact[key]))) for key in WITNESS_PACKETS if key in artifact)
        # Count the serialized script fields for one deployment and one spend.
        # Funding, appended signatures and application payloads are external.
        path_bytes = len(lock) + len(compact_size(len(lock))) + witness_bytes + len(compact_size(witness_bytes))
        candidates.append(LayoutCandidate(verifier, artifact, {
            "lock_bytes": len(lock), "witness_bytes": witness_bytes, "path_bytes": path_bytes,
        }))
    return tuple(candidates)


def select_layout(candidates, objective):
    """Return the selected witness generator and a reproducible build artifact."""
    order = OBJECTIVES[objective]
    chosen = min(candidates, key=lambda row: (*(row.cost[metric] for metric in order),
                                              row.verifier.witness_layout))
    verifier = chosen.verifier
    artifact = {
        **chosen.artifact,
        "witness_layout": verifier.witness_layout,
        "layout_selection": {
            "objective": objective,
            "scope": "one_lock_and_one_proof_witness_with_compact_size",
            "candidates": tuple({"witness_layout": row.verifier.witness_layout, **row.cost} for row in candidates),
        },
    }
    return verifier, build_artifact(artifact, verifier.source)


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("source", type=Path, nargs="?", default=SOURCE)
    cli.add_argument("--entry", help=f"Forth definition to compile (default: {ENTRY})")
    cli.add_argument("--verification-key", type=Path, required=True)
    cli.add_argument("--input-sources", type=Path, help="ordered JSON of fixed scalars, nulls, widths, or inclusive bounds")
    cli.add_argument("--stack-schedule", choices=("compact", "baseline"), default="compact",
                     help="compact uses optimized field arithmetic and early checks (default: compact)")
    cli.add_argument("--script-era", choices=SCRIPT_ERAS, default="genesis",
                     help="allow Chronicle opcodes for outputs created after its activation")
    cli.add_argument("--arithmetic-plan", type=Path, help="replay an explicit Fp2 and residue lowering plan")
    layout = cli.add_mutually_exclusive_group()
    layout.add_argument("--objective", choices=OBJECTIVES, help="choose the verifier layout by a byte budget")
    layout.add_argument("--witness-layout", choices=LAYOUTS, help="pin the wire format (default: projective)")
    cli.add_argument("--owner", help="optional compressed secp256k1 public key in hex")
    cli.add_argument("--output", type=Path, required=True)
    cli.add_argument("--public", type=Path, help="full public statement for witness generation")
    cli.add_argument("--proof", type=Path, help="snarkjs proof.json")
    cli.add_argument("--witness-output", type=Path, help="write the push-only witness prefix in hex")
    args = cli.parse_args()
    witness_args = (args.public, args.proof, args.witness_output)
    if any(witness_args) and not all(witness_args):
        cli.error("--public, --proof, and --witness-output must be supplied together")
    if args.witness_output and args.witness_output.resolve() == args.output.resolve():
        cli.error("artifact and witness need separate output paths")
    try:
        key, source = args.verification_key.read_bytes(), args.source.read_bytes()
        sources = input_sources(args.input_sources.read_bytes()) if args.input_sources else None
        owner = bytes.fromhex(args.owner) if args.owner is not None else None
        compact = args.stack_schedule == "compact"
        plan = ArithmeticPlan.read(args.arithmetic_plan) if args.arithmetic_plan else None
        if args.objective:
            candidates = layout_candidates(key, source, sources, owner, compact=compact, script_era=args.script_era,
                                           entry=args.entry, source_path=args.source, plan=plan)
            verifier, artifact = select_layout(candidates, args.objective)
        else:
            verifier = ForthVerifier(key, source, witness_layout=args.witness_layout or "projective",
                                     script_era=args.script_era, entry=args.entry, source_path=args.source, plan=plan)
            lock = verifier.compile(sources, owner, compact=compact)
            artifact = verifier.artifact(sources, owner, lock, compact=compact)
        witness = None
        if args.proof:
            signals = public_signals(args.public.read_bytes())
            witness = verifier.witness(signals, args.proof.read_bytes(), sources=sources)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(artifact, indent=2) + "\n")
        if witness is not None:
            args.witness_output.parent.mkdir(parents=True, exist_ok=True)
            args.witness_output.write_text(witness.hex() + "\n")
    except (OSError, ValueError, KeyError, TypeError) as error:
        cli.error(str(error))


if __name__ == "__main__":
    main()
