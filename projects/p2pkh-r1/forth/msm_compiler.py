"""R1 preflight and construction of a lock and its matching OTDA program."""

from dataclasses import replace
from functools import cached_property
from hashlib import sha256
from pathlib import Path

from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.otda_reconstruction import Reconstruction
from fourthgraph.compiler.ranges import Slot, primitive_outputs
from fourthgraph.compiler.script_builder import ScriptBuilder, build_word
from fourthgraph.compiler.wordsets import PRIMITIVES

from fixed_templates import compiled_template
from msm_lowering import FIELD, INFINITY, ORDER, Strategy, WindowPlan, constant_point
from msm_lowering import opcode_count, reconstruction, window_program

SOURCE = Path(__file__).with_name("msm.fth")
OWNER = bytes(range(20))
CALIBRATION = ("split-4", "joint-2", "split-5x4")
# Serialized size of the shared two-input, two-output fixture minus its locks.
BIP143_FRAMING = 770
OTDA_FRAMING = {"otda-all": 50, "otda-single": -21}


def site(token):
    return {"file": token.module or SOURCE.name, "line": token.line, "column": token.column}


def payment_estimates(lock_bytes, otda_bytes):
    bip143 = 2 * lock_bytes + BIP143_FRAMING
    return {"bip143-all": bip143, **{mode: bip143 + 2 * otda_bytes + framing
                                    for mode, framing in OTDA_FRAMING.items()}}


class R1MSMCompiler:
    def __init__(self, source_path=SOURCE):
        self.source_path = source_path.resolve()
        self.source = self.source_path.read_bytes()
        self.reference = compiled_template(scheduled=True)
        self.frontend = self.builder(optimize=False)
        self.prepare = self.frontend.emit("r1-msm-before", b"")
        # The fixed template contains the audited guard and scalar derivation.
        # Split at its first fixed-G table row without expanding any source loop.
        marker = INFINITY + constant_point(1)
        reference = self.reference.lock(OWNER)
        if reference.count(marker) != 1 or self.prepare != reference.split(marker, 1)[0]:
            raise ValueError("r1-msm-before does not preserve the verified point guard, scalar reduction and stack layout")
        if self.prepare.count(OWNER) != 1:
            raise ValueError("the R1 prologue needs one owner field")
        self.bounds = {}
        for name, bounds in (("msm-scalar", (0, ORDER - 1)), ("msm-affine", (0, FIELD - 1)),
                             ("msm-projective", (1 - FIELD, FIELD - 1))):
            declared = self.frontend.ranges.get(name)
            if declared is None or declared.slot != Slot("script-int", bounds):
                raise ValueError(f"{name} must declare the range proved by the R1 prologue: {bounds}")
            self.bounds[name] = declared.slot
        word = self.frontend.words["r1-mul2"]
        primitive = self.frontend.words["p256.mul2"]
        if len(word.body) != 1 or word.body[0].instruction is not primitive:
            raise ValueError("r1-mul2 must call the P256.mul2 intrinsic once")
        self.location = site(word.body[0].source)
        self.bits = self.bounds["msm-scalar"].bounds[1].bit_length()

    def builder(self, *, optimize):
        return ScriptBuilder(self.source.decode(), source_path=self.source_path, optimize=optimize, vocabulary={
            "bsv-owner": build_word("", "bytes", lambda: OWNER),
            "p256.mul2": build_word("script script", "script", bytes.__add__),
        })

    @cached_property
    def optimized(self):
        compiler = self.builder(optimize=True)
        changed = set(self.frontend.library_imports).symmetric_difference(compiler.library_imports)
        if changed:
            names = ", ".join(sorted({entry.name for entry in changed}))
            raise ValueError(f"required Forth dependencies changed after R1 preflight: {names}")
        return compiler

    @cached_property
    def source_identity(self):
        return {
            "source_sha256": sha256(self.source).hexdigest(),
            "dependencies": {entry.name: entry.sha256 for entry in self.frontend.library_imports},
        }

    def plan(self, name):
        try:
            return WindowPlan(Strategy.parse(name), self.bits)
        except ValueError as error:
            location = self.location
            raise ValueError(f"{location['file']}:{location['line']}:{location['column']}: {error}") from error

    def scan(self, plan):
        strategy = plan.strategy
        counts = plan.counts()
        digit_ranges = {}
        for name, width in (("G", strategy.width), ("Q", strategy.q_width or strategy.width)):
            divisor = Slot("script-int", (1 << width, 1 << width))
            digit, = primitive_outputs(PRIMITIVES["int-rem"], (self.bounds["msm-scalar"], divisor))
            digit_ranges[name] = list(digit.bounds)

        opportunities = []
        if counts["g_adds"]:
            sites = counts["g_adds"]
            guard_bytes = 3 if strategy.affine_guard_ifdup else 5
            opportunities.append({
                "id": "affine-g", "source": self.location, "calls": sites,
                "proven": [
                    "0 <= digit < 2^width", "G has order n and 2^width < n",
                    "G[0] is infinity; every nonzero G entry is emitted with Z=1",
                ],
                "requirements": ["use only the separate G table", "guard digit zero before substituting Z=1"],
                "missing": [] if strategy.affine_g else ["guard and five-input affine lowering in the current candidate"],
                "equivalence": "the finite result represents the same group point and infinity is preserved",
                "estimated": {"multiplications_removed": 3 * sites, "branch_opcode_bytes_added": guard_bytes * sites,
                              "lookup_opcode_bytes_removed": 3 * sites},
                "try": strategy.name if strategy.affine_g else strategy.name + "-affine-g",
                "priority": 3 * sites,
            })
            if strategy.affine_g and not strategy.affine_guard_ifdup:
                opportunities.append({
                    "id": "affine-g-ifdup", "source": self.location, "calls": sites,
                    "proven": ["the digit is a bounded nonnegative Script number",
                               "the nonzero branch consumes its digit in the lookup",
                               "the zero branch only discards the digit"],
                    "requirements": ["preserve the accumulator for zero", "retain one digit for nonzero"],
                    "missing": [],
                    "equivalence": "both guards leave the same stack at lookup entry or after skipping zero",
                    "estimated": {"window_loop_bytes_saved": 2 * sites},
                    "try": strategy.name + "-ifdup", "priority": 2 * sites,
                })
        else:
            opportunities.append({
                "id": "affine-g", "source": self.location, "calls": 0,
                "proven": ["only the fixed G-only row has a uniform affine encoding"],
                "requirements": ["every selected nonzero right operand must have Z=1", "handle infinity separately"],
                "missing": ["joint entries that contain Q have no proof of Z=1"],
                "equivalence": "the finite result represents the same group point and infinity is preserved",
                "estimated": None, "try": None, "priority": 0,
            })
        joint = self.plan("joint-2").counts()
        opportunities.append({
            "id": "joint-table", "source": self.location, "calls": counts["digit_rounds"],
            "proven": ["joint index is u_digit * radix + v_digit",
                       "each table entry represents u_digit*G + v_digit*Q"],
            "requirements": ["same digit width for G and Q", "joint table fits the backend budget"],
            "missing": [] if strategy.q_width is None else ["common digit width for a direct table replacement"],
            "equivalence": "same group result for every u,v in the declared scalar range",
            "estimated": {"joint_2_setup_adds_delta": joint["setup_adds"] - counts["setup_adds"],
                          "joint_2_loop_adds_delta": joint["loop_adds"] - counts["loop_adds"],
                          "joint_2_loop_doubles_delta": joint["loop_doubles"] - counts["loop_doubles"]},
            "try": "joint-2" if not strategy.joint else None, "priority": counts["digit_rounds"],
        })
        return {
            **self.source_identity, "intrinsic": "P256.mul2(u,G,v,Q)", "source": self.location,
            "candidate": strategy.name, "scalar_bits": self.bits,
            "ranges_inclusive": {name: list(map(str, slot.bounds)) for name, slot in self.bounds.items()},
            "runtime_point_check": site(self.frontend.definitions["r1-check-r1-fields"]),
            "runtime_scalar_derivation": site(self.frontend.definitions["r1-prepare-scalars"]),
            "digit_ranges_inclusive": digit_ranges, "table_points": plan.table_points,
            "unexpanded_counts": counts,
            "opportunities": sorted(opportunities, key=lambda row: -row["priority"]),
        }

    @cached_property
    def kernels(self):
        return tuple(self.optimized.emit(name, b"") for name in ("r1-add-points", "r1-double-point"))

    @cached_property
    def affine(self):
        formula = self.optimized.formula_ir["r1-add-points"].bind_input(5, 1)
        return formula.lower(optimize=True, specialized=True)

    def lower(self, plan):
        if plan.bits != self.bits:
            raise ValueError("window plan must use the scalar range proved by the source")
        affine = self.affine[0] if plan.strategy.affine_g else None
        return window_program(plan, *self.kernels, affine=affine)

    def finish(self, slots):
        if slots % 2:
            raise ValueError("R1 table cleanup expects an even number of stack slots")
        return self.optimized.emit("r1-msm-after", b"", slots, (slots + 6) // 2)

    def link(self, program):
        prefix, before = self.prepare.split(OWNER)
        after = self.finish(program.table_slots)
        # Both consumers use the same ordered pieces and repetition counts.
        window = self.optimized.emit("r1-mul2", b"", program.emit())
        suffix = before + window + after
        raw = prefix + bytes(len(OWNER)) + suffix
        encoded = reconstruction(prefix, before, program.pieces, after, program.kernels)
        if evaluate(encoded) != ([prefix, suffix], []):
            raise ValueError("OTDA reconstruction does not reproduce the selected lock bytes")
        lock = replace(self.reference, script=raw, owner_start=len(prefix))
        return lock, Reconstruction(encoded, (prefix, suffix), (len(OWNER),))

    def local_cost(self, plan, program):
        # Reuse the counted pieces without expanding the loop for this estimate.
        add, _ = self.kernels
        costs = {"window_sections_bytes": program.sections,
                 "window_bytes": sum(program.sections.values()),
                 "static_window_mul_opcodes": sum(opcode_count(raw, "OP_MUL") * count
                                                  for raw, count in program.pieces)}
        if plan.strategy.affine_g:
            affine, report = self.affine
            calls = plan.counts()["g_adds"]
            guard_bytes = 3 if plan.strategy.affine_guard_ifdup else 5
            costs["affine_g"] = {
                "calls": calls, "generic_kernel_bytes": len(add), "affine_kernel_bytes": len(affine),
                "kernel_bytes_saved": (len(add) - len(affine)) * calls,
                "lookup_bytes_saved": 3 * calls, "guard_bytes_added": guard_bytes * calls,
                "multiplications_removed_on_nonzero_path": (opcode_count(add, "OP_MUL") -
                                                           opcode_count(affine, "OP_MUL")) * calls,
                "formula": report,
            }
        return costs
