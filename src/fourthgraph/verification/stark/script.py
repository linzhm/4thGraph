"""Lower a fixed AIR and its Plonky3 SHA-256 FRI opening argument to BSV Script."""

from functools import cache, reduce

from fourthgraph.bsv.script import asm, push
from fourthgraph.compiler.graph_source import render_assertion_graph
from fourthgraph.compiler.linear_form import WeightedDifferences
from fourthgraph.compiler.packed_lookup import PackedLookup
from fourthgraph.compiler.script_builder import ScriptBuilder
from fourthgraph.compiler.stack_schedule import Graph

from .proof import DIGEST, LOG_LDE, LOG_TRACE, QUERIES, Packet, Transcript, read_header

PLANS = ("baseline", "schedule", "lookup", "affine")
DEFAULT_PLAN = PLANS[-1]


@cache
def opcode(name):
    return asm(name)


@cache
def point_table(profile):
    root = profile.subgroup_root(LOG_LDE)

    def rows():
        for index in range(1 << LOG_LDE):
            exponent = sum((index >> j & 1) << (LOG_LDE - 1 - j) for j in range(LOG_LDE))
            subgroup = pow(root, exponent, profile.modulus)
            point = profile.generator * subgroup % profile.modulus
            yield profile.encode(point) + profile.encode(pow(subgroup, -1, profile.modulus))
    return PackedLookup.from_rows(rows())


class Script:
    def __init__(self, profile, source, *, plan=DEFAULT_PLAN):
        if plan not in PLANS:
            raise ValueError(f"unknown STARK lowering plan {plan!r}")
        self.plan = plan
        self.profile = profile
        self.p = profile.modulus
        self.d = profile.dimension
        self.zero = (0,) * self.d
        self.one = self.base(1)
        self.graph = Graph(1)
        self.checks = []
        self.sections = {}
        self.fragments = {}
        self.source = source
        self.builder = ScriptBuilder.from_file(source)
        packet, = self.graph.inputs
        self.packet = Packet(lambda offset, width: self.slice(packet, offset, width))

    def section(self, label):
        self.sections[len(self.graph.inputs) + len(self.graph.definitions)] = label

    def value(self, value):
        if isinstance(value, bytes):
            return self.graph.define(push(value))
        return self.graph.integer(value) if type(value) is int else value

    def op(self, name, *args):
        return self.graph.define(opcode(name), tuple(map(self.value, args)))

    def fragment(self, name, *args, parameters=()):
        code = self.builder.emit(name, b"", *parameters)
        if not parameters:
            self.fragments[code] = name
        return self.graph.define(code, tuple(map(self.value, args)))

    def slice(self, value, offset, width):
        return self.graph.packet_slice(value, offset, width)

    def concat(self, *parts):
        return reduce(lambda a, b: self.op("OP_CAT", a, b), parts)

    def unsigned(self, data):
        return self.fragment("stark-le-unsigned", data)

    def decode(self, data, count):
        values = tuple(self.unsigned(self.slice(data, i * self.profile.width, self.profile.width))
                       for i in range(count))
        self.checks.extend(self.op("OP_LESSTHAN", value, self.p) for value in values)
        return values

    def encode(self, values):
        return self.concat(*(self.fragment("stark-unsigned-le", value, parameters=(self.profile.width,))
                             for value in values))

    def read_extension(self):
        return self.decode(self.packet.take(self.profile.extension_width), self.d)

    def base(self, number):
        return (number, *self.zero[1:])

    def mod(self, value):
        return value % self.p if type(value) is int else self.op("OP_MOD", value, self.p)

    def add_base(self, a, b):
        if type(a) is type(b) is int:
            return a + b
        if a == 0 or b == 0:
            return b if a == 0 else a
        return self.op("OP_ADD", a, b)

    def mul_base(self, a, b):
        if type(a) is type(b) is int:
            return a * b
        if a == 0 or b == 0:
            return 0
        if a == 1 or b == 1:
            return b if a == 1 else a
        return self.op("OP_MUL", a, b)

    def add(self, a, b):
        return tuple(self.mod(self.add_base(x, y)) for x, y in zip(a, b, strict=True))

    def sub(self, a, b):
        # Both operands are canonical, so x + p - y is nonnegative.
        return tuple(self.mod(self.op("OP_SUB", self.add_base(x, self.p), y))
                     if y != 0 else x for x, y in zip(a, b, strict=True))

    def scale(self, value, scalar):
        return tuple(self.mod(self.mul_base(x, scalar)) for x in value)

    def mul(self, left, right):
        # Multiply in F[u]/(u^d - w), reducing once per output coefficient.
        coefficients = [0] * self.d
        for i, a in enumerate(left):
            for j, b in enumerate(right):
                power = i + j
                term = self.mul_base(a, b)
                if power >= self.d:
                    term = self.mul_base(term, self.profile.nonresidue)
                k = power % self.d
                coefficients[k] = self.add_base(coefficients[k], term)
        return tuple(map(self.mod, coefficients))

    def extension_equal(self, left, right):
        self.checks.extend(self.op("OP_NUMEQUAL", a, b) for a, b in zip(left, right, strict=True))

    def extension_nonzero(self, value):
        total = 0
        for limb in value:
            total = self.add_base(total, limb)
        self.checks.append(self.op("OP_0NOTEQUAL", total))

    def check_air(self, public, alpha, zeta, local, following, quotient_openings):
        # Multiply the out-of-domain identity by (zeta-1)(zeta-last_point).
        omega = self.profile.subgroup_root(LOG_TRACE)
        first_delta = self.sub(zeta, self.one)
        last_delta = self.sub(zeta, self.base(pow(omega, -1, self.p)))
        vanishing = zeta
        for _ in range(LOG_TRACE):
            vanishing = self.mul(vanishing, vanishing)
        vanishing = self.sub(vanishing, self.one)
        self.extension_nonzero(vanishing)
        deltas = self.mul(first_delta, last_delta)
        first_selector = self.mul(vanishing, last_delta)
        transition_selector = self.mul(deltas, last_delta)
        last_selector = self.mul(vanishing, first_delta)

        a, b, result = map(self.base, public)
        left, right = local
        next_left, next_right = following
        terms = (
            (first_selector, self.sub(left, a)),
            (first_selector, self.sub(right, b)),
            (transition_selector, self.sub(right, next_left)),
            (transition_selector, self.sub(self.add(left, right), next_right)),
            (last_selector, self.sub(right, result)),
        )
        accumulator = self.zero
        for selector, difference in terms:
            accumulator = self.add(self.mul(alpha, accumulator), self.mul(selector, difference))

        quotient = self.zero
        for i, value in enumerate(quotient_openings):
            basis = tuple(int(j == i) for j in range(self.d))
            quotient = self.add(quotient, self.mul(basis, value))
        self.extension_equal(accumulator, self.mul(quotient, self.mul(vanishing, deltas)))

    def query_bits(self, index):
        bits = []
        for _ in range(LOG_LDE):
            bits.append(self.op("OP_MOD", index, 2))
            index = self.op("OP_DIV", index, 2)
        return tuple(bits)

    def query_points(self, index, bits):
        if self.plan in {"lookup", "affine"}:
            row = point_table(self.profile).emit(self.graph, index)
            width = self.profile.width
            return tuple(self.unsigned(self.slice(row, i * width, width)) for i in range(2))
        # Each bit selects its fixed factor in the bit-reversed exponent.
        root = self.profile.subgroup_root(LOG_LDE)
        point, inverse = self.profile.generator, 1
        for j, bit in enumerate(bits):
            factor = pow(root, 1 << (LOG_LDE - 1 - j), self.p)
            for_inverse = pow(factor, -1, self.p)
            point_factor = self.op("OP_IF OP_NIP OP_ELSE OP_DROP OP_ENDIF", 1, factor, bit)
            inv_factor = self.op("OP_IF OP_NIP OP_ELSE OP_DROP OP_ENDIF", 1, for_inverse, bit)
            point = self.mod(self.mul_base(point, point_factor))
            inverse = self.mod(self.mul_base(inverse, inv_factor))
        return point, inverse

    def merkle(self, row, bits, root):
        current = self.fragment("stark-leaf-hash", row)
        for bit in bits:
            sibling = self.packet.take(DIGEST)
            pair = self.fragment("stark-order-pair", current, sibling, bit)
            current = self.fragment("stark-node-hash", pair)
        self.checks.append(self.op("OP_EQUAL", current, root))

    def check_query(self, index, header, opened, final, transcript, weights, forms):
        bits = self.query_bits(index)
        x, inverse_x = self.query_points(index, bits)
        reciprocal = self.read_extension()

        trace_row = self.packet.take(2 * self.profile.width)
        trace = self.decode(trace_row, 2)
        self.merkle(trace_row, bits, header.trace)
        quotient_row = self.packet.take(self.profile.extension_width)
        quotient = self.decode(quotient_row, self.d)
        self.merkle(quotient_row, bits, header.quotient)

        zeta = transcript.zeta
        next_zeta = self.scale(zeta, self.profile.subgroup_root(LOG_TRACE))
        d0 = self.sub(zeta, self.base(x))
        d1 = self.sub(next_zeta, self.base(x))
        self.extension_equal(self.mul(reciprocal, self.mul(d0, d1)), self.one)
        if forms:
            local, following = (form.evaluate(trace + quotient, scale=self.scale, subtract=self.sub) for form in forms)
        else:
            local, following = self.zero, self.zero
            for i, (claim, at_x, weight) in enumerate(zip(opened, trace + trace + quotient, weights, strict=True)):
                term = self.mul(self.sub(claim, self.base(at_x)), weight)
                if i in (2, 3):
                    following = self.add(following, term)
                else:
                    local = self.add(local, term)
        folded = self.mul(self.add(self.mul(local, d1), self.mul(following, d0)), reciprocal)

        half = (self.p + 1) // 2
        for round_index, (beta, root) in enumerate(zip(transcript.betas, header.fri, strict=True)):
            sibling = self.read_extension()
            row = self.fragment("stark-order-pair", self.encode(folded), self.encode(sibling), bits[round_index])
            self.merkle(row, bits[round_index + 1:], root)
            even = self.scale(self.add(folded, sibling), half)
            odd = self.scale(self.sub(folded, sibling), self.mod(self.mul_base(inverse_x, half)))
            folded = self.add(even, self.mul(beta, odd))
            inverse_x = self.mod(self.mul_base(inverse_x, inverse_x))
        self.extension_equal(folded, final)

    def build_graph(self, public):
        self.section("Read commitments and derive Fiat-Shamir challenges")
        header = read_header(self.profile, self.packet)
        transcript = Transcript(self.profile, public, header, script=self)
        opened = tuple(self.decode(value, self.d) for value in header.opened)
        final = self.decode(header.final, self.d)
        self.section("Check the AIR quotient at the out-of-domain point")
        self.check_air(public, transcript.alpha, transcript.zeta, opened[:2], opened[2:4], opened[4:])

        self.section("Prepare the weighted PCS openings")
        weights = [self.one]
        for _ in opened[1:]:
            weights.append(self.mul(weights[-1], transcript.rho))
        forms = ()
        if self.plan == "affine":
            cols = tuple(range(2 + self.d))
            forms = (
                WeightedDifferences.lower(opened[:2] + opened[4:], weights[:2] + weights[4:], cols,
                                          zero=self.zero, add=self.add, multiply=self.mul),
                WeightedDifferences.lower(opened[2:4], weights[2:4], cols[:2],
                                          zero=self.zero, add=self.add, multiply=self.mul),
            )
        for query in range(QUERIES):
            self.section(f"Query {query + 1}: authenticate PCS rows and check four FRI folds")
            self.check_query(transcript.query_index(), header, opened, final, transcript, weights, forms)

        assert self.packet.offset == self.profile.witness_size

    def generate(self, public):
        """Produce the complete Forth source for the selected public statement."""
        self.build_graph(public)
        schedule = "ordered" if self.plan == "baseline" else "compact"
        checks = render_assertion_graph(self.graph, self.checks, "stark-assertions", schedule=schedule,
                                       input_names=("packet",), sections=self.sections, fragments=self.fragments)
        return (
            f"( Generated {self.profile.name} STARK verifier, plan {self.plan}. )\n"
            f"{self.source.read_text(encoding='utf-8')}\n{checks}\n"
            ": stark-lock ( -- script )\n"
            f"    bsv-empty {self.profile.witness_size} bsv-empty stark-assertions verify-proof\n"
            ";\n"
        )
