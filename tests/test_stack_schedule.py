"""Cross-backend checks for Script graph lowering."""

import unittest

from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.bsv.script import asm, decode_num, encode_num, push
from fourthgraph.compiler.graph_source import render_assertion_graph
from fourthgraph.compiler.linear_form import WeightedDifferences
from fourthgraph.compiler.packed_lookup import PackedLookup
from fourthgraph.compiler.script_builder import ScriptBuilder
from fourthgraph.compiler.stack_schedule import Graph, Value, emit_steps


class StackScheduleTests(unittest.TestCase):
    def test_select_expansion_reuses_the_parent_graph_and_discards_other_definitions(self):
        graph = Graph(1)
        value, = graph.inputs
        twice = graph.define(asm("OP_ADD"), (value, value))

        def lower(plan, trial):
            if plan == "product":
                two = trial.integer(2)
                return trial.define(asm("OP_MUL"), (value, two)), 1
            return trial.define(asm("OP_ADD"), (value, value)), 1

        plan, outputs = graph.select_expansion(("product", "sum"), lower)
        self.assertEqual((plan, outputs), ("sum", (twice, 1)))
        self.assertEqual(tuple(graph.definitions), (twice,))
        two = graph.integer(2)
        self.assertEqual(graph.definitions[two].script, asm("OP_2"))
        finished = graph.define(asm("OP_SUB"), (twice, two))
        self.assertEqual(evaluate(graph.emit((finished,), compact=True), [encode_num(-4)]),
                         ([encode_num(-10)], []))

    def test_compact_schedule_keeps_a_live_right_operand(self):
        graph = Graph(2)
        left, right = graph.inputs
        first = graph.define(asm("OP_SUB"), (left, right))
        second = graph.define(asm("OP_SUB"), (first, right))
        compact = graph.emit((second,), compact=True)
        self.assertEqual(compact, asm("OP_TUCK OP_SUB OP_SWAP OP_SUB"))
        for a, b in ((12, 5), (3, -7), (-2, 4)):
            prefix = b"caller"
            stack = [prefix, encode_num(a), encode_num(b)]
            result = [prefix, encode_num(a - 2 * b)]
            self.assertEqual(evaluate(compact, stack), (result, []))
            self.assertEqual(evaluate(graph.emit((second,)), stack), (result, []))

    def test_compact_schedule_repushes_single_byte_literals(self):
        steps = [
            (asm("OP_1"), (), (1,)),
            (asm("OP_SUB"), (0, 1), (2,)),
            (asm("OP_SUB"), (2, 1), (3,)),
        ]
        compact = emit_steps((0,), steps, (3,), compact=True)
        self.assertEqual(compact, asm("OP_1 OP_SUB OP_1 OP_SUB"))
        for returns, expected in (((3,), (5,)), ((3, 1), (5, 1))):
            for compact in (False, True):
                script = emit_steps((0,), steps, returns, compact=compact)
                self.assertEqual(evaluate(script, [encode_num(7)]), (list(map(encode_num, expected)), []))

    def test_assertions_consume_flags_and_preserve_other_uses(self):
        graph = Graph(1)
        operand, = graph.inputs
        flag = graph.define(asm("OP_0NOTEQUAL"), (operand,))
        one = graph.define(asm("OP_1"))
        equal = graph.define(asm("OP_EQUAL"), (flag, one))
        script = graph.emit_assertions((equal, flag, flag), compact=True)
        self.assertEqual(script, graph.emit_assertions((flag, equal), compact=True))
        self.assertIn(asm("OP_EQUALVERIFY"), script)
        prefix = b"underneath"
        self.assertEqual(evaluate(script, [prefix, encode_num(-1)]), ([prefix], []))
        with self.assertRaises(ScriptError):
            evaluate(script, [prefix, b""])

    def test_numeric_boolean_folds_nonzero_without_changing_other_uses(self):
        for opcode, operation in (("OP_BOOLOR", lambda a, b: a or b), ("OP_BOOLAND", lambda a, b: a and b)):
            with self.subTest(opcode=opcode):
                graph = Graph(2, compact_booleans=True)
                a, b = graph.inputs
                nonzero_a = graph.define(asm("OP_0NOTEQUAL"), (a,))
                nonzero_b = graph.define(asm("OP_0NOTEQUAL"), (b,))
                flag = graph.define(asm(opcode), (nonzero_a, nonzero_b))
                self.assertEqual(graph.emit((flag,), compact=True), asm(opcode))
                preserving = graph.emit((flag, nonzero_a), compact=True)
                for left, right in ((0, 0), (0, 9), (-14, 0), (-5, 8)):
                    stack = list(map(encode_num, (left, right)))
                    expected = list(map(encode_num, (int(bool(operation(left, right))), int(left != 0))))
                    self.assertEqual(evaluate(preserving, stack), (expected, []))

    def test_input_assertions_and_undefined_flags(self):
        graph = Graph(1)
        self.assertEqual(graph.emit_assertions(graph.inputs, compact=True), asm("OP_VERIFY"))
        with self.assertRaisesRegex(ValueError, "undefined"):
            graph.emit_assertions((Value(1),))

    def test_assertion_schedule_selects_the_shorter_order(self):
        for order, dependencies_win in (((0, 2, 1, 3), True), ((0, 1, 2, 3), False)):
            with self.subTest(order=order):
                graph = Graph(4)
                a, b, c, d = (graph.inputs[index] for index in order)
                difference = graph.define(asm("OP_SUB"), (a, b))
                first = graph.define(asm("OP_0NOTEQUAL"), (c,))
                balance = graph.define(asm("OP_SUB"), (difference, d))
                second = graph.define(asm("OP_NOT"), (balance,))
                source = graph.emit_assertions((first, second), compact=True)
                chosen = graph.emit_assertions((second, first), compact=True, reorder=True)
                if dependencies_win:
                    self.assertLess(len(chosen), len(source))
                    self.assertLess(chosen.index(asm("OP_VERIFY")), chosen.index(asm("OP_SUB")))
                else:
                    self.assertEqual(chosen, source)

                prefix = b"unrelated stack item"
                for values, accepted in (((8, 3, 1, 5), True), ((8, 3, 0, 5), False), ((8, 3, 1, 4), False)):
                    stack = [prefix, *map(encode_num, (values[order.index(index)] for index in range(4)))]
                    for script in (source, chosen):
                        if accepted:
                            self.assertEqual(evaluate(script, stack), ([prefix], []))
                        else:
                            with self.assertRaises(ScriptError):
                                evaluate(script, stack)

    def test_forth_assertion_graph_round_trips_with_numeric_verification(self):
        graph = Graph(1)
        packet, = graph.inputs
        a = graph.packet_slice(packet, 0, 1)
        b = graph.packet_slice(packet, 1, 1)
        total = graph.define(asm("OP_ADD"), (a, b))
        flag = graph.define(asm("OP_NUMEQUAL"), (total, graph.integer(7)))
        prefix = b"caller"
        for schedule in ("ordered", "compact"):
            with self.subTest(schedule=schedule):
                src = render_assertion_graph(graph, (flag,), "check-total", schedule=schedule, input_names=("packet",))
                builder = ScriptBuilder(src + ": lock ( -- script ) bsv-empty check-total op-1 ;\n")
                script = builder.emit("lock")
                expected = graph.emit_assertions((flag,), compact=True, optimize=schedule == "compact") + asm("OP_1")
                self.assertEqual(script, expected)
                self.assertEqual(asm("OP_NUMEQUALVERIFY") in script, schedule == "compact")
                self.assertEqual(evaluate(script, [prefix, b"\x03\x04"]), ([prefix, b"\x01"], []))
                for packet in (b"\x03\x05", b"\x07"):
                    with self.assertRaises(ScriptError):
                        evaluate(script, [prefix, packet])

    def test_forth_assertion_graph_reports_undefined_fragments_and_labels(self):
        for body, error in (
            ("v apply bad-word let a a assert", "declared"),
            ("v apply op-1 let v v assert", "repeated"),
            ("v slice 0 0 let a a assert", "positive width"),
            ("v v assert", "one named value"),
        ):
            with self.subTest(body=body), self.assertRaisesRegex(ValueError, error):
                ScriptBuilder(f"assertion-graph: check-total compact {{: v :}} {body} ;")

    def test_packed_lookup_enforces_table_bounds(self):
        graph = Graph(1)
        index, = graph.inputs
        rows = (b"a\x00", b"bc", b"\x80\xff")
        looked_up = PackedLookup.from_rows(rows).emit(graph, index)
        script = graph.emit((looked_up,), compact=True)
        for i, expected in enumerate(rows):
            self.assertEqual(evaluate(script, [b"caller", encode_num(i)]), ([b"caller", expected], []))
        for i in (-1, len(rows), 10**18):
            with self.assertRaises(ScriptError):
                evaluate(script, [encode_num(i)])
        with self.assertRaises(ValueError):
            PackedLookup.from_rows((b"a", b"bc"))

    def test_weighted_differences_combine_repeated_columns_in_a_ring(self):
        modulus = 97

        def add(left, right):
            return (left + right) % modulus

        def subtract(left, right):
            return (left - right) % modulus

        def multiply(left, right):
            return (left * right) % modulus

        openings, weights, columns = (9, 27, 32), (11, 13, 16), (1, 0, 1)
        form = WeightedDifferences.lower(openings, weights, columns, zero=0, add=add, multiply=multiply)
        self.assertEqual(dict(form.weights), {0: 13, 1: 27})
        for row in ((0, 0), (-2, 94), (modulus - 1, modulus)):
            expected = sum(w * (opening - row[column]) for opening, w, column in zip(openings, weights, columns))
            actual = form.evaluate(row, scale=multiply, subtract=subtract)
            self.assertEqual(actual, expected % modulus)

    def test_packet_slices_use_the_unread_suffix(self):
        prefix, packet = b"caller", b"ab--cdxyz"
        for chronicle in (False, True):
            graph = Graph(1)
            value, = graph.inputs
            checks = []
            for offset, expected in ((0, b"AB"), (4, b"CD"), (6, b"XY")):
                decoded = graph.packet_slice(value, offset, 2, decode=push(b"  ") + asm("OP_XOR"),
                                             chronicle=chronicle)
                literal = graph.define(push(expected))
                checks.append(graph.define(asm("OP_EQUAL"), (decoded, literal)))
            baseline = graph.emit_assertions(checks)
            compact = graph.emit_assertions(checks, compact=True, reorder=True)
            self.assertLess(len(compact), len(baseline))

            def observe(main, alt):
                self.assertLessEqual(main.count(packet) + alt.count(packet), 1)

            self.assertEqual(evaluate(compact, [prefix, packet], observe_stack=observe), ([prefix], []))
            for malformed in (packet[:7], b"ab--zzxyz"):
                for script in (baseline, compact):
                    with self.assertRaises(ScriptError):
                        evaluate(script, [prefix, malformed])

    def test_packet_slices_keep_random_access_for_other_uses(self):
        for offsets, check_packet in (((2, 0), False), ((0, 1), False), ((0, 2), True)):
            with self.subTest(offsets=offsets, check_packet=check_packet):
                graph = Graph(1)
                packet, = graph.inputs
                chunks = [graph.packet_slice(packet, offset, 2) for offset in offsets]
                checks = [graph.define(asm("OP_EQUAL"), tuple(chunks))]
                if check_packet:
                    literal = graph.define(push(b"aaaa"))
                    checks.append(graph.define(asm("OP_EQUAL"), (packet, literal)))
                plain = graph.emit_assertions(checks, compact=True)
                graph.packet_reads.clear()
                self.assertEqual(plain, graph.emit_assertions(checks, compact=True))
                self.assertEqual(evaluate(plain, [b"aaaa"]), ([], []))

    def test_residue_block_defers_polynomial_remainders(self):
        graph = Graph(2)
        left, right = graph.inputs
        block = graph.residue_block(5)
        divisor = block.integer(5)
        baseline = graph.remainder(graph.define(asm("OP_ADD"), (graph.remainder(left, divisor),
                                                                 graph.remainder(right, divisor))), divisor)
        operands = (block.remainder(left, divisor), block.remainder(right, divisor))
        value = block.define(asm("OP_ADD"), operands)
        reduced = graph.remainder(value, divisor, reuse=True)
        self.assertEqual(graph.remainder(reduced, divisor, reuse=True), reduced)
        start = list(map(encode_num, (12, -9)))
        eager, _ = evaluate(graph.emit((baseline,)), start)
        deferred, _ = evaluate(graph.emit((reduced,)), start)
        self.assertEqual(tuple(map(decode_num, eager + deferred)), (-2, 3))
        self.assertEqual(decode_num(eager[0]) % 5, decode_num(deferred[0]) % 5)

    def test_residue_block_rejects_operations_that_observe_representatives(self):
        graph = Graph(1)
        value, = graph.inputs
        with self.assertRaisesRegex(ValueError, "positive integer modulus"):
            graph.residue_block(0)
        block = graph.residue_block(5)
        with self.assertRaisesRegex(ValueError, "polynomial arithmetic"):
            block.define(asm("OP_0NOTEQUAL"), (value,))
        with self.assertRaisesRegex(ValueError, "declared modulus"):
            block.remainder(value, block.integer(7))
