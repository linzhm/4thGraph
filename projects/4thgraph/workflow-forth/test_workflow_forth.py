"""Forth workflow declarations, signing coverage and serial Script binding."""

from dataclasses import replace
import os
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest

from build import CompileError, load_plan, lower_serial, parse_plan
from compiler import SourceCompiler
from replay import Replay, TestKeys
from shared.benchmark_validation import Node
from shared.chain_gang import validate_at_heights
from shared.transaction import Input, Transaction
from workflow_contract import WorkflowContracts


HERE = Path(__file__).resolve().parent
COUNTER = HERE / "counter.fth"
RULES = HERE / "counter-rules.fth"
FORTH = shutil.which(os.environ.get("GFORTH", "gforth"))


def row(name, consumes, produces, *, ins=(0, 0, -1, 0, 0), outs=(0, 0, -1, 0, 0),
        modes=(0x41,), amount=0, policy=0):
    fields = (*modes, *ins, *outs, len(consumes), *consumes, len(produces), *produces)
    return " ".join(map(str, ("stage", name, "rule?", "owner", policy, amount, len(modes), *fields)))


def plan(*entries):
    return parse_plan("\n".join(("roots 1 0", *entries)))


class PlanTests(unittest.TestCase):
    def test_topological_order_preserves_join_slot_order_and_conflicts(self):
        entries = (
            row("fork", (0,), (1, 2)), row("b", (2,), (4,)), row("a", (1,), (3,)),
            row("join", (4, 3), (5,), policy=2), row("recover-a", (3,), (6,)),
        )
        graph = plan(*entries).describe()
        self.assertEqual(graph, plan(*reversed(entries)).describe())
        self.assertEqual([step["name"] for step in graph["steps"]], ["fork", "a", "b", "join", "recover-a"])
        self.assertEqual(graph["steps"][3]["inputs"], [(3, 0), (2, 0)])
        self.assertEqual(graph["steps"][3]["verification_policy"], "groth16-required")
        self.assertEqual(graph["conflicts"], [(2, 0, (4, 5))])

    def test_invalid_networks_are_rejected(self):
        cases = (
            ((row("a", (1,), (2,)),), "has no producer"),
            ((row("a", (0,), (1,)), row("b", (0,), (1,))), "multiple producers"),
            ((row("a", (1,), (2,)), row("b", (2,), (1,))), "stage dependency cycle"),
            ((row("a", (0,), (1,)), row("b", (0,), (2,)), row("join", (1, 2), (3,))),
             "required stages compete for resource 0"),
            ((row("a", (0, 0), (1,)),), "distinct unsigned 32-bit"),
        )
        for entries, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                plan(*entries)

    def test_fixed_and_dynamic_ranges_are_half_open_with_separate_count_bounds(self):
        a = plan(row("a", (0,), (1,), outs=(1, 2, 4, 1, 3))).describe()["steps"][0]
        self.assertEqual(a["output_selection"], {"kind": "range", "count": [2, 4], "index_range": [1, 3]})
        for out in ((1, 2, 4, 1, 1), (1, 2, 4, 4, 5), (1, 4, 2, 1, 2), (2, 0, -1, 0, 0)):
            with self.subTest(out=out), self.assertRaisesRegex(ValueError, "output"):
                plan(row("a", (0,), (1,), outs=out))

    def test_every_authorized_sighash_must_cover_the_selection(self):
        current = (2, 0, -1, 0, 0)
        paired = (3, 0, -1, 0, 0)
        none = (4, 0, -1, 0, 0)
        self.assertEqual(plan(row("a", (0,), (1,), ins=current, outs=paired, modes=(0x43, 0x63))).stages[0]
                         .sighashes, (0x43, 0x63))
        self.assertEqual(plan(row("a", (0,), (), ins=current, outs=none, modes=(0x42,))).stages[0].produces, ())
        self.assertEqual(plan(row("a", (0,), (1,), ins=current, modes=(0xc1,))).stages[0].sighashes, (0xc1,))
        cases = (
            ({"modes": (0x41, 0x42)}, "0x42.*NONE"),
            ({"modes": (0x41, 0x43)}, "0x43.*SINGLE"),
            ({"modes": (0x43,), "outs": (3, 0, 2, 0, 0)}, "SINGLE.*output count"),
            ({"modes": (0x63,), "outs": none}, "unselected outputs"),
            ({"modes": (0xc1,)}, "ANYONECANPAY"),
            ({"modes": (0xc1,), "ins": (2, 1, 1, 0, 0)}, "without an input count"),
            ({"modes": (0x61,), "amount": 1}, "OTDA omits.*amount"),
        )
        for options, message in cases:
            with self.subTest(options=options), self.assertRaisesRegex(ValueError, message):
                plan(row("a", (0,), (1,), **options))
        with self.assertRaisesRegex(ValueError, "SINGLE requires a paired output"):
            plan(row("a", (0,), (), modes=(0x63,), outs=none))
        self.assertEqual(plan(row("a", (0,), (1,), modes=(0x61,), amount=2)).stages[0].amount, "parent")


@unittest.skipUnless(FORTH, "requires Gforth")
class ForthWorkflowTests(unittest.TestCase):
    def load_variant(self, **updates):
        source = COUNTER.read_text().replace("REQUIRE workflow.fth", f"REQUIRE {HERE / 'workflow.fth'}")
        source = source.replace("REQUIRE counter-rules.fth", f"REQUIRE {RULES}")
        for old, new in updates.items():
            self.assertIn(old, source)
            source = source.replace(old, new)
        with TemporaryDirectory() as temp:
            path = Path(temp) / "variant.fth"
            path.write_text(source)
            return load_plan(path, forth=FORTH)

    def test_forth_defining_words_produce_ordered_resources_and_policies(self):
        stage = load_plan(COUNTER, forth=FORTH).describe()["steps"][1]
        self.assertEqual((stage["name"], stage["relation"], stage["inputs"], stage["outputs"]),
                         ("settle", "decide", [(1, 0)], (2, 3)))
        selected = self.load_variant(**{
            "2 2 ordered: two-items": "2 2 1 2 at-range: two-items",
            "payment receipt 2 list: terminal-resources": "receipt 1 list: terminal-resources",
            "bob forkid-context direct-script stage: settle": "bob forkid-context groth16-required stage: settle",
        }).describe()["steps"][1]
        self.assertEqual(selected["output_selection"], {"kind": "range", "count": [2, 2], "index_range": [1, 2]})
        self.assertEqual(selected["verification_policy"], "groth16-required")

    def test_workflow_library_preserves_the_callers_number_base(self):
        include = f"REQUIRE {HERE / 'workflow.fth'}"
        net = self.load_variant(**{include: f"HEX {include}\nBASE @ #16 <> [IF] -1 THROW [THEN] DECIMAL"})
        self.assertEqual(net.describe(), load_plan(COUNTER).describe())

    def test_unimplemented_stage_requirements_prevent_lock_generation(self):
        for updated, message in (
            ({"bob forkid-context direct-script stage: settle": "bob forkid-context proof-required stage: settle"},
             "cannot enforce proof-required"),
            ({"bob forkid-context direct-script stage: settle": "bob forkid-context groth16-required stage: settle"},
             "cannot enforce groth16-required"),
            ({"1 1 ordered: one-item": "1 1 0 1 at-range: one-item"}, "needs exact ordered"),
            ({"modes no-amount context:": "modes parent-amount context:"}, "unsupported prevout amount"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(CompileError, message):
                lower_serial(self.load_variant(**updated), RULES, TestKeys().public, 19)

    def test_lock_uses_the_stage_xt_even_if_another_rules_file_was_loaded(self):
        with TemporaryDirectory() as temporary:
            alternate = Path(temporary) / "other-rules.fth"
            alternate.write_text(RULES.read_text().replace("1 cell>u32", "3 cell>u32"))
            # Both files were loaded. The stage captured the first definition;
            # loading a new one before emission does not change that binding.
            net = self.load_variant(**{"root-resources emit-roots":
                                       f"REQUIRE {alternate}\nroot-resources emit-roots"})
            keys = TestKeys().public
            expected = lower_serial(load_plan(COUNTER), RULES, keys, 18)
            self.assertEqual(lower_serial(net, RULES, keys, 18).root, expected.root)
            with self.assertRaisesRegex(CompileError, "different definition of 'advance'"):
                lower_serial(net, alternate, keys, 18)
            with self.assertRaisesRegex(CompileError, "rules differ"):
                lower_serial(net, RULES, keys, 18, source_bytes=alternate.read_bytes())

    def test_changed_transitive_rules_are_rejected_and_identical_helpers_build(self):
        with TemporaryDirectory(prefix="rules with spaces ") as temporary:
            folder = Path(temporary)
            helpers = folder / "helpers.fth"
            helpers.write_bytes("( two-line\r\n 注释 ) : helper ( u32 -- u32 ) 1 cell>u32 u32+ ;\r\n".encode())
            rules = folder / "rules.fth"
            rules.write_text("REQUIRE helpers.fth\n" + RULES.read_text().replace("1 cell>u32 u32+", "helper"))
            workflow = folder / "counter.fth"
            workflow.write_text(COUNTER.read_text().replace("REQUIRE workflow.fth", f"REQUIRE {HERE / 'workflow.fth'}")
                                .replace("counter-rules.fth", "rules.fth"))
            net = load_plan(workflow)
            keys = TestKeys().public
            self.assertEqual(lower_serial(net, rules, keys, 18).root,
                             lower_serial(load_plan(COUNTER), RULES, keys, 18).root)
            helpers.write_bytes(helpers.read_bytes().replace(b"1 cell>u32", b"3 cell>u32"))
            with self.assertRaisesRegex(CompileError, "rules differ.*helpers"):
                lower_serial(net, rules, keys, 18)

    def test_helper_calls_use_the_same_definition_in_both_compilers(self):
        with TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / "helpers.fth").write_text(": helper ( u32 -- u32 ) 1 cell>u32 u32+ ;\n")
            rules = folder / "rules.fth"
            rules.write_text("REQUIRE helpers.fth\n" + RULES.read_text().replace("1 cell>u32 u32+", "helper"))
            workflow = folder / "counter.fth"
            workflow.write_text(COUNTER.read_text().replace("REQUIRE workflow.fth", f"REQUIRE {HERE / 'workflow.fth'}")
                                .replace("REQUIRE counter-rules.fth", "REQUIRE helpers.fth\n"
                                         ": helper ( u32 -- u32 ) 3 cell>u32 u32+ ;\nREQUIRE rules.fth"))
            with self.assertRaisesRegex(CompileError, "different definition of 'helper'"):
                lower_serial(load_plan(workflow), rules, TestKeys().public, 18)

    def test_shared_literals_match_gforth_at_the_route_boundary(self):
        keys = TestKeys().public
        reference = lower_serial(load_plan(COUNTER), RULES, keys, 19)
        with TemporaryDirectory() as temp:
            rules = Path(temp) / "rules.fth"
            workflow = Path(temp) / "counter.fth"
            workflow.write_text(COUNTER.read_text().replace("REQUIRE workflow.fth", f"REQUIRE {HERE / 'workflow.fth'}")
                                .replace("REQUIRE counter-rules.fth", "HEX REQUIRE rules.fth DECIMAL"))
            for numeral, expected in (("20", "0 0 0"), ("#20", "0 1 1"), ("$14", "0 1 1")):
                with self.subTest(numeral=numeral):
                    rules.write_text(RULES.read_text().replace("20 cell>u32", numeral + " cell>u32"))
                    result = subprocess.check_output([FORTH, str(workflow), "-e",
                                                      "cr 19 decide . 20 decide . 21 decide . bye"], text=True)
                    self.assertEqual(result.splitlines()[-1].strip(), expected)
                    net = load_plan(workflow)
                    if numeral == "20":
                        with self.assertRaisesRegex(CompileError, "literal '20': Gforth compiled 32, 4thGraph compiled 20"):
                            lower_serial(net, rules, keys, 19)
                    else:
                        contract = lower_serial(net, rules, keys, 19)
                        self.assertEqual(contract.deployment_outputs, reference.deployment_outputs)
                        self.assertEqual(contract.state_codes, reference.state_codes)

    def test_host_dictionary_lookup_precedes_numeric_conversion(self):
        net = self.load_variant(**{f"REQUIRE {RULES}": f"32 CONSTANT 20\nREQUIRE {RULES}"})
        with self.assertRaisesRegex(CompileError, "literal '20': Gforth compiled no single-cell literal"):
            lower_serial(net, RULES, TestKeys().public, 19)

    def test_rules_bind_the_shared_route_and_arithmetic_primitives(self):
        for definition, name in (("1 CONSTANT route-review", "route-review"), (": u32+ - cell>u32 ;", "u32+")):
            with self.subTest(name=name):
                net = self.load_variant(**{f"REQUIRE {RULES}": f"{definition}\nREQUIRE {RULES}"})
                with self.assertRaisesRegex(CompileError, "different primitive") as failure:
                    lower_serial(net, RULES, TestKeys().public, 19)
                self.assertIn(repr(name), str(failure.exception))

    def test_user_word_must_compile_a_call(self):
        with TemporaryDirectory() as temp:
            folder = Path(temp)
            (folder / "identity.fth").write_text(": identity ( u32 -- u32 ) ;\n")
            rules = folder / "rules.fth"
            rules.write_text("REQUIRE identity.fth\n" + RULES.read_text().replace("1 cell>u32", "identity 1 cell>u32"))
            workflow = folder / "counter.fth"
            workflow.write_text(COUNTER.read_text().replace("REQUIRE workflow.fth", f"REQUIRE {HERE / 'workflow.fth'}")
                                .replace("REQUIRE counter-rules.fth", "REQUIRE identity.fth\nIMMEDIATE\nREQUIRE rules.fth"))
            with self.assertRaisesRegex(CompileError, "Gforth executes 'identity' at compile time"):
                lower_serial(load_plan(workflow), rules, TestKeys().public, 19)

    def test_forth_plan_reproduces_serial_locks_and_validates_real_input_scripts(self):
        keys = TestKeys()
        net = load_plan(COUNTER, forth=FORTH)
        from_forth = lower_serial(net, RULES, keys.public, 19)
        legacy = SourceCompiler(RULES.read_text() + """
workflow-input: current u32 ;
stage: prepare advance current pending operator ;
stage: settle decide pending payment bob ;
""").workflow()
        reference = WorkflowContracts(legacy, keys.public, 19, mode="serial", target="both")
        self.assertEqual(from_forth.deployment_outputs, reference.deployment_outputs)
        self.assertEqual(from_forth.state_codes, reference.state_codes)

        for current, expected_route in ((18, 0), (19, 1)):
            contract = lower_serial(net, RULES, keys.public, current)
            root = Transaction((Input(bytes(32), 0),), contract.deployment_outputs)
            prepare_draft = contract.prepare("prepare", {"deploy": root})
            pending = prepare_draft.seal(keys.sign)
            settle_draft = contract.prepare("settle", {"deploy": root, "prepare": pending})
            payment = settle_draft.seal(keys.sign)
            validate_at_heights(pending, (root,), spend_height=4, activation_height=10, utxo_heights=(3,))
            validate_at_heights(payment, (pending,), spend_height=5, activation_height=10, utxo_heights=(4,))
            self.assertEqual(payment.outputs,
                             (contract.terminals[expected_route], contract.receipt(root.txid_wire(), current + 1)))
            for outputs in (payment.outputs[::-1], payment.outputs + payment.outputs[-1:]):
                changed = replace(settle_draft, tx=replace(settle_draft.tx, outputs=outputs)).seal(keys.sign)
                with self.assertRaises((ValueError, RuntimeError)):
                    validate_at_heights(changed, (pending,), spend_height=5, activation_height=10, utxo_heights=(4,))

    def test_two_declared_sighashes_can_be_used_in_different_stages(self):
        net = self.load_variant(**{"forkid-all 1 list: modes": "otda-all forkid-all 2 list: modes"})
        self.assertEqual(net.describe()["steps"][0]["sighash"], ["41", "61"])
        keys = TestKeys()
        contract = lower_serial(net, RULES, keys.public, 19)
        root = Transaction((Input(bytes(32), 0),), contract.deployment_outputs)
        first = contract.prepare("prepare", {"deploy": root}, sighash_family="forkid")
        pending = first.seal(keys.sign)
        second = contract.prepare("settle", {"deploy": root, "prepare": pending}, sighash_family="chronicle")
        payment = second.seal(keys.sign)
        validate_at_heights(pending, (root,), spend_height=4, activation_height=10, utxo_heights=(3,))
        validate_at_heights(payment, (pending,), spend_height=5, activation_height=2, utxo_heights=(4,))
        with self.assertRaises((ValueError, RuntimeError)):
            validate_at_heights(payment, (pending,), spend_height=5, activation_height=10, utxo_heights=(4,))

    @unittest.skipUnless(os.environ.get("SCRIPT_LAB_REGTEST_PROFILE"), "requires the isolated regtest launcher")
    def test_forth_workflow_mines_and_binds_output_order_on_bsv_node(self):
        node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
        self.assertEqual(node.call("getblockcount", []), 0)
        replay = Replay(node, 0, "both", int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"]))
        net = load_plan(COUNTER, forth=FORTH)
        contract = lower_serial(net, RULES, replay.keys.public, 19)
        root, deployed = replay.deploy(contract, replay.fund(1), 0)
        self.assertTrue(deployed["bsv_node"]["mined"])
        first = contract.prepare("prepare", {"deploy": root})
        pending = replay.sign(first)
        self.assertTrue(replay.record_step(first, pending)["bsv_node"]["mined"])
        settle = contract.prepare("settle", {"deploy": root, "prepare": pending})
        reordered = replace(settle, tx=replace(settle.tx, outputs=settle.tx.outputs[::-1]))
        rejected = replay.record(replay.sign(reordered), reordered.previous, expected=False)
        self.assertFalse(rejected["chain_gang"]["transaction"])
        result = replay.record_step(settle, replay.sign(settle))
        self.assertTrue(result["bsv_node"]["mined"])


if __name__ == "__main__":
    unittest.main()
