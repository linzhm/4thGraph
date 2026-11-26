"""Exercise project templates on transactions outside the benchmark workloads."""
from dataclasses import replace
from importlib import import_module
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from shared.benchmark import PROJECTS, ROOT
from shared.benchmark_cases import native_coin, seed, synthetic_parent
from shared.benchmark_validation import Node, chain_verdict
from shared.transaction import (
    ANYONECANPAY, CHRONICLE, FORKID, SIGHASH_ALL, SIGHASH_NONE, SIGHASH_TYPES,
    Input, Output, Transaction,
)


# Each row uses fresh test-only keys, including for the one-time schemes.
# Fields are version, input sighashes, output count, and inputs paired to
# the output changed by the control (the last output).
PAYMENTS = (
    (1, (0x41,), 1, (0,)),
    (2, (0x42, 0xe3), 3, ()),
    (1, (0xc3, 0x62, 0x43), 3, (2,)),
    (2, (0x61, 0xc3, 0x42), 2, (0, 1)),
)
ACTIVATIONS = (
    (1, (0x61,), 2, (0, 1)),
    (2, (0x41, 0x61, 0x41), 4, (0, 1, 2, 3)),
)

# Keep the expected inventory explicit so losing a supported mode fails the suite.
SPONSORED_MODES = (
    0x41, 0x42, 0x43,
    0xc1, 0xc2, 0xc3,
    0x61, 0x62, 0x63,
    0xe1, 0xe2, 0xe3,
)


def require_chronicle_context():
    from tx_engine import Tx

    if not hasattr(Tx, "validate_with_chronicle_context"):
        raise RuntimeError(
            "The optimization matrix requires explicit Chronicle consensus validation. "
            "Install tx-engine from shared/requirements-chronicle.txt."
        )


def check_verdicts(test, node, tx, parents, expected):
    test.assertIs(chain_verdict(tx, parents), all(expected))
    if node:
        test.assertEqual(node.verdicts(tx, parents, timeout_us=2_000_000), expected)


def payment_matrix(test, project, node, scratch):
    test.assertCountEqual(SPONSORED_MODES, SIGHASH_TYPES)
    templates = import_module("benchmark_adapter").TEMPLATES
    test.assertTrue(templates)
    for name, template in templates.items():
        sighash_matrix(test, project, name, template, node, scratch)
        rows = ACTIVATIONS if template.deferred else PAYMENTS
        for row, (version, modes, count, rejects) in enumerate(rows):
            with test.subTest(template=name, version=version, modes=modes, outputs=count):
                label = f"optimization matrix test only/{project}/{name}/{row}"
                coins = [template.create(f"{label}/{i}", 18_243 + 311 * i)
                         for i in range(len(modes))]
                # Reuse one parent and spend its outputs in reverse order, leaving
                # index zero unspent. Activation still pairs input and output slots.
                parent = Transaction(
                    (Input(seed(label), 2),),
                    (Output(7, b"\x51"), *(coin.output for coin in reversed(coins))),
                )
                sources = [(parent, len(coins) - i, coin, mode)
                           for i, (coin, mode) in enumerate(zip(coins, modes, strict=True))]
                if template.deferred:
                    outputs = [coin.activated.output for coin in coins]
                    outputs.append(Output(2_037, b"\x51"))
                    sponsor = native_coin(label + "/sponsor", 2_250)
                    sponsor_parent = Transaction((Input(seed(label + "/sponsor"), 1),), (sponsor.output,))
                    sources.append((sponsor_parent, 0, sponsor, 0x41))
                else:
                    total = sum(coin.output.value for coin in coins)
                    outputs = [Output(2_037 + i, b"\x51") for i in range(count - 1)]
                    outputs.append(Output(total - 213 - sum(out.value for out in outputs), b"\x52"))
                tx = Transaction(tuple(Input(prev.txid_wire(), vout, sequence=0xfffffffd - i)
                                       for i, (prev, vout, _, _) in enumerate(sources)),
                                 tuple(outputs), version=version, locktime=480 + row)
                for i, (prev, _, coin, mode) in enumerate(sources):
                    signed = coin.unlock(tx, i, prev, mode, scratch)
                    test.assertTrue(signed.inputs[i].script)
                    test.assertEqual(signed, tx.with_script(i, signed.inputs[i].script))
                    tx = signed
                parents = tuple(prev for prev, *_ in sources)
                last = replace(outputs[-1], value=outputs[-1].value - 1)
                witness_index = row % len(sources)
                for control, candidate, expected in (
                    ("valid", tx, [True] * len(sources)),
                    ("locktime", replace(tx, locktime=tx.locktime + 1), [False] * len(sources)),
                    ("last-output", replace(tx, outputs=(*outputs[:-1], last)),
                     [i not in rejects for i in range(len(sources))]),
                    ("missing-witness", tx.with_script(witness_index, b""),
                     [i != witness_index for i in range(len(sources))]),
                ):
                    with test.subTest(control=control):
                        check_verdicts(test, node, candidate, parents, expected)


def sighash_matrix(test, project, name, template, node, scratch):
    """Check the effects of editing a sponsored transaction after signing."""
    for mode in SPONSORED_MODES:
        anyone_can_pay = bool(mode & ANYONECANPAY)
        base_mode = mode & 0x1f
        commits_all_outputs = base_mode == SIGHASH_ALL
        version = 2 if bool(mode & CHRONICLE) != anyone_can_pay else 1
        with test.subTest(template=name, version=version, sighash=f"{mode:#04x}"):
            label = f"sighash matrix test only/{project}/{name}/{mode:02x}"
            coin = template.create(label, 20_031)
            funding = synthetic_parent(label, coin)
            sponsor = native_coin(label + "/sponsor", 5_001)
            sponsor_parent = synthetic_parent(label + "/sponsor", sponsor)
            parents = (sponsor_parent, funding)

            # The project input is at index 1. Its paired output follows sponsor
            # change, whose script crosses the one-byte CompactSize boundary.
            change = Output(4_770, b"\x61" * (250 + version) + b"\x51")
            paired = coin.activated.output if template.deferred else Output(coin.output.value, b"\x52")
            inputs = (
                Input(sponsor_parent.txid_wire(), 0, sequence=0xfffffffc),
                Input(funding.txid_wire(), 0, sequence=0xfffffffd),
            )
            unsigned = Transaction(inputs, (change, paired), version=version, locktime=840)
            signed = coin.unlock(unsigned, 1, funding, mode, scratch)
            test.assertTrue(signed.inputs[1].script)
            test.assertEqual(signed, unsigned.with_script(1, signed.inputs[1].script))
            # NONE|ANYONECANPAY isolates the sponsor from output and input-list
            # edits, while still committing to its own sequence.
            sponsor_mode = FORKID | SIGHASH_NONE | ANYONECANPAY
            tx = sponsor.unlock(signed, 0, sponsor_parent, sponsor_mode, scratch)
            appended_parent = Transaction((Input(seed(label + "/extra"), 0),), (Output(271, b"\x51"),))
            appended = Input(appended_parent.txid_wire(), 0)
            changed_sponsor = replace(tx.inputs[0], sequence=tx.inputs[0].sequence - 1)

            for control, candidate, previous, expected in (
                ("valid", tx, parents, [True, True]),
                ("paired-output", replace(tx, outputs=(change, replace(paired, value=paired.value - 1))),
                 parents, [True, base_mode == SIGHASH_NONE and not template.deferred]),
                ("unpaired-output", replace(tx, outputs=(replace(change, value=change.value - 1), paired)),
                 parents, [True, not commits_all_outputs]),
                ("append-input", replace(tx, inputs=(*tx.inputs, appended)),
                 (*parents, appended_parent), [True, anyone_can_pay, True]),
                ("sponsor-sequence", replace(tx, inputs=(changed_sponsor, tx.inputs[1])),
                 parents, [False, anyone_can_pay or not commits_all_outputs]),
            ):
                with test.subTest(control=control):
                    check_verdicts(test, node, candidate, previous, expected)


def counter_matrix(test, node):
    from compiler import SourceCompiler
    from examples.pels_counter import SOURCE, counter_builds, counter_output
    from pels_constraints import FeeConstraint, WitnessAmount

    advance = SourceCompiler(SOURCE.read_text()).words["advance"]
    for rule, fees in ((FeeConstraint(193, 193), (193,)),
                       (FeeConstraint(127, 257), (127, 194, 257)),
                       (WitnessAmount(), (0, 257, 4_102))):
        _, builds = counter_builds(advance, rule)
        test.assertTrue(builds)
        for build in builds:
            with test.subTest(rule=rule, authentication=build.authentication,
                              witness=build.witness, scenario="two-hop-continuation"):
                initial = Transaction((Input(seed("counter continuation matrix"), 0),),
                                      (counter_output(build.code, 255, 17_001),))
                first_output = counter_output(build.code, 256, 17_001 - fees[0])
                first = build.spend(initial, first_output)
                second_output = counter_output(build.code, 257, first_output.value - fees[-1])
                second = build.spend(first, second_output)
                check_verdicts(test, node, first, (initial,), [True])
                check_verdicts(test, node, second, (first,), [True])
                replay = replace(second, inputs=(replace(second.inputs[0], txid=initial.txid_wire()),))
                check_verdicts(test, node, replay, (initial,), [False])
            for state, previous_value in ((127, 4_102), (65_535, 82_003), (2**32 - 2, 83_211)):
                parent = Transaction((Input(seed("counter optimization matrix"), 0),),
                                     (counter_output(build.code, state, previous_value),))
                for fee in fees:
                    with test.subTest(rule=rule, authentication=build.authentication,
                                      witness=build.witness, state=state, fee=fee):
                        output = counter_output(build.code, state + 1, previous_value - fee)
                        valid = build.spend(parent, output)
                        wrong_state = counter_output(build.code, state, output.value)
                        if isinstance(rule, FeeConstraint):
                            # Build a fresh witness so the fee guard must reject it.
                            wrong_amount = replace(output, value=previous_value - rule.maximum - 1)
                            wrong_amount_spend = build.spend(parent, wrong_amount)
                        else:
                            # Witness-supplied amounts are bound to the signed successor.
                            wrong_amount = replace(output, value=output.value + 1)
                            wrong_amount_spend = replace(valid, outputs=(wrong_amount,))
                        for control, candidate, expected in (
                            ("valid", valid, True),
                            ("state", build.spend(parent, wrong_state), False),
                            ("amount", wrong_amount_spend, False),
                        ):
                            with test.subTest(control=control):
                                check_verdicts(test, node, candidate, (parent,), [expected])


class OptimizationMatrixTests(unittest.TestCase):
    def test_projects(self):
        require_chronicle_context()
        for project in (*PROJECTS, "4thgraph"):
            with self.subTest(project=project):
                result = subprocess.run(
                    [sys.executable, "-m", "shared.test_optimization_matrix", project],
                    cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                )
                self.assertEqual(result.returncode, 0, result.stdout)


def run_project(project):
    # Reference projects use bare imports such as payment and script.
    path = ROOT / "projects" / project
    sys.path.insert(0, str(path if project == "4thgraph" else path / "reference"))

    def run_matrix(test):
        cookie = os.environ.get("REGTEST_COOKIE")
        node = Node(os.environ.get("REGTEST_URL", "http://127.0.0.1:18443"), cookie) if cookie else None
        if project == "4thgraph":
            counter_matrix(test, node)
        else:
            with TemporaryDirectory(prefix=f"{project}-matrix-") as scratch:
                payment_matrix(test, project, node, Path(scratch))

    class ProjectMatrix(unittest.TestCase):
        def runTest(self):
            require_chronicle_context()
            run_matrix(self)

    return unittest.TextTestRunner().run(ProjectMatrix()).wasSuccessful()


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] in (*PROJECTS, "4thgraph"):
        sys.exit(not run_project(sys.argv[1]))
    unittest.main()
