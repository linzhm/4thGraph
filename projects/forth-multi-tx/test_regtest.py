"""Funded regressions for previously reviewed signing and provenance behavior."""

from dataclasses import replace
import os
import unittest

from compiler import parse, schedule
from replay import GATED_EXAMPLE, Replay
from shared.benchmark_validation import ACTIVATION_HEIGHT, Node


@unittest.skipUnless(os.environ.get("REGTEST_URL"), "requires shared/verify_node.sh")
class FundedRegressionTests(unittest.TestCase):
    def test_shared_gate_and_stale_signatures(self):
        node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
        self.assertEqual(node.call("getconnectioncount", []), 0)
        self.assertEqual(node.call("getblockcount", []), 0)
        activation = int(os.environ.get("SCRIPT_LAB_CHRONICLE_HEIGHT", ACTIVATION_HEIGHT))
        replay = Replay(node, 1, "both", activation, optimization="stack", join_witness="shared")
        source = GATED_EXAMPLE.read_text().replace("qualify z", "qualify x") + "\nindependent-submit qualify\n"
        plan = schedule(parse(source), "split")
        contracts = replay.contracts(plan)
        bootstrap = replay.fund(4)
        for slot, (route, y) in enumerate((("settle", 20), ("review", 2))):
            with self.subTest(route=route):
                result = replay.path(contracts, bootstrap, slot, {"x": 2, "y": y}, route)
                self.assertIn("qualify_wrong_shared_input", result["controls"])
                self.assertIn("split_wrong_shared_input", result["controls"])

        old_root, _ = replay.deploy(contracts, bootstrap, 2)
        new_root, _ = replay.deploy(contracts, bootstrap, 3)
        old = contracts.prepare("qualify", {"deploy": old_root}, {"x": 2})
        rebound = contracts.prepare("qualify", {"deploy": new_root}, {"x": 2})
        requests = []
        with self.assertRaisesRegex(ValueError, "draft input does not match"):
            replace(rebound, previous=old.previous).seal(requests.append)
        self.assertEqual(requests, [])
        old_signature = replay.keys.sign(old.signing_requests()[0])
        self.assertNotEqual(old.signing_requests()[0].digest, rebound.signing_requests()[0].digest)
        replay.record(rebound.seal(lambda _: old_signature), rebound.previous, expected=False)
        replay.record(replay.sign(rebound), rebound.previous)
