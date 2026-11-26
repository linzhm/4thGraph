"""Exhaust the declared WOTS+ payment cases on independent Script engines."""

from itertools import chain, product
import os
import unittest

from fixtures import malformed_cases, mode_cases, mode_fixture
from script import CACHE_PROFILES
from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.script import push
from test_node import engine_transaction, node_check


VERSIONS = (1, 2)
CHRONICLE_HEIGHT = 3
CONTEXTS = (
    (2, (1, 1)),
    (4, (1, 1)),
    (4, (1, 3)),
    (4, (3, 1)),
    (4, (3, 3)),
)

# Read directly from the payment specification, independently of SIGHASH_TYPES
# and the fixture generator's use of sighash bit masks.
ALL = frozenset((0x41, 0xc1, 0x61, 0xe1))
NONE = frozenset((0x42, 0xc2, 0x62, 0xe2))
SINGLE = frozenset((0x43, 0xc3, 0x63, 0xe3))
ANYONECANPAY = frozenset((0xc1, 0xc2, 0xc3, 0xe1, 0xe2, 0xe3))
OTDA = frozenset((0x61, 0x62, 0x63, 0xe1, 0xe2, 0xe3))
MODES = ALL | NONE | SINGLE
PAIRED_RULES = {
    "paired": MODES,
    "paired_output": NONE,
    "other_output": NONE | SINGLE,
    "other_sequence": NONE | SINGLE | ANYONECANPAY,
    "other_outpoint": ANYONECANPAY,
    "own_sequence": frozenset(),
    "locktime": frozenset(),
}
SINGLE_RULES = {
    "moved_pair": frozenset((0xc3,)),
    "unpaired": SINGLE,
    "unpaired_other_output": SINGLE,
    "unpaired_own_sequence": frozenset(),
    "added_paired_output": frozenset(),
}
COMPANION_RULES = ("companion_paired_preimage", "companion_wrong_selector")
MALFORMED = (
    "short_signature", "long_signature", "changed_checksum_chain", "other_key", "other_digest",
    "extra_argument", "missing_argument", "invalid_selector", "noncanonical_selector",
    "short_preimage", "long_preimage", "unsupported_flag", "nonzero_high_flag", "bad_script_code",
    "wrong_previous_amount",
)


def base_verdicts():
    """Map required labels to (requested sighash, verdict after activation)."""
    verdicts = {label: (0x41, False) for label in MALFORMED}
    for flag, operation in product(MODES, PAIRED_RULES):
        verdicts[f"{flag:02x}_{operation}"] = flag, flag in PAIRED_RULES[operation]
    for flag, operation in product(SINGLE, SINGLE_RULES):
        verdicts[f"{flag:02x}_{operation}"] = flag, flag in SINGLE_RULES[operation]
    for flag, operation in product(SINGLE & OTDA, COMPANION_RULES):
        verdicts[f"{flag:02x}_{operation}"] = flag, False
    return verdicts


class AcceptanceTests(unittest.TestCase):
    def test_complete_payment_domain(self):
        self.check_payment_domain(cached_constants=False)

    def test_cached_constants_complete_payment_domain(self):
        self.check_payment_domain(cached_constants=True)

    def test_cached_steps_complete_payment_domain(self):
        self.check_payment_domain(cached_constants="steps")

    def test_compact_complete_payment_domain(self):
        self.check_payment_domain(cached_constants="compact")

    def test_compact_v2_complete_payment_domain(self):
        self.check_payment_domain(cached_constants="compact-v2")

    def check_payment_domain(self, *, cached_constants):
        expected = base_verdicts()
        self.assertEqual(len(expected), 123)
        self.assertEqual(len(set(VERSIONS)), 2)
        self.assertEqual(len(set(CONTEXTS)), 5)
        required = set(product(VERSIONS, CONTEXTS, expected))
        self.assertEqual(len(required), 1230)
        accepted = set()
        visited = set()
        native = bool(os.environ.get("REGTEST_COOKIE"))

        for version in VERSIONS:
            fixtures = chain(mode_cases(version=version, cached_constants=cached_constants),
                             malformed_cases(version=version, cached_constants=cached_constants))
            for label, transaction, parents, index, fixture_verdict in fixtures:
                self.assertIn(label, expected)
                flag, active_verdict = expected[label]
                self.assertEqual(fixture_verdict, active_verdict, label)
                self.assertEqual(transaction.version, version, label)
                spend = engine_transaction(transaction)
                funding = [engine_transaction(parent) for parent in parents]
                for context in CONTEXTS:
                    height, creation = context
                    case = version, context, label
                    with self.subTest(version=version, heights=context, case=label):
                        self.assertIn(case, required)
                        self.assertNotIn(case, visited)
                        inputs = [
                            (entry.txid[::-1].hex(), entry.vout, era)
                            for entry, era in zip(transaction.inputs, creation, strict=True)
                        ]
                        want = active_verdict and (height >= CHRONICLE_HEIGHT or flag not in OTDA)
                        if want:
                            spend.validate_with_chronicle_context(funding, height, CHRONICLE_HEIGHT, inputs, True)
                            accepted.add(case)
                        else:
                            with self.assertRaisesRegex(ValueError, r"^Error evaluating the script"):
                                spend.validate_with_chronicle_context(funding, height, CHRONICLE_HEIGHT, inputs, True)
                        if native:
                            self.assertEqual(node_check(transaction, parents[index], index, spend_height=height,
                                                        funding_height=creation[index]), want)
                        visited.add(case)

        self.assertEqual(visited, required)
        self.assertEqual(len(accepted), 442)
        engines = "chain-gang + BSV Node" if native else "chain-gang"
        print(f"{engines}: {len(visited)} WOTS+ rows, {len(accepted)} accepted, cached={cached_constants}")

    def test_every_signature_chain_in_a_complete_input(self):
        for cached_constants in CACHE_PROFILES:
            with self.subTest(cached_constants=cached_constants):
                self.check_signature_chains(cached_constants=cached_constants)

    def check_signature_chains(self, *, cached_constants):
        _, parents, spending = mode_fixture(0x41, cached_constants=cached_constants)
        preimage, signature, selector = evaluate(spending.inputs[1].script)[0]
        self.assertEqual(len(signature), 67 * 32)
        funding = [engine_transaction(parent) for parent in parents]
        heights = [(entry.txid[::-1].hex(), entry.vout, 3) for entry in spending.inputs]
        engine_transaction(spending).validate_with_chronicle_context(funding, 4, CHRONICLE_HEIGHT, heights, True)
        native = bool(os.environ.get("REGTEST_COOKIE"))
        if native:
            self.assertTrue(node_check(spending, parents[1], 1))

        for index in range(67):
            with self.subTest(chain=index):
                offset = index * 32
                candidate = signature[:offset] + bytes([signature[offset] ^ 1]) + signature[offset + 1:]
                transaction = spending.with_script(1, push(preimage) + push(candidate) + push(selector))
                with self.assertRaisesRegex(ValueError, r"^Error evaluating the script"):
                    engine_transaction(transaction).validate_with_chronicle_context(
                        funding, 4, CHRONICLE_HEIGHT, heights, True
                    )
                if native:
                    self.assertFalse(node_check(transaction, parents[1], 1))


if __name__ == "__main__":
    unittest.main()
