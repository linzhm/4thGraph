"""Check complete WOTS+ inputs with BSV Node 1.2.3 and pinned chain-gang."""

from dataclasses import replace
from itertools import chain
import os
from pathlib import Path
import unittest

import requests
from tx_engine import Script, Tx, TxIn, TxOut

from fixtures import fixture_seeds, funding_transaction, malformed_cases, mode_cases
from payment import authorization, current_input_unlock, sign_payment, sign_spend
from script import locking_script
from shared.benchmark_cases import SHAPES, batch
from shared.evaluate import evaluate
from shared.transaction import Input, Output, Transaction
from wots import OneTimeSigner
from fixed_template import TEMPLATE_DIRECTORY, fixed_pattern
from generate_reconstruction import build_artifacts


def engine_transaction(tx):
    def engine_script(raw):
        script = Script()
        script.append_data(raw)
        return script

    inputs = [TxIn(item.txid[::-1].hex(), item.vout, engine_script(item.script), item.sequence) for item in tx.inputs]
    outputs = [TxOut(item.value, engine_script(item.script)) for item in tx.outputs]
    result = Tx(tx.version, inputs, outputs, tx.locktime)
    if result.serialize() != tx.serialize():
        raise AssertionError("chain-gang wire serialization differs")
    return result


def chain_valid(tx, parents):
    spend = engine_transaction(tx)
    funding = [engine_transaction(parent) for parent in parents]
    try:
        spend.validate(funding)
    except (RuntimeError, ValueError):
        return False
    return True


def node_check(tx, parent, index, *, spend_height=4, funding_height=3):
    # Every funding fixture spends output zero. The synthetic prevout isolates
    # the input under test, even in negative cases with a changed transaction.
    previous = parent.outputs[0]
    cookie = Path(os.environ["REGTEST_COOKIE"]).read_text().strip().split(":", 1)
    flags = sum(1 << bit for bit in (1, 2, 3, 16, 18, 19))
    flags |= (1 << 20) if spend_height >= 3 else 0
    flags |= (1 << 21) if funding_height >= 3 else 0
    request = {
        "tx": tx.serialize().hex(),
        "n": index,
        "flags": flags,
        "reportflags": True,
        "txo": {"lock": previous.script.hex(), "value": previous.value, "height": funding_height},
    }
    response = requests.post(
        os.environ.get("REGTEST_URL", "http://127.0.0.1:18443"),
        auth=tuple(cookie),
        timeout=30,
        json={"jsonrpc": "1.0", "id": 1, "method": "verifyscript", "params": [[request], False, 5000]},
    )
    response.raise_for_status()
    data = response.json()
    if data.get("error"):
        raise AssertionError(data["error"])
    result = data["result"][0]
    if result["flags"] != flags or result["result"] not in ("ok", "error"):
        raise AssertionError(result)
    return result["result"] == "ok"


class ChainGangTests(unittest.TestCase):
    def test_complete_input_matrix(self):
        for label, tx, parents, _, expected in chain(mode_cases(), malformed_cases()):
            with self.subTest(case=label):
                self.assertEqual(chain_valid(tx, parents), expected)


class NodeTests(unittest.TestCase):
    def test_complete_input_matrix(self):
        count = 0
        for label, tx, parents, index, expected in chain(mode_cases(), malformed_cases()):
            with self.subTest(case=label):
                self.assertEqual(chain_valid(tx, parents), expected)
                self.assertEqual(node_check(tx, parents[index], index), expected)
                count += 1
        print(f"BSV Node + chain-gang: {count} complete-input cases")

    def test_reconstruction_artifacts_match_generator(self):
        for name, data in build_artifacts().items():
            self.assertEqual((TEMPLATE_DIRECTORY / name).read_text(encoding="ascii"), data)
        pattern = fixed_pattern()
        self.assertEqual(len(pattern.program), 3097)
        self.assertEqual(evaluate(pattern.program), (list(pattern.fixed_parts), []))
        key = bytes(range(64))
        sample = locking_script(key, cached_constants="steps")
        self.assertEqual(len(sample), 33956)
        self.assertEqual(pattern.match(sample), (key[:32], key[32:]))
        self.assertIsNone(pattern.match(sample[:-1] + bytes([sample[-1] ^ 1])))

    def test_reconstructed_wots_transactions_and_marginals(self):
        from benchmark_adapter import TEMPLATES
        from tempfile import TemporaryDirectory

        template = TEMPLATES["cached-steps-reconstructed"]
        sizes = {
            0x61: (79090, 84786, 113235),
            0xe1: (79006, 84537, 113151),
        }
        with TemporaryDirectory() as temp:
            for mode, expected_sizes in sizes.items():
                for shape, expected in zip(SHAPES, expected_sizes, strict=True):
                    with self.subTest(mode=hex(mode), shape=shape):
                        leg = batch(template, mode, shape, f"test/{mode:02x}/{shape}", Path(temp))
                        tx = leg.tx
                        self.assertEqual(len(tx.serialize()), expected)
                        self.assertTrue(chain_valid(tx, leg.parents))
                        for index, parent in enumerate(leg.parents):
                            self.assertTrue(node_check(tx, parent, index))
                            witness, alt = evaluate(tx.inputs[index].script)
                            preimage, signature, _ = witness
                            expected_auth = authorization(tx, index, parent.outputs[0].value, mode)
                            key = b"".join(fixed_pattern().match(parent.outputs[0].script))
                            literal = current_input_unlock(expected_auth, key, signature)
                            self.assertEqual((witness, alt), evaluate(literal))
                            self.assertLess(len(tx.inputs[index].script), len(literal))

    def test_compressing_a_mixed_payment_signs_once_and_retains_literal_fallbacks(self):
        for version, mode, use_fixed_output, compresses in (
            (2, 0x61, True, True), (1, 0x61, True, False),
            (2, 0x41, True, False), (2, 0x63, True, False), (2, 0x61, False, False),
        ):
            with self.subTest(version=version, mode=hex(mode), fixed=use_fixed_output):
                label = bytes((version, mode, use_fixed_output))
                signer = OneTimeSigner(*fixture_seeds(label))
                change = OneTimeSigner(*fixture_seeds(label + b"/change"))
                previous = funding_transaction(signer.public_key, cached_constants="steps")
                destination = locking_script(change.public_key, cached_constants="steps") if use_fixed_output else b"\x51"
                tx = Transaction((Input(previous.txid_wire(), 0),),
                                 (Output(400, b"\x51"), Output(9500, destination)), version=version)
                approvals = []

                def callback(digest):
                    signature = signer(digest)
                    approvals.append((digest, signature))
                    return signature

                if version == 2:
                    signed = sign_payment(previous.serialize(), 0, tx.outputs, 100, signer.public_key,
                                          callback, sighash=mode, compress_otda=True)
                else:
                    signed = sign_spend(tx, 0, previous.serialize(), signer.public_key, callback,
                                        sighash=mode, compress_otda=True)
                auth = authorization(tx, 0, 10_000, mode)
                (digest, signature), = approvals
                self.assertEqual(digest, auth.digest())
                literal = current_input_unlock(auth, signer.public_key, signature)
                witness = signed.inputs[0].script
                self.assertEqual(evaluate(witness), evaluate(literal))
                if compresses:
                    self.assertLess(len(witness), len(literal))
                else:
                    self.assertEqual(witness, literal)
                self.assertTrue(chain_valid(signed, (previous,)))
                self.assertTrue(node_check(signed, previous, 0))
                if compresses:
                    altered = replace(signed, outputs=(Output(399, b"\x51"), signed.outputs[1]))
                    self.assertFalse(chain_valid(altered, (previous,)))
                    self.assertFalse(node_check(altered, previous, 0))

    def test_fresh_key_change_and_spend(self):
        first = OneTimeSigner(*fixture_seeds(b"node-first"))
        change = OneTimeSigner(*fixture_seeds(b"node-change"))
        funding = funding_transaction(first.public_key)
        payment = sign_payment(
            funding.serialize(), 0, [Output(9_900, locking_script(change.public_key))], 100, first.public_key, first
        )
        self.assertTrue(chain_valid(payment, [funding]))
        self.assertTrue(node_check(payment, funding, 0))
        spend = sign_payment(payment.serialize(), 0, [Output(9_800, b"\x51")], 100, change.public_key, change)
        self.assertTrue(chain_valid(spend, [payment]))
        self.assertTrue(node_check(spend, payment, 0))


if __name__ == "__main__":
    unittest.main()
