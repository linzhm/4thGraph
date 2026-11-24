"""Check complete WOTS+ inputs with BSV Node 1.2.3 and pinned chain-gang."""

from itertools import chain
import os
from pathlib import Path
import unittest

import requests
from tx_engine import Script, Tx, TxIn, TxOut

from fixtures import fixture_seeds, funding_transaction, malformed_cases, mode_cases
from payment import sign_payment
from script import locking_script
from shared.transaction import Output
from wots import OneTimeSigner


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


def node_check(tx, parent, index):
    # Every funding fixture spends output zero. The synthetic prevout isolates
    # the input under test, even in negative cases with a changed transaction.
    previous = parent.outputs[0]
    cookie = Path(os.environ["REGTEST_COOKIE"]).read_text().strip().split(":", 1)
    flags = sum(1 << bit for bit in (1, 2, 3, 16, 18, 19, 20, 21))
    request = {
        "tx": tx.serialize().hex(),
        "n": index,
        "flags": flags,
        "reportflags": True,
        "txo": {"lock": previous.script.hex(), "value": previous.value, "height": 3},
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
    if result["flags"] & flags != flags or result["result"] not in ("ok", "error"):
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
