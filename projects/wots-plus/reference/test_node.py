"""Check complete WOTS+ inputs with BSV Node 1.2.3 and pinned chain-gang."""

from dataclasses import replace
from hashlib import sha256
from itertools import chain
import os
from pathlib import Path
import unittest

import requests
from tx_engine import Script, Tx, TxIn, TxOut, sig_hash_preimage

from fixtures import fixture_seeds, funding_transaction, malformed_cases, mode_cases
from payment import authorization, current_input_unlock, sign_payment, sign_spend
from script import ORDINARY_CODE, _payment_script, locking_script
from fourthgraph.benchmark.cases import SHAPES, batch
from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.transaction import SIGHASH_TYPES, Input, Output, Transaction, hash256
from wots import OneTimeSigner
from fixed_template import TEMPLATE_DIRECTORY, compact_pattern, fixed_pattern
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

    def test_compact_reconstruction_matches_compiled_lock(self):
        for profile, lock_bytes, program_bytes, fingerprint in (
            ("compact", 29217, 2395, "b5de618ce7e3429a4f4b2f1d6c386a8841afb40c11dcf1eb57ee135765cea4ca"),
            ("compact-v2", 27070, 2358, "6325b2e472c95893b9d76cf95d3240c9c3ff5ec4f334f9f69784f905004dbd91"),
            ("compact-v3", 25965, 1979, "a47457b71ef80921da0cc82d216e98331ea1365de0045854f8f2a37abd1dca7a"),
        ):
            with self.subTest(profile=profile):
                pattern = compact_pattern(profile)
                self.assertEqual(len(pattern.program), program_bytes)
                self.assertEqual(evaluate(pattern.program), (list(pattern.fixed_parts), []))
                zero_key_lock = locking_script(bytes(64), cached_constants=profile)
                self.assertEqual(sha256(zero_key_lock).hexdigest(), fingerprint)
                for key in (bytes(64), bytes(range(64)), b"\xff" * 64):
                    lock = locking_script(key, cached_constants=profile)
                    self.assertEqual(len(lock), lock_bytes)
                    self.assertEqual(lock, _payment_script(key, cached_constants=profile))
                    self.assertEqual(pattern.match(lock), (key[:32], key[32:]))
                    self.assertIsNone(pattern.match(lock[:-1] + bytes([lock[-1] ^ 1])))

    def test_reconstructed_wots_transactions_and_marginals(self):
        self.check_transactions_and_marginals("cached-steps-reconstructed", fixed_pattern(), {
            0x61: (79090, 84786, 113235),
            0xe1: (79006, 84537, 113151),
            0x63: (78921, 81361, 112888),
            0xe3: (78837, 81195, 112804),
        })

    def test_compact_transactions_and_marginals(self):
        self.check_transactions_and_marginals("compact-reconstructed", compact_pattern(), {
            0x41: (63172, 65525, 92400),
            0x61: (68208, 73202, 97614),
            0xe1: (68124, 72953, 97530),
            0x63: (68039, 70479, 97267),
            0xe3: (67955, 70313, 97183),
        })

    def test_compact_v2_transactions_and_marginals(self):
        self.check_transactions_and_marginals("compact-v2-reconstructed", compact_pattern("compact-v2"), {
            0x41: (58878, 61231, 85959),
            0x61: (63840, 68797, 91099),
            0xe1: (63756, 68548, 91015),
            0x63: (63671, 66111, 90752),
            0xe3: (63587, 65945, 90668),
        })

    def test_compact_v3_transactions_and_marginals(self):
        self.check_transactions_and_marginals("compact-v3-reconstructed", compact_pattern("compact-v3"), {
            0x41: (56668, 59021, 82644),
            0x61: (60872, 65450, 87026),
            0xe1: (60788, 65201, 86942),
            0x63: (60703, 63143, 86679),
            0xe3: (60619, 62977, 86595),
        })

    def check_transactions_and_marginals(self, template, pattern, sizes):
        from benchmark_adapter import TEMPLATES
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as temp:
            for mode, expected_sizes in sizes.items():
                for shape, expected in zip(SHAPES, expected_sizes, strict=True):
                    with self.subTest(mode=hex(mode), shape=shape):
                        leg = batch(TEMPLATES[template], mode, shape, f"test/{mode:02x}/{shape}", Path(temp))
                        tx = leg.tx
                        self.assertEqual(len(tx.serialize()), expected)
                        self.assertTrue(chain_valid(tx, leg.parents))
                        for index, parent in enumerate(leg.parents):
                            self.assertTrue(node_check(tx, parent, index))
                            witness, alt = evaluate(tx.inputs[index].script)
                            preimage, signature, _ = witness
                            expected_auth = authorization(tx, index, parent.outputs[0].value, mode)
                            key = b"".join(pattern.match(parent.outputs[0].script))
                            literal = current_input_unlock(expected_auth, key, signature)
                            self.assertEqual((witness, alt), evaluate(literal))
                            if expected_auth.companion or mode == 0x41:
                                self.assertEqual(tx.inputs[index].script, literal)
                            else:
                                self.assertLess(len(tx.inputs[index].script), len(literal))
                        if mode in (0x63, 0xe3) and shape == (2, 2):
                            for changed in range(2):
                                outputs = list(tx.outputs)
                                outputs[changed] = replace(outputs[changed], value=outputs[changed].value - 1)
                                modified = replace(tx, outputs=tuple(outputs))
                                self.assertFalse(chain_valid(modified, leg.parents))
                                for index, parent in enumerate(leg.parents):
                                    self.assertEqual(node_check(modified, parent, index), index != changed)

    def test_reconstruction_matches_signer_and_both_engines_across_modes(self):
        modes = (0x41, 0x42, 0x43, 0x61, 0x62, 0x63, 0xc1, 0xc2, 0xc3, 0xe1, 0xe2, 0xe3)
        self.assertEqual(SIGHASH_TYPES, set(modes))
        recipients = [OneTimeSigner(*fixture_seeds(f"coverage/recipient/{i}".encode())) for i in range(4)]
        fixed = [locking_script(recipient.public_key, cached_constants="steps") for recipient in recipients]
        compact = [locking_script(recipient.public_key, cached_constants="compact") for recipient in recipients]
        v2 = [locking_script(recipient.public_key, cached_constants="compact-v2") for recipient in recipients]
        v3 = [locking_script(recipient.public_key, cached_constants="compact-v3") for recipient in recipients]
        layouts = (
            ((False, True, "steps"), (fixed[0], b"\x51", fixed[1], fixed[2])),
            ((False, True, "steps"), (fixed[0], fixed[1])),
            ((False, "steps", "compact"), (compact[0], b"\x51", fixed[1], compact[2])),
            ((False, "steps", "compact"), (compact[0], compact[1])),
            (("steps", "compact", "compact-v2"), (v2[0], b"\x51", fixed[1], compact[2])),
            (("steps", "compact", "compact-v2"), (v2[0], v2[1])),
            (("compact", "compact-v2", "compact-v3"), (v3[0], b"\x51", v2[1], compact[2], fixed[3])),
            (("compact", "compact-v2", "compact-v3"), (v3[0], v3[1])),
        )
        for version in (1, 2):
            for profiles, locks in layouts:
                for mode in modes:
                    with self.subTest(version=version, mode=hex(mode), profiles=profiles, shape=(3, len(locks))):
                        self.check_reconstruction_case(version, mode, profiles, locks)

    def check_reconstruction_case(self, version, mode, profiles, locks):
        # Each of these public fixture keys is used for exactly one signature.
        label = f"coverage/{version}/{mode}/{profiles}/{len(locks)}".encode()
        keys = [OneTimeSigner(*fixture_seeds(label + bytes([i]))) for i in range(3)]
        parents = tuple(funding_transaction(key.public_key, cached_constants=profile)
                        for key, profile in zip(keys, profiles, strict=True))
        tx = Transaction(tuple(Input(parent.txid_wire(), 0, sequence=0xfffffffe - i)
                               for i, parent in enumerate(parents)),
                         tuple(Output(5000 - i, lock) for i, lock in enumerate(locks)),
                         version=version, locktime=17)
        engine = engine_transaction(tx)
        code = Script()
        code.append_data(ORDINARY_CODE)
        for i, (key, parent) in enumerate(zip(keys, parents, strict=True)):
            approved = []

            def callback(digest):
                approved.append(digest)
                return key(digest)

            auth = authorization(tx, i, parent.outputs[0].value, mode)
            tx = sign_spend(tx, i, parent.serialize(), key.public_key, callback,
                            sighash=mode, compress_otda=True)
            witness = tx.inputs[i].script
            stack, alt = evaluate(witness)
            preimage, signature, _ = stack
            self.assertEqual(approved, [hash256(preimage)], i)
            self.assertEqual(preimage, auth.preimage, i)
            if mode & 0x20 and not auth.companion:
                oracle = bytes(sig_hash_preimage(engine, i, code, parent.outputs[0].value, mode))
                self.assertEqual(preimage, oracle, i)
            literal = current_input_unlock(auth, key.public_key, signature)
            self.assertEqual((stack, alt), evaluate(literal), i)
            compresses = mode in (0x61, 0xe1) or (
                mode in (0x63, 0xe3) and i < len(locks) and locks[i] != b"\x51"
            )
            if version == 2 and compresses:
                # The witness fits all four dictionaries. A literal WOTS+
                # lock alone exceeds this bound.
                self.assertLess(len(witness), min(14_000, len(literal)), i)
            else:
                self.assertEqual(witness, literal, i)
        self.assertTrue(chain_valid(tx, parents))
        for i, parent in enumerate(parents):
            self.assertTrue(node_check(tx, parent, i), i)

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
