"""Run both freeze-versus-payment orderings on an independent BSV regtest."""

from dataclasses import replace
from hashlib import new, sha256
from importlib.util import find_spec
import json
import os
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest

from ecdsa import SECP256k1, SigningKey

from mimo_verifier import MimoProfile
from mint import MintPolicy, authorize_mint, prepare_mint
from mint_events import EMPTY_ROOT, MintEvents
from operational_token import TokenPolicy, freeze_witness, ordinary_witness
from regtest_mint import Node, RpcFailure, base58check, sign_p2pkh
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, hash256, preimage_all
from statement import AssetDescriptor, Slot
from test_mimo_verifier import TransferProver
from test_mint import event
from test_operational_token import fixture_signer
from transaction_relation import TokenState


@unittest.skipUnless(
    os.environ.get("CCTP_FREEZE_RACE_COOKIE") and find_spec("tx_engine") and shutil.which("circom") and shutil.which("node"),
    "requires independent BSV regtest, chain-gang, Circom, and Node.js",
)
class FreezeRaceRegtest(unittest.TestCase):
    def test_freeze_and_payment_orders(self):
        from shared.chain_gang import validate_at_heights

        node = Node(os.environ.get("CCTP_FREEZE_RACE_URL", "http://127.0.0.1:19454"),
                    Path(os.environ["CCTP_FREEZE_RACE_COOKIE"]))
        # Fixed public fixture signing keys, confined to a disposable regtest.
        owner_key, owner = fixture_signer(11)
        freeze_key, admin = fixture_signer(12)
        issuer_key, issuer = fixture_signer(13)
        recipient_key, _ = fixture_signer(14)
        address = base58check(b"\x6f" + new("ripemd160", sha256(owner_key).digest()).digest())
        coinbase = node.fund(address)
        funding_value = min(100_000_000, coinbase.outputs[0].value // 9)
        funding = Transaction((Input(coinbase.txid_wire(), 0),), (Output(funding_value, asm("OP_1")),) * 8)
        funding = sign_p2pkh(funding, coinbase, 0, SigningKey.from_secret_exponent(11, curve=SECP256k1))
        node.confirm(funding, address)
        anchor, mint1_sponsor, mint2_sponsor, freeze1_sponsor, freeze2_sponsor, *verifier_sponsors = (
            Input(funding.txid_wire(), i) for i in range(8)
        )
        asset = AssetDescriptor(1, anchor.outpoint(), 6, 7, b"a" * 32, b"p" * 32)
        profile = MimoProfile(1, 1, 1, freeze_key)
        evidence = {
            "scope": "Independent BSV regtest, two anchored mint origins, synthetic finalized deposits and test Groth16 setup",
            "node": node.call("getnetworkinfo")["subversion"],
            "cases": {},
        }

        with TemporaryDirectory(prefix="cctp-freeze-race-") as temporary:
            prover = TransferProver(Path(temporary) / "payment", profile)
            lock = profile.lock(asset, prover.key)
            policy = TokenPolicy((lock,), freeze_key)
            mint_policy = MintPolicy(asset, 84532, b"r" * 20, issuer_key, policy.lock)
            genesis = Transaction((anchor,), (Output(100_000, mint_policy.state_lock(EMPTY_ROOT)),))
            node.confirm(genesis, address)

            def issue(prior, spent_events, nonce, quantity, sponsor):
                deposit = event(mint_policy, nonce, quantity)
                plan = prepare_mint(mint_policy, prior, spent_events, deposit, sponsor)
                minted = authorize_mint(plan, lambda _: deposit, issuer)
                node.confirm(minted, address)
                return minted, plan.successor

            first, consumed = issue(genesis, MintEvents(), 1, 640, mint1_sponsor)
            second, _ = issue(first, consumed, 2, 384, mint2_sponsor)
            verifiers = tuple(Transaction((sponsor,), (Output(funding_value // 2, lock),))
                              for sponsor in verifier_sponsors)
            for verifier in verifiers:
                node.confirm(verifier, address)

            def owner_spend(parent, vout, verifier, quantity, *, frozen=False):
                recipient = policy.lock(TokenState(asset.asset_id(), quantity, recipient_key))
                tx = Transaction((Input(verifier.txid_wire(), 0), Input(parent.txid_wire(), vout)),
                                 (Output(1000, recipient),))
                signals, proof = prover.prove(asset, tx, verifier, (Slot(1, quantity),), (Slot(0, quantity),))
                parents = (verifier, parent)
                if frozen:
                    # The host builder deliberately rejects frozen tokens.
                    # Supply the actual proof, preimage and owner signature to
                    # exercise rejection at the node, on both independent inputs.
                    state = parent.outputs[vout]
                    preimage = preimage_all(tx, 1, state.value, state.script)
                    prevouts = b"".join(item.outpoint() for item in tx.inputs)
                    owner_unlock = (push(owner(hash256(preimage)) + b"\x41") + push(verifier.serialize())
                                    + push(prevouts) + push(preimage) + asm("OP_0"))
                    verifier_unlock = profile.witness_material(prover.key, proof, signals, tx, parents)
                else:
                    owner_unlock = ordinary_witness(tx, 1, parent, policy, verifier, owner)
                    verifier_unlock = profile.witness(asset, prover.key, proof, tx, parents, policy)
                return tx.with_script(0, verifier_unlock).with_script(1, owner_unlock)

            def freeze_spend(parent, sponsor, signer):
                old = parent.outputs[1]
                state = policy.parse(old.script)
                lock_frozen = policy.lock(replace(state, frozen=True))
                tx = Transaction((Input(parent.txid_wire(), 1), sponsor), (Output(old.value, lock_frozen),))
                return tx.with_script(0, freeze_witness(tx, 0, parent, policy, signer))

            def node_inputs(tx, parents):
                # Test the actual candidate against the previous output data
                # before broadcasting either conflicting transaction.
                flags = sum(1 << bit for bit in (1, 2, 3, 16, 18, 19, 20, 21))
                raw = tx.serialize().hex()
                requests = []
                for index, parent in enumerate(parents):
                    previous = parent.outputs[tx.inputs[index].vout]
                    info = node.call("getrawtransaction", parent.txid(), True)
                    block = node.call("getblockheader", info["blockhash"], True)
                    requests.append({
                        "tx": raw, "n": index, "flags": flags, "reportflags": True,
                        "txo": {"lock": previous.script.hex(), "value": previous.value, "height": block["height"]},
                    })
                results = node.call("verifyscript", requests, False, 10000)
                self.assertEqual(len(results), len(requests))
                self.assertTrue(all(row["flags"] & flags == flags for row in results), results)
                return tuple(row["result"] for row in results)

            def reject(tx, expected):
                with self.assertRaises(RpcFailure) as rejected:
                    node.submit(tx)
                self.assertIn(expected, str(rejected.exception).lower())
                return str(rejected.exception)

            bad_admin = freeze_spend(first, freeze1_sponsor, owner)
            self.assertEqual(node_inputs(bad_admin, (first, funding)), ("error", "ok"))
            evidence["wrong_administrator_rejection"] = reject(bad_admin, "mandatory-script-verify-flag-failed")

            for label, minted, quantity, sponsor, verifier in (
                ("freeze_first", first, 640, freeze1_sponsor, verifiers[0]),
                ("payment_first", second, 384, freeze2_sponsor, verifiers[1]),
            ):
                freeze = freeze_spend(minted, sponsor, admin)
                payment = owner_spend(minted, 1, verifier, quantity)
                self.assertEqual(freeze.inputs[0].outpoint(), payment.inputs[1].outpoint())
                both_results = {}
                for name, candidate, parents in (("freeze", freeze, (minted, funding)),
                                                 ("payment", payment, (verifier, minted))):
                    verify = node_inputs(candidate, parents)
                    self.assertEqual(verify, ("ok", "ok"))
                    validate_at_heights(candidate, parents, spend_height=100, activation_height=2,
                                        utxo_heights=(3, 3))
                    both_results[name] = {"txid": candidate.txid(), "node_validated_inputs": verify}
                first_is_freeze = label == "freeze_first"
                winner, loser = (freeze, payment) if first_is_freeze else (payment, freeze)
                node.submit(winner)
                rejection = reject(loser, "txn-mempool-conflict")
                pending = node.call("getrawmempool")
                self.assertIn(winner.txid(), pending)
                self.assertNotIn(loser.txid(), pending)
                block_hash = node.call("generatetoaddress", 1, address)[0]
                block_transactions = node.call("getblock", block_hash, 1)["tx"]
                self.assertIn(winner.txid(), block_transactions)
                self.assertNotIn(loser.txid(), block_transactions)
                self.assertIsNone(node.call("gettxout", minted.txid(), 1, False))
                winner_state = policy.parse(winner.outputs[0].script)
                self.assertEqual(winner_state.frozen, first_is_freeze)
                self.assertEqual(winner_state.owner, owner_key if first_is_freeze else recipient_key)
                self.assertEqual(winner_state.quantity, quantity)
                evidence["cases"][label] = {
                    "token_outpoint": f"{minted.txid()}:1",
                    "candidates": both_results, "winner": winner.txid(), "blockhash": block_hash,
                    "loser_rejection": rejection, "winner_frozen": winner_state.frozen, "quantity": quantity,
                }
                if first_is_freeze:
                    bad_payment = owner_spend(freeze, 0, verifiers[2], quantity, frozen=True)
                    frozen_results = node_inputs(bad_payment, (verifiers[2], freeze))
                    self.assertEqual(frozen_results, ("error", "error"))
                    evidence["frozen_owner_rejection"] = {
                        "node_input_results": frozen_results,
                        "submit_rejection": reject(bad_payment, "mandatory-script-verify-flag-failed"),
                    }

        if os.environ.get("CCTP_FREEZE_RACE_REPORT"):
            Path(os.environ["CCTP_FREEZE_RACE_REPORT"]).write_text(json.dumps(evidence, indent=2) + "\n")
