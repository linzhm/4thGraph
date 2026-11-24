"""Canonical mint transitions, transaction signatures and external node replay."""

from dataclasses import replace
from hashlib import new, sha256
from importlib.util import find_spec
import os
from pathlib import Path
import unittest

from ecdsa import BadSignatureError, SECP256k1, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_der, sigencode_der_canonize

from mint import (
    MintPlan, MintPolicy, authorize_mint, authorize_pause, mint_unlock,
    prepare_mint, read_deposit, recover_events, recover_mint_state,
)
from mint_events import Deposit, DepositPosition, EMPTY_ROOT, MintEvents, transition_roots
from regtest_mint import Node, RpcFailure, base58check, sign_p2pkh
from shared.evaluate import ScriptError, evaluate
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, hash256, preimage_all
from statement import AssetDescriptor
from transaction_relation import read_token, token_lock

# Test-only private keys.
ATTESTOR = SigningKey.from_secret_exponent(10, curve=SECP256k1)
OWNER = SigningKey.from_secret_exponent(11, curve=SECP256k1)
OTHER = SigningKey.from_secret_exponent(12, curve=SECP256k1)
VERIFIER = asm("OP_1")  # Token-lock identity fixture only. No transfer is tested here.


def public(signer):
    return signer.verifying_key.to_string("compressed")


def sign(digest, signer=ATTESTOR):
    return signer.sign_digest_deterministic(digest, hashfunc=sha256, sigencode=sigencode_der_canonize)


def force_sign(plan, *, transaction=None, signer=ATTESTOR):
    """Bypass the service so invalid transitions reach BSV Script."""
    tx = plan.transaction if transaction is None else transaction
    override = replace(plan, transaction=tx)
    prior = plan.prior.outputs[0]
    digest = hash256(preimage_all(tx, 0, prior.value, prior.script))
    return tx.with_script(0, mint_unlock(override, sign(digest, signer)))


def run_script(transaction, prior, input_index=0):
    output = prior.outputs[0]
    digest = hash256(preimage_all(transaction, input_index, output.value, output.script))

    def verify(signature, key):
        if signature[-1:] != b"\x41":
            return False
        try:
            return VerifyingKey.from_string(key, curve=SECP256k1).verify_digest(
                signature[:-1], digest, sigdecode=sigdecode_der,
            )
        except BadSignatureError:
            return False

    return evaluate(transaction.inputs[input_index].script + output.script, checksig=verify)


def setup_policy(anchor):
    return MintPolicy(
        AssetDescriptor(1, anchor.outpoint(), 6, 7, b"\0" * 12 + b"a" * 20, b"p" * 32),
        84532, b"r" * 20, public(ATTESTOR), lambda state: token_lock(state, VERIFIER),
    )


def event(policy, identifier, quantity, owner=OWNER):
    asset = policy.asset
    return Deposit(
        DepositPosition(policy.source_chain_id, asset.reserve_domain, policy.reserve_contract,
                        identifier.to_bytes(32, "big"), 1),
        asset.reserve_asset, asset.network, asset.asset_id(), quantity, 0, public(owner),
    )


def replay_plan(plan, transaction, sponsor):
    """Attempt to record the same event against the actual new mint state."""
    return MintPlan(
        plan.policy, transaction, plan.successor, plan.deposit,
        replace(plan.transaction, inputs=(Input(transaction.txid_wire(), 0), sponsor)),
        plan.path, plan.successor,
    )


class MintTests(unittest.TestCase):
    def setUp(self):
        self.anchor = Input(b"x" * 32, 0)
        self.policy = setup_policy(self.anchor)
        self.genesis = Transaction((self.anchor,), (Output(1500, self.policy.state_lock(EMPTY_ROOT)),))
        self.sponsor = Transaction((Input(b"z" * 32, 0),), (Output(10_000, asm("OP_1")),) * 3)
        self.first = event(self.policy, 1, 1024)
        self.second = event(self.policy, 2, 384, OTHER)

    def plan(self, deposit=None, *, prior=None, events=None, vout=0, change=None):
        return prepare_mint(
            self.policy, self.genesis if prior is None else prior, MintEvents() if events is None else events,
            self.first if deposit is None else deposit, Input(self.sponsor.txid_wire(), vout), change=change,
        )

    def test_signed_sequential_mints_recover_after_restart(self):
        first = self.plan(change=Output(8000, bytes.fromhex("76a914" + "a1" * 20 + "88ac")))
        first_tx = authorize_mint(first, lambda _: self.first, sign)
        self.assertEqual(run_script(first_tx, self.genesis), ([b"\x01"], []))
        self.assertEqual(read_deposit(first_tx), self.first)
        self.assertEqual(read_token(first_tx.outputs[1].script, VERIFIER).quantity, 1024)
        restored = recover_events(self.policy, self.genesis, (first_tx,))
        self.assertEqual(restored, first.successor)
        with self.assertRaisesRegex(ValueError, "already consumed"):
            self.plan(prior=first_tx, events=restored, vout=1)

        second = self.plan(self.second, prior=first_tx, events=restored, vout=1)
        second_tx = authorize_mint(second, lambda _: self.second, sign)
        self.assertEqual(run_script(second_tx, first_tx), ([b"\x01"], []))
        self.assertEqual(recover_events(self.policy, self.genesis, (first_tx, second_tx)), second.successor)
        self.assertEqual(transition_roots(self.second.position.event_id(), second.path), (restored.root, second.successor.root))
        self.assertIn(self.first.position.event_id(), second.successor.consumed)
        if find_spec("tx_engine"):
            from shared.chain_gang import validate_at_heights

            validate_at_heights(first_tx, (self.genesis, self.sponsor), spend_height=100,
                                activation_height=2, utxo_heights=(3, 3))
            validate_at_heights(second_tx, (first_tx, self.sponsor), spend_height=101,
                                activation_height=2, utxo_heights=(100, 3))

    def test_wrong_chain_asset_and_nonfinal_receipts_are_rejected(self):
        for deposit in (
            replace(self.first, position=replace(self.first.position, source_chain_id=11155111)),
            replace(self.first, position=replace(self.first.position, reserve_domain=8)),
            replace(self.first, position=replace(self.first.position, reserve_contract=b"f" * 20)),
            replace(self.first, asset_id=b"f" * 32),
            replace(self.first, reserve_asset=b"f" * 32),
            replace(self.first, destination_network=2),
        ):
            with self.subTest(deposit=deposit), self.assertRaisesRegex(ValueError, "mint policy"):
                self.plan(deposit)
            bypass = replace(self.plan(), deposit=deposit)
            with self.assertRaises(ScriptError):
                run_script(force_sign(bypass), self.genesis)
        for observed in (None, replace(self.first, owner=public(OTHER)), replace(self.first, gross_quantity=1025)):
            with self.subTest(observed=observed), self.assertRaisesRegex(ValueError, "finalized"):
                authorize_mint(self.plan(), lambda _: observed, sign)
        with self.assertRaisesRegex(ValueError, "invalid secp256k1 public key"):
            self.plan(replace(self.first, owner=b"\x02" + b"\xff" * 32))

    def test_attestor_and_output_tampering(self):
        first = self.plan()
        with self.assertRaises(ScriptError):
            run_script(force_sign(first, signer=OTHER), self.genesis)

        tx = first.transaction
        alternatives = (
            replace(tx, outputs=(tx.outputs[0], self.policy.token_output(1025, self.first.owner), tx.outputs[2])),
            replace(tx, outputs=(tx.outputs[0], self.policy.token_output(1024, public(OTHER)), tx.outputs[2])),
            replace(tx, outputs=(self.genesis.outputs[0], *tx.outputs[1:])),
            replace(tx, outputs=(tx.outputs[1], tx.outputs[0], tx.outputs[2])),
            replace(tx, outputs=(*tx.outputs[:2], replace(tx.outputs[2], script=tx.outputs[2].script + b"\x00"))),
            replace(tx, outputs=(*tx.outputs, Output(1, asm("OP_1")))),
        )
        for bad in alternatives:
            with self.subTest(txid=bad.txid()), self.assertRaises((ScriptError, ValueError)):
                run_script(force_sign(first, transaction=bad), self.genesis)
        reordered = replace(tx, inputs=tx.inputs[::-1])
        prior = self.genesis.outputs[0]
        preimage = preimage_all(reordered, 1, prior.value, prior.script)
        wrong_position = reordered.with_script(1, b"".join(push(field) for field in (
            sign(hash256(preimage)) + b"\x41", b"".join(first.path), self.first.encode(),
            b"".join(item.outpoint() for item in reordered.inputs), b"", preimage,
        )))
        with self.assertRaises(ScriptError):
            run_script(wrong_position, self.genesis, input_index=1)
        with self.assertRaises(ScriptError):
            run_script(force_sign(replace(first, path=(b"t" * 32, *first.path[1:]))), self.genesis)

    def test_reissued_event_rejected_by_script_after_state_advance(self):
        first = self.plan()
        first_tx = authorize_mint(first, lambda _: self.first, sign)
        replay = replay_plan(first, first_tx, Input(self.sponsor.txid_wire(), 1))
        # A fresh valid attestor signature still cannot prove emptiness for the used event.
        with self.assertRaises(ScriptError):
            run_script(force_sign(replay), first_tx)
        revised = replace(first.deposit, owner=public(OTHER), gross_quantity=2048)
        self.assertEqual(revised.position.event_id(), first.deposit.position.event_id())
        with self.assertRaisesRegex(ValueError, "already consumed"):
            self.plan(revised, prior=first_tx, events=first.successor, vout=1)

    def test_pause_key_preserves_state_and_blocks_mint_until_resume(self):
        policy = replace(self.policy, pause_authority=public(OTHER))
        genesis = replace(self.genesis, outputs=(Output(1500, policy.state_lock(EMPTY_ROOT)),))
        first_deposit, second_deposit = event(policy, 1, 1024), event(policy, 2, 384)
        sponsor = Input(self.sponsor.txid_wire(), 0)
        first = prepare_mint(policy, genesis, MintEvents(), first_deposit, sponsor)
        first_tx = authorize_mint(first, lambda _: first_deposit, sign)
        self.assertEqual(run_script(first_tx, genesis), ([b"\x01"], []))
        sponsor2 = replace(sponsor, vout=1)
        bad_pause = authorize_pause(policy, first_tx, first.successor, sponsor2, sign, paused=True)
        with self.assertRaises(ScriptError):
            run_script(bad_pause, first_tx)
        pause_sign = lambda digest: sign(digest, OTHER)
        paused = authorize_pause(policy, first_tx, first.successor, sponsor2, pause_sign, paused=True,
                                 change=Output(8000, bytes.fromhex("76a914" + "a1" * 20 + "88ac")))
        self.assertEqual(run_script(paused, first_tx), ([b"\x01"], []))
        recovered = recover_mint_state(policy, genesis, (first_tx, paused))
        self.assertTrue(recovered.paused)
        self.assertEqual(recovered.events, first.successor)

        sponsor3 = replace(sponsor, vout=2)
        with self.assertRaisesRegex(ValueError, "minting is paused"):
            prepare_mint(policy, paused, first.successor, second_deposit, sponsor3)
        hypothetical = prepare_mint(policy, first_tx, first.successor, second_deposit, sponsor3)
        invalid = replace(hypothetical.transaction, inputs=(Input(paused.txid_wire(), 0), sponsor3))
        with self.assertRaises(ScriptError):
            run_script(force_sign(replace(hypothetical, prior=paused), transaction=invalid), paused)
        resumed = authorize_pause(policy, paused, first.successor, sponsor3, pause_sign, paused=False)
        self.assertEqual(run_script(resumed, paused), ([b"\x01"], []))
        restored = recover_mint_state(policy, genesis, (first_tx, paused, resumed))
        self.assertFalse(restored.paused)
        self.assertEqual(restored.events, first.successor)

    def test_counted_mint_state_checks_the_full_uint128_range(self):
        policy = replace(self.policy, state_version=2)
        sponsor = Input(self.sponsor.txid_wire(), 0)
        deposit = replace(self.first, gross_quantity=9, fee_quantity=8)
        events = MintEvents()

        def state_output(total):
            return Output(1500, policy.state_lock(EMPTY_ROOT, cumulative_minted=total))

        # Synthetic previous outputs isolate arithmetic. Genesis separately requires zero.
        for old_total in ((1 << 127) - 1, (1 << 128) - 2):
            with self.subTest(old_total=old_total):
                prior = replace(self.genesis, outputs=(state_output(old_total),))
                plan = prepare_mint(policy, prior, events, deposit, sponsor)
                signed = authorize_mint(plan, lambda _: deposit, sign)
                self.assertEqual(run_script(signed, prior), ([b"\x01"], []))
                self.assertEqual(policy.parse_state_lock(signed.outputs[0].script).cumulative_minted, old_total + 1)
                with self.assertRaisesRegex(ValueError, "anchored empty mint state"):
                    policy.check_genesis(prior)

        overflow = replace(self.genesis, outputs=(state_output((1 << 128) - 1),))
        with self.assertRaisesRegex(ValueError, "uint128"):
            prepare_mint(policy, overflow, events, deposit, sponsor)
        attempted_wrap = replace(plan.transaction, inputs=(Input(overflow.txid_wire(), 0), sponsor),
                                 outputs=(Output(1500, policy.state_lock(plan.successor.root)), *plan.transaction.outputs[1:]))
        with self.assertRaises(ScriptError):
            run_script(force_sign(replace(plan, prior=overflow), transaction=attempted_wrap), overflow)

    @unittest.skipUnless(os.environ.get("CCTP_MINT_REGTEST_COOKIE"), "requires independent BSV regtest")
    def test_independent_node_mints_and_rejects_replay(self):
        self._independent_node_mints(state_version=1)

    @unittest.skipUnless(os.environ.get("CCTP_MINT_REGTEST_COOKIE"), "requires independent BSV regtest")
    def test_independent_node_enforces_cumulative_minting(self):
        self._independent_node_mints(state_version=2)

    def _independent_node_mints(self, *, state_version):
        node = Node(os.environ.get("CCTP_MINT_REGTEST_URL", "http://127.0.0.1:19444"),
                    Path(os.environ["CCTP_MINT_REGTEST_COOKIE"]))
        owner_hash = new("ripemd160", sha256(public(OWNER)).digest()).digest()
        address = base58check(b"\x6f" + owner_hash)
        coinbase = node.fund(address)
        funded = Transaction((Input(coinbase.txid_wire(), 0),), (Output(200_000, asm("OP_1")),) * 6)
        funded = sign_p2pkh(funded, coinbase, 0, OWNER)
        node.confirm(funded, address)
        anchor = Input(funded.txid_wire(), 0)
        policy = replace(setup_policy(anchor), pause_authority=public(OTHER), state_version=state_version)
        genesis = Transaction((anchor,), (Output(100_000, policy.state_lock(EMPTY_ROOT)),))
        node.confirm(genesis, address)
        first_event, second_event = event(policy, 1, 1024), event(policy, 2, 384, OTHER)
        if state_version == 2:
            first_event = replace(first_event, fee_quantity=7)
            second_event = replace(second_event, fee_quantity=1)
        first = prepare_mint(policy, genesis, MintEvents(), first_event, Input(funded.txid_wire(), 1))
        competitor = prepare_mint(policy, genesis, MintEvents(), first_event, Input(funded.txid_wire(), 2))
        first_tx = authorize_mint(first, lambda _: first_event, sign)
        node.submit(first_tx)
        with self.assertRaises(RpcFailure) as conflict:
            node.submit(authorize_mint(competitor, lambda _: first_event, sign))
        self.assertIn("mempool-conflict", str(conflict.exception))
        first_block = node.call("generatetoaddress", 1, address)[0]
        self.assertIn(first_tx.txid(), node.call("getblock", first_block, 1)["tx"])

        replay = replay_plan(first, first_tx, Input(funded.txid_wire(), 2))
        with self.assertRaises(RpcFailure) as replay_error:
            node.submit(force_sign(replay))
        self.assertIn("mandatory-script-verify-flag-failed", str(replay_error.exception))
        pause_sign = lambda digest: sign(digest, OTHER)
        paused = authorize_pause(policy, first_tx, first.successor, Input(funded.txid_wire(), 4),
                                 pause_sign, paused=True)
        node.confirm(paused, address)
        sponsor = Input(funded.txid_wire(), 3)
        unpaused_only = prepare_mint(policy, first_tx, first.successor, second_event, sponsor)
        invalid = replace(unpaused_only.transaction, inputs=(Input(paused.txid_wire(), 0), sponsor))
        with self.assertRaises(RpcFailure) as paused_mint:
            node.submit(force_sign(replace(unpaused_only, prior=paused), transaction=invalid))
        self.assertIn("mandatory-script-verify-flag-failed", str(paused_mint.exception))
        resumed = authorize_pause(policy, paused, first.successor, Input(funded.txid_wire(), 5),
                                  pause_sign, paused=False)
        node.confirm(resumed, address)
        history = (first_tx, paused, resumed)
        restarted = recover_mint_state(policy, genesis, history)
        second = prepare_mint(policy, restarted.transaction, restarted.events, second_event, sponsor)
        if state_version == 2:
            self.assertEqual(restarted.cumulative_minted, first_event.net_quantity)
            for state_tx in (first_tx, paused, resumed):
                self.assertEqual(policy.parse_state_lock(state_tx.outputs[0].script).cumulative_minted,
                                 first_event.net_quantity)
            gross = first_event.net_quantity + second_event.gross_quantity
            wrong_state = replace(second.transaction.outputs[0], script=policy.state_lock(
                second.successor.root, cumulative_minted=gross,
            ))
            bad_total = replace(second.transaction, outputs=(wrong_state, *second.transaction.outputs[1:]))
            with self.assertRaises(RpcFailure) as wrong_total:
                node.submit(force_sign(second, transaction=bad_total))
            self.assertIn("mandatory-script-verify-flag-failed", str(wrong_total.exception))
        second_tx = authorize_mint(second, lambda _: second_event, sign)
        node.confirm(second_tx, address)
        recovered = recover_mint_state(policy, genesis, (*history, second_tx))
        self.assertEqual(recovered.events, second.successor)
        if state_version == 2:
            self.assertEqual(recovered.cumulative_minted, first_event.net_quantity + second_event.net_quantity)

        if os.environ.get("CCTP_MINT_REPORT"):
            import json

            second_block = node.call("getrawtransaction", second_tx.txid(), True)["blockhash"]
            report = {
                "node": node.call("getnetworkinfo")["subversion"],
                "mint_state_version": state_version,
                "genesis_txid": genesis.txid(),
                "first": {"txid": first_tx.txid(), "block": first_block, "quantity": first_event.net_quantity},
                "second": {"txid": second_tx.txid(), "block": second_block, "quantity": second_event.net_quantity},
                "pause_txid": paused.txid(),
                "resume_txid": resumed.txid(),
                "mint_while_paused": str(paused_mint.exception),
                "competing_mint": str(conflict.exception),
                "resigned_replay": str(replay_error.exception),
                "first_mint_bytes": len(first_tx.serialize()),
                "state_lock_bytes": len(genesis.outputs[0].script),
            }
            if state_version == 2:
                report.update({
                    "cumulative_minted_by_stage": [
                        policy.parse_state_lock(tx.outputs[0].script).cumulative_minted
                        for tx in (genesis, first_tx, paused, resumed, second_tx)
                    ],
                    "wrong_cumulative_minted": str(wrong_total.exception),
                    "second_mint_bytes": len(second_tx.serialize()),
                })
            Path(os.environ["CCTP_MINT_REPORT"]).write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    unittest.main()
