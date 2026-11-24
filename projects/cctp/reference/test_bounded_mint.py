"""Exercise the bounded counted mint with the real sparse roots and issuer checks."""

from dataclasses import replace
from hashlib import new, sha256
from itertools import permutations
import json
import os
from pathlib import Path
import unittest

from ecdsa.util import sigencode_der_canonize

from bounded_mint import BoundedMintPolicy
from mint import _record, authorize_mint, prepare_mint, recover_mint_state
from mint_events import EMPTY_ROOT, TREE_DEPTH, MintEvents, transition_roots
from regtest_mint import Node, RpcFailure, base58check, sign_p2pkh
from shared.evaluate import ScriptError
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction
from test_mint import ATTESTOR, OTHER, OWNER, VERIFIER, event, force_sign, public, run_script, setup_policy
from transaction_relation import read_token


def fixture(anchor, count=3):
    base = setup_policy(anchor)
    deposits = tuple(
        replace(event(base, i, gross, owner), fee_quantity=fee)
        for i, (gross, fee, owner) in enumerate(((1024, 7, OWNER), (384, 1, OTHER), (257, 3, OWNER))[:count], 1)
    )
    policy = BoundedMintPolicy(base.asset, base.source_chain_id, base.reserve_contract, base.attestor, base.lock_token,
                               event_ids=tuple(deposit.position.event_id() for deposit in deposits))
    return policy, deposits


def sign_fixed_width(digest):
    # Test keys only. Control DER width for serialized size comparisons.
    for attempt in range(256):
        sig = ATTESTOR.sign_digest_deterministic(digest, hashfunc=sha256, sigencode=sigencode_der_canonize,
                                                extra_entropy=bytes([attempt]))
        if len(sig) == 70:
            return sig
    raise AssertionError("could not produce a 70-byte test signature")


def sign_mint(plan):
    return authorize_mint(plan, lambda _: plan.deposit, sign_fixed_width)


def signed_unchecked_event(plan, deposit):
    """Re-sign a draft whose outputs match a replayed or unapproved deposit."""
    policy = plan.policy
    old_state = plan.prior.outputs[0]
    initial = policy.parse_state_lock(old_state.script)
    successor = MintEvents(plan.events.consumed | {deposit.position.event_id()})
    outputs = (
        Output(old_state.value, policy.state_lock(successor.root,
                                                 cumulative_minted=initial.cumulative_minted + deposit.net_quantity)),
        policy.token_output(deposit.net_quantity, deposit.owner),
        _record(deposit),
    )
    tx = replace(plan.transaction, outputs=outputs)
    return force_sign(replace(plan, deposit=deposit), transaction=tx)


class BoundedMintTests(unittest.TestCase):
    def setUp(self):
        self.anchor = Input(b"x" * 32, 0)
        self.policy, self.deposits = fixture(self.anchor)
        self.genesis = Transaction((self.anchor,), (Output(100_000, self.policy.state_lock(EMPTY_ROOT)),))

    def test_all_event_orders_use_the_actual_sparse_roots(self):
        for count in (2, 3):
            policy, deposits = fixture(self.anchor, count)
            genesis = replace(self.genesis, outputs=(Output(100_000, policy.state_lock(EMPTY_ROOT)),))
            for ordering in permutations(deposits):
                prior, events, history, total = genesis, MintEvents(), [], 0
                for i, deposit in enumerate(ordering):
                    plan = prepare_mint(policy, prior, events, deposit, Input(b"s" * 32, i))
                    self.assertEqual(len(plan.path), TREE_DEPTH)
                    self.assertEqual(transition_roots(deposit.position.event_id(), plan.path),
                                     (events.root, plan.successor.root))
                    signed = sign_mint(plan)
                    witness = signed.inputs[0].script
                    self.assertEqual(witness[witness[0] + 1], 0)
                    self.assertEqual(run_script(signed, prior), ([b"\x01"], []))
                    total += deposit.net_quantity
                    state = policy.parse_state_lock(signed.outputs[0].script)
                    self.assertEqual((state.root, state.cumulative_minted), (plan.successor.root, total))
                    self.assertEqual(read_token(signed.outputs[1].script, VERIFIER).owner, deposit.owner)
                    history.append(signed)
                    prior, events = signed, plan.successor
                self.assertEqual(recover_mint_state(policy, genesis, tuple(history)).cumulative_minted, total)

    def test_rejects_mutations_with_a_fresh_issuer_signature(self):
        first = prepare_mint(self.policy, self.genesis, MintEvents(), self.deposits[0], Input(b"s" * 32, 0))
        prior = sign_mint(first)
        sponsor = Input(b"s" * 32, 1)
        second = prepare_mint(self.policy, prior, first.successor, self.deposits[1], sponsor)
        foreign = event(self.policy, 9, self.deposits[1].gross_quantity)
        for deposit in (first.deposit, foreign):
            with self.subTest(event=deposit.position.event_id().hex()):
                with self.assertRaises(ValueError):
                    prepare_mint(self.policy, prior, first.successor, deposit, sponsor)
                with self.assertRaises(ScriptError):
                    run_script(signed_unchecked_event(second, deposit), prior)

        signed = sign_mint(second)
        witness = signed.inputs[0].script
        path_offset = witness[0] + 1
        with self.assertRaises(ScriptError):
            run_script(signed.with_script(0, witness[:path_offset] + push(b"bad path") + witness[path_offset + 1:]), prior)

        wrong_state = replace(second.transaction.outputs[0], script=self.policy.state_lock(
            second.successor.root, cumulative_minted=second.deposit.net_quantity,
        ))
        wrong_total = replace(second.transaction, outputs=(wrong_state, *second.transaction.outputs[1:]))
        with self.assertRaises(ScriptError):
            run_script(force_sign(second, transaction=wrong_total), prior)

    def test_event_set_is_bounded_and_canonical(self):
        reverse = replace(self.policy, event_ids=self.policy.event_ids[::-1])
        self.assertEqual(reverse.state_lock(EMPTY_ROOT), self.policy.state_lock(EMPTY_ROOT))
        for ids in ((), self.policy.event_ids + (b"z" * 32,), (b"z" * 32,) * 2, (b"z" * 31, b"x" * 32)):
            with self.subTest(lengths=list(map(len, ids))), self.assertRaises(ValueError):
                replace(self.policy, event_ids=ids)
        with self.assertRaises(ValueError):
            replace(self.policy, state_version=1)

        foreign_events = MintEvents(frozenset((b"z" * 32,)))
        foreign = replace(self.genesis, outputs=(Output(100_000, self.policy.state_lock(foreign_events.root)),))
        with self.assertRaisesRegex(ValueError, "outside the bounded lab mint"):
            prepare_mint(self.policy, foreign, foreign_events, self.deposits[1], Input(b"s" * 32, 0))

    @unittest.skipUnless(os.environ.get("CCTP_BOUNDED_MINT_COOKIE"), "requires isolated BSV regtest")
    def test_three_mints_on_independent_node(self):
        node = Node(os.environ.get("CCTP_BOUNDED_MINT_URL", "http://127.0.0.1:19541"),
                    Path(os.environ["CCTP_BOUNDED_MINT_COOKIE"]))
        self.assertEqual(node.call("getconnectioncount"), 0)
        owner_hash = new("ripemd160", sha256(public(OWNER)).digest()).digest()
        address = base58check(b"\x6f" + owner_hash)
        coinbase = node.fund(address)
        funding = Transaction((Input(coinbase.txid_wire(), 0),), (Output(200_000, asm("OP_1")),) * 4)
        funding = sign_p2pkh(funding, coinbase, 0, OWNER)
        node.confirm(funding, address)
        anchor = Input(funding.txid_wire(), 0)
        policy, deposits = fixture(anchor)
        genesis = Transaction((anchor,), (Output(100_000, policy.state_lock(EMPTY_ROOT)),))
        policy.check_genesis(genesis)
        node.confirm(genesis, address)

        prior, events, history, records, rejections = genesis, MintEvents(), [], [], {}
        for i, deposit in enumerate(deposits, 1):
            plan = prepare_mint(policy, prior, events, deposit, Input(funding.txid_wire(), i))
            if i == 2:
                for label, invalid in (("replay", deposits[0]), ("unapproved", event(policy, 9, 384))):
                    bad = signed_unchecked_event(plan, invalid)
                    with self.assertRaises(RpcFailure) as rejected:
                        node.submit(bad)
                    self.assertIn("mandatory-script-verify-flag-failed", str(rejected.exception))
                    rejections[label] = {"txid": bad.txid(), "rejection": str(rejected.exception)}
            signed = sign_mint(plan)
            node.confirm(signed, address)
            block_hash = node.call("getrawtransaction", signed.txid(), True)["blockhash"]
            self.assertEqual(signed.inputs[0].outpoint(), Input(prior.txid_wire(), 0).outpoint())
            self.assertIsNone(node.call("gettxout", prior.txid(), 0, False))
            state = policy.parse_state_lock(signed.outputs[0].script)
            records.append({
                "txid": signed.txid(), "blockhash": block_hash,
                "height": node.call("getblockheader", block_hash, True)["height"],
                "bytes": len(signed.serialize()),
                "script_sig_bytes": [len(txin.script) for txin in signed.inputs],
                "txout_bytes": [len(output.serialize()) for output in signed.outputs],
                "net_quantity": deposit.net_quantity, "cumulative_minted": state.cumulative_minted,
                "event_root": state.root.hex(), "previous_state_txid": prior.txid(),
            })
            self.assertEqual(state.root, plan.successor.root)
            history.append(signed)
            prior, events = signed, plan.successor

        self.assertEqual([record["bytes"] for record in records], [records[0]["bytes"]] * 3)
        self.assertEqual(recover_mint_state(policy, genesis, tuple(history)).cumulative_minted, 1654)
        if report := os.environ.get("CCTP_BOUNDED_MINT_REPORT"):
            result = {
                "scope": "Native bounded lab mint using three locally attested deposits and actual sparse roots",
                "node": node.call("getnetworkinfo")["subversion"],
                "genesis_txid": genesis.txid(), "genesis_bytes": len(genesis.serialize()),
                "state_lock_bytes": len(genesis.outputs[0].script), "attestation_der_bytes": 70,
                "event_path_bytes_on_wire": 0, "mints": records, "rejections": rejections,
            }
            with Path(report).open("x") as stream:
                json.dump(result, stream, indent=2)
                stream.write("\n")
