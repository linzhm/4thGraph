"""Exercise the same-key lifecycle on isolated Anvil and independent BSV regtest."""
import argparse
from contextlib import closing
from dataclasses import dataclass, replace
import json
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory

from bridge_ledger import BridgeLedger
from burn_receipt import BurnReceipt
from certified_burn_provenance import CertifiedBurnProvenance
from certified_wallet_provenance import CertifiedWalletProvenance
from committed_verifier import load_verifying_key
from continuity_statement import ParentReceipt
from continuity_verifier import ContinuityVerifier, SINGLE_OUTPUT_MARKER
from cross_chain_fixture import AdoptedBsvChain, DurableBridge, LocalReserve
from mint import MintPolicy, authorize_pause, prepare_mint
from mint_events import EMPTY_ROOT, MintEvents
from operational_token import freeze_witness
from projects.cctp.evm.anvil_fixture import start_anvil
from projects.cctp.evm.bsv_burn_evidence import BsvTransactionLocation, BurnReference
from projects.cctp.evm.release_adapter import burn_event_id
from run_continuity_regtest import NativeProver, _checkpoint, _prove, _save, _sign
from run_recursive_mimo import Regtest
from shared.transaction import Input, Output, Transaction
from test_operational_token import fixture_signer
from usdc_amount import parse_usdc
from wallet_receipt import SpendStatus


@dataclass(frozen=True)
class CertifiedOutput:
    transaction: Transaction
    position: int
    funding: Transaction
    proof: Path

    def input(self):
        return Input(self.transaction.txid_wire(), self.position)


class Lifecycle:
    def __init__(self, node, prover, key_artifact, evm):
        self.node, self.prover = node, prover
        freeze_key, self.freeze_sign = fixture_signer(12)
        pause_key, self.pause_sign = fixture_signer(14)
        self.setup = node.setup(outputs=11)
        anchor = Input(self.setup.txid_wire(), 0)
        self.reserve = LocalReserve(evm, anchor.outpoint())
        template = MintPolicy(self.reserve.asset, self.reserve.scope.chain_id, self.reserve.scope.vault,
                              node.minter_key, lambda _: b"", pause_authority=pause_key)
        key, commitment = load_verifying_key(key_artifact)
        self.verifier = ContinuityVerifier(
            template, freeze_key, key, commitment, bytes.fromhex(key_artifact["continuity_key_digest"]),
            certified_mints=True, certified_admin=True, certified_burns=True,
            certified_single_output=True, certified_pause=True,
        )
        self.mint_policy = self.verifier.mint_policy
        self.genesis = node.include("mint-genesis", Transaction(
            (anchor,), (Output(self.setup.outputs[0].value - 50_000, self.mint_policy.state_lock(EMPTY_ROOT)),),
        ), (self.setup,))
        self.bridge = DurableBridge(self.reserve, self.mint_policy, prover.out / "bridge.sqlite")
        self.events = MintEvents()
        self.transitions = []
        self.state = None
        self.next_funding = 1
        self.proof_checks = {}

    def fund(self, label):
        index = self.next_funding
        self.next_funding += 1
        output = Output(self.setup.outputs[index].value - 1_000_000, self.verifier.lock)
        candidate = Transaction((Input(self.setup.txid_wire(), index),), (output,))
        return self.node.include(f"funding-{label}", candidate, (self.setup,))

    def mine_confirmation(self):
        self.node.node.call("generatetoaddress", 1, self.node.address)

    def adopted(self):
        return AdoptedBsvChain(self.node.node, {
            bytes.fromhex(record["txid"])[::-1]: record["blockhash"]
            for record in self.node.evidence["transactions"].values()
        })

    def locations(self):
        return {
            bytes.fromhex(record["txid"])[::-1]: BsvTransactionLocation(
                bytes.fromhex(record["blockhash"])[::-1], record["height"],
            ) for record in self.node.evidence["transactions"].values()
        }

    def state_prior(self):
        return self.genesis if self.state is None else self.state.transaction

    def _receipt(self, origins):
        return ParentReceipt(tuple(self.verifier.proof_digest(item.transaction, item.funding) for item in origins))

    def _submit(self, label, funding, origins, verified, witness, *, position, quantities, coin_parents=None):
        receipt, context = verified
        artifact, public, proof = _prove(self.verifier, self.prover, label, receipt, context,
                                         tuple(item.proof for item in origins))
        signed = witness(proof)
        if coin_parents is None:
            coin_parents = (funding, *(item.transaction for item in origins))
        self.node.include(label, signed, coin_parents)
        spent = tuple((item.transaction, item.position) for item in origins)
        _, _, details = _checkpoint(self.node, self.prover, label, signed, funding, artifact, public, receipt,
                                    quantities, spent, {})
        self.proof_checks[label] = details
        record = self.node.evidence["transactions"][label]
        print(f"{label} confirmed at {record['height']} ({record['bytes']} bytes)", flush=True)
        return CertifiedOutput(signed, position, funding, artifact)

    def mint(self, label, quantity, *, interrupt=False):
        deposit, source = self.reserve.deposit(quantity, self.node.owner_key)
        funding, prior = self.fund(label), self.state_prior()
        self.mine_confirmation()
        chain = self.adopted()

        def load_state():
            return chain.mint_state(self.mint_policy, self.genesis, self.transitions)

        previous = load_state()
        origins = () if self.state is None else (self.state,)
        support = None if self.state is None else self.state.funding
        plan = prepare_mint(self.mint_policy, prior, self.events, deposit, Input(funding.txid_wire(), 0),
                            receipt=self._receipt(origins), verifier_parent=funding)

        def resolve_funding(txid):
            raw = chain.raw(txid)
            if raw is None:
                raise ValueError("saved mint verifier funding is not confirmed")
            return Transaction.parse(raw)

        signed, journal = self.bridge.authorize_mint(plan, load_state, self.node.minter, interrupt=interrupt,
                                                     resolve_verifier_funding=resolve_funding)
        verify = self.verifier.validate_mint(signed, funding, prior, support)
        mint = self._submit(label, funding, origins, verify,
                            lambda proof: signed.with_script(1, self.verifier.mint_witness(
                                proof, signed, funding, prior, support,
                            )), position=1, quantities=(quantity,), coin_parents=(prior, funding))
        self.mine_confirmation()
        after = self.bridge.record_mint(self.adopted(), mint.transaction, previous, deposit.position.event_id())
        self.transitions.append(mint.transaction)
        self.events, self.state = plan.successor, replace(mint, position=0)
        return mint, {"source": source, "intent": journal, "effect": after}

    def pause_mint(self, label, paused):
        prior, funding = self.state_prior(), self.fund(label)
        origins = () if self.state is None else (self.state,)
        support = None if self.state is None else self.state.funding
        signed = authorize_pause(self.mint_policy, prior, self.events, Input(funding.txid_wire(), 0),
                                  self.pause_sign, paused=paused, receipt=self._receipt(origins), verifier_parent=funding)
        verified = self.verifier.validate_pause(signed, funding, prior, support)
        self.state = self._submit(label, funding, origins, verified,
                                  lambda proof: signed.with_script(1, self.verifier.pause_witness(
                                      proof, signed, funding, prior, support,
                                  )), position=0, quantities=(), coin_parents=(prior, funding))
        self.transitions.append(self.state.transaction)
        self.mine_confirmation()
        recovered = self.adopted().mint_state(self.mint_policy, self.genesis, self.transitions)
        if recovered.events != self.events or recovered.paused != paused:
            raise AssertionError("confirmed pause did not preserve the logged mint state")

    def toggle(self, label, item):
        funding, prior = self.fund(label), item.transaction
        output = prior.outputs[item.position]
        state = self.verifier.policy.parse(output.script)
        successor = replace(output, script=self.verifier.policy.lock(replace(state, frozen=not state.frozen)))
        tx = Transaction((item.input(), Input(funding.txid_wire(), 0)), (successor, self._receipt((item,)).output()))
        signed = tx.with_script(0, freeze_witness(tx, 0, prior, self.verifier.policy, self.freeze_sign,
                                                 verifier_parent=funding))
        verified = self.verifier.validate_admin(signed, funding, prior, item.funding)
        return self._submit(label, funding, (item,), verified,
                            lambda proof: signed.with_script(1, self.verifier.admin_witness(
                                proof, signed, funding, prior, item.funding,
                            )), position=0, quantities=(state.quantity,), coin_parents=(prior, funding))

    def transfer(self, label, origins, quantities, *, burn=None):
        funding = self.fund(label)
        parents = tuple(item.transaction for item in origins)
        supports = tuple(item.funding for item in origins)
        successors = tuple(self.mint_policy.token_output(number, self.node.owner_key) for number in quantities)
        if burn is not None:
            successors = (burn.output(), *successors)
        elif len(successors) == 1:
            successors += (SINGLE_OUTPUT_MARKER,)
        tx = Transaction((Input(funding.txid_wire(), 0), *(item.input() for item in origins)),
                         (*successors, self._receipt(origins).output()))
        if burn is None:
            verified = self.verifier.validate(tx, funding, parents, supports)
            choose_witness = self.verifier.witness
        else:
            receipt, context, actual = self.verifier.validate_burn(tx, funding, parents, supports)
            if actual != burn:
                raise AssertionError("certified burn changed the reserve payout fields")
            verified = receipt, context
            choose_witness = self.verifier.burn_witness

        def sign(proof):
            material = choose_witness(proof, tx, funding, parents, supports)
            return _sign(self.node, self.verifier, tx, funding, parents, material)

        return self._submit(label, funding, origins, verified, sign, position=int(burn is not None and bool(quantities)),
                            quantities=quantities)

    def release(self, item, live, *, interrupt=False):
        self.mine_confirmation()
        chain = self.adopted()
        provenance = CertifiedBurnProvenance(self.verifier, self.locations().get)
        circulating, frozen = self.supply(*live)
        if frozen:
            raise AssertionError("unexpected frozen supply at release checkpoint")
        return self.bridge.release(chain, item.transaction, 0, provenance, circulating=circulating, interrupt=interrupt)

    def wallet_acceptance(self, minted, frozen, change):
        chain = self.adopted()
        policy = chain.confirmation_policy(self.verifier.asset)
        provenance = CertifiedWalletProvenance(self.verifier, chain.call, policy, self.locations().get)
        evidence = []
        for item, quantity, flag, status in (
            (minted, 1024, False, SpendStatus.SPENT),
            (frozen, 640, True, SpendStatus.SPENT),
            (change, 384, False, SpendStatus.UNSPENT),
        ):
            receipt, fields = chain.payment(item.transaction, item.position, self.verifier.asset,
                                             self.verifier.policy, provenance, self.node.owner_key)
            if (receipt.quantity, receipt.frozen, receipt.spend_status) != (quantity, flag, status):
                raise AssertionError("wallet receipt disagrees with the expected selected output")
            evidence.append(fields)
        if provenance.valid_creation(change.transaction, 0):
            raise AssertionError("wallet accepted a burn receipt as a token output")
        return evidence

    def supply(self, *live):
        circulating = frozen = 0
        for item in live:
            found = self.node.node.call("gettxout", item.transaction.txid(), item.position, False)
            output = item.transaction.outputs[item.position]
            if not found or found["scriptPubKey"]["hex"] != output.script.hex():
                raise AssertionError("selected supply output is missing from the independent node UTXO set")
            state = self.verifier.policy.parse(output.script)
            circulating += state.quantity
            if state.frozen:
                frozen += state.quantity
        return circulating, frozen


def exercise_release_reorg(node, service, policy, reference, verifier, accounting):
    """Temporarily roll back the final burn in a dedicated BSV regtest."""
    tip = node.call("getblockchaininfo")
    blockhash = reference.block_hash[::-1].hex()
    if (policy.rpc_chain != "regtest" or tip["chain"] != "regtest"
            or tip["blocks"] != reference.block_height + 1
            or node.call("getblockhash", reference.block_height) != blockhash):
        raise ValueError("the reorg probe requires the dedicated regtest tip immediately after final burn confirmation")
    event = burn_event_id(policy.network, reference)

    def forbidden(*_):
        raise AssertionError("reorganized burn reached a source RPC or signer callback")

    with TemporaryDirectory(prefix="cctp-reorg-probe-") as directory:
        path = Path(directory) / "bridge.sqlite"
        with closing(sqlite3.connect(service.ledger.path)) as original, closing(sqlite3.connect(path)) as copy:
            original.backup(copy)

        def ledger():
            return BridgeLedger(path, verifier.asset, service.reserve_scope.chain_id, service.reserve_scope.vault)

        check = replace(service, ledger=ledger(), evm_rpc=forbidden)
        if check.ledger.state(event).phase != "settled":
            raise AssertionError("burn must already have finalized source settlement before the reorg probe")
        provenance = CertifiedBurnProvenance(verifier, forbidden)
        try:
            node.call("invalidateblock", blockhash)
            height = node.call("getblockchaininfo")["blocks"]
            if height >= reference.block_height:
                raise AssertionError("the test burn block remains on the active chain")
            try:
                check.authorize_release(node.call, policy, reference, provenance, forbidden)
            except ValueError as error:
                if str(error) != "recorded BSV block was replaced":
                    raise
            else:
                raise AssertionError("orphaned burn reached release authorization")
        finally:
            node.call("reconsiderblock", blockhash)
        if node.call("getbestblockhash") != tip["bestblockhash"]:
            raise AssertionError("the dedicated regtest was not restored")

        reopened = ledger()
        state = reopened.state(event)
        reconciliation = reopened.reconcile(
            source_balance=accounting["actual_vault_balance"],
            live_supply=accounting["bsv_circulating"], frozen_supply=accounting["bsv_frozen"],
        )
        reasons = [reason for _, reason in reconciliation.holds]
        if (state.phase != "held" or state.origin_confirmed or not state.effect_confirmed
                or reconciliation.may_authorize or "origin reorganized after external authorization" not in reasons):
            raise AssertionError("the paid, orphaned burn did not retain its hold after restart")
        return {"burn_event_id": event.hex(), "orphaned_bsv_block": blockhash, "reverted_bsv_height": height,
                "restored_bsv_tip": tip["bestblockhash"], "ledger_phase_after_reopen": state.phase,
                "prior_release_still_finalized": state.effect_confirmed,
                "may_authorize_after_reopen": reconciliation.may_authorize, "persisted_hold_reasons": reasons,
                "source_rpc_or_signer_called": False}


def run(node, prover, key_artifact, evm, *, reorg_probe=False):
    lab = Lifecycle(node, prover, key_artifact, evm)
    minted, first = lab.mint("mint-1024", parse_usdc("0.001024"), interrupt=True)
    split = lab.transfer("split", (minted,), (640, 384))
    retained = replace(split, position=1)
    frozen = lab.toggle("freeze-640", split)
    freeze_accounting = lab.bridge.reconcile(*lab.supply(frozen, retained))
    resumed = lab.toggle("unfreeze-640", frozen)
    merged = lab.transfer("merge-1024", (resumed, retained), (1024,))
    burn = BurnReceipt(lab.verifier.asset.asset_id(), lab.verifier.asset.reserve_domain, lab.reserve.recipient, 640)
    change = lab.transfer("partial-burn-640", (merged,), (384,), burn=burn)
    primary_release = lab.release(change, (change,), interrupt=True)
    primary = lab.bridge.reconcile(*lab.supply(change))
    if (primary["net_reserve"], primary["bsv_circulating"], primary["pending_mint"], primary["pending_release"]) != (384, 384, 0, 0):
        raise AssertionError("primary lifecycle must settle to 384 base units on both chains")

    lab.pause_mint("pause-minting", True)
    lab.pause_mint("resume-minting", False)
    second_mint, second = lab.mint("mint-64-after-resume", parse_usdc("0.000064"))
    full = lab.transfer("full-burn-64", (second_mint,), (), burn=replace(burn, quantity=64))
    full_release = lab.release(full, (change,))
    final = lab.bridge.reconcile(*lab.supply(change))
    report = {
        "scope": "Same-key continuity on independent BSV regtest with a local Anvil mock USDC reserve",
        "asset_id": lab.verifier.asset.asset_id().hex(),
        "continuity_key_digest": lab.verifier.key_digest.hex(),
        "evm": {"chain_id": lab.reserve.scope.chain_id, "reserve": lab.reserve.vault, "token": lab.reserve.usdc},
        "mints": [first, second], "proof_checks": lab.proof_checks, "freeze_accounting": freeze_accounting,
        "releases": [primary_release, full_release], "after_primary_scenario": primary,
        "wallet": lab.wallet_acceptance(minted, frozen, change),
        "final_accounting": final, "journal": lab.bridge.audit(), **node.evidence,
    }
    if reorg_probe:
        chain = lab.adopted()
        spent = chain.reference(full.transaction, 0)
        reference = BurnReference(spent.txid, spent.position, spent.block_hash, spent.height)
        report["post_release_reorg"] = exercise_release_reorg(
            node.node, lab.bridge.reopen(), chain.confirmation_policy(lab.verifier.asset), reference, lab.verifier, final,
        )
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-url", default=os.environ.get("REGTEST_URL"))
    parser.add_argument("--cookie", type=Path, default=os.environ.get("REGTEST_COOKIE"))
    parser.add_argument("--prover", type=Path, required=True)
    parser.add_argument("--setup-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--reorg-probe", action="store_true", help="temporarily revert the final burn on a dedicated regtest")
    args = parser.parse_args()
    if not (args.node_url and args.cookie):
        parser.error("independent BSV regtest RPC and cookie are required")
    key_artifact = json.loads((args.setup_dir / "key.json").read_text())
    args.out.mkdir()
    node = Regtest(args.node_url, args.cookie)
    with NativeProver(args.prover, args.setup_dir, args.out, key_artifact["continuity_key_digest"]) as prover, start_anvil() as evm:
        _save(args.out / "summary.json", run(node, prover, key_artifact, evm, reorg_probe=args.reorg_probe))


if __name__ == "__main__":
    main()
