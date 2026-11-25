"""Run the fixed-width D+A lifecycle on independent BSV Node and Anvil."""

import argparse
from dataclasses import dataclass, replace
from hashlib import sha256
import json
import lzma
from pathlib import Path
import subprocess
from time import perf_counter

from burn_receipt import BurnReceipt
from cross_chain_fixture import AdoptedBsvChain, DurableBridge, LocalReserve
from mint import MintPolicy
from payment_cost import measure_bundle
from prepared_lifecycle import Action, LIFECYCLE_LAYOUTS, Policy, Previous
from prepared_lifecycle_mint import MintGrant
from prepared_lifecycle_wire import (ACTIVE, BURN, FREEZE, FROZEN, MINT, SUFFIX_BYTES,
                                     TRANSFER, UNFREEZE, State)
from evm.anvil_fixture import start_anvil
from evm.release_adapter import _hash
from regtest_support import Regtest, one_input, p2pk, save, test_signer
from shared.transaction import Input, Output, Transaction
from snarkjs_adapter import load_verification_key
from spv_payment import RegtestHeaderChain
from spv_regtest import archive_packet, header_chain, included_packet, packet_bytes, read_packet
from statement import AssetDescriptor
from wallet_receipt import SpendStatus


ACTIONS = ("mint-300", "mint-200", "mint-150", "alice-to-bob", "bob-to-carol",
           "freeze-carol", "unfreeze-carol", "partial-burn", "full-burn")


@dataclass(frozen=True)
class ConfirmedAction:
    transaction: Transaction
    companion: Transaction
    funding: Transaction
    packet: object
    parents: tuple
    chain: RegtestHeaderChain
    record: dict

    def previous(self, vout):
        return Previous(self.transaction, vout, self.companion)


class Lifecycle:
    def __init__(self, node, evm, out, session, *, layout):
        self.node, self.out, self.session = node, out, session
        if (node.node.call("getblockchaininfo")["chain"] != "regtest"
                or node.node.call("getconnectioncount") or node.node.call("getblockcount")):
            raise ValueError("use a fresh isolated BSV regtest")
        self.alice, self.bob, self.carol = test_signer(21), test_signer(22), test_signer(23)
        self.issuer, self.manager = test_signer(24), test_signer(25)
        self.sponsors = test_signer(26), test_signer(27)
        capital = node.setup(outputs=3, anchor_tag=b"BSV/CCTP/prepared-lifecycle/v1")
        anchor = node.include("issuance-anchor", Transaction(
            (Input(capital.txid_wire(), 0),), (Output(10_000, p2pk(self.issuer[0])),),
        ), (capital,))
        self.state = Previous(anchor, 0)
        self.reserve = LocalReserve(evm, self.state.input.outpoint())
        key = session.key_data
        if key["verifying_key_sha256"] != session.pin:
            raise ValueError("different lifecycle verification key")
        self.policy = Policy(self.reserve.asset, load_verification_key(key), self.issuer[0], self.manager[0],
                             layout=layout)
        self.parameters = key
        # The existing release service uses the reserve scope from a MintPolicy.
        # Lifecycle mint authorizations below use its journal at the actual state vin.
        mint_scope = MintPolicy(self.reserve.asset, self.reserve.scope.chain_id, self.reserve.scope.vault,
                                self.issuer[0], lambda state: State(ACTIVE, state.quantity, owner=state.owner)
                                .output(self.policy.digest).script)
        self.bridge = DurableBridge(self.reserve, mint_scope, out / "bridge.sqlite")
        self.coins = node.include("sponsor-wallets", Transaction(
            (Input(capital.txid_wire(), 1),),
            tuple(Output(1_200_000, p2pk(self.sponsors[i % 2][0])) for i in range(len(ACTIONS)) for _ in range(3)),
        ), (capital,))
        self.results = {}
        self.node_errors, self.proof_errors, self.wallet_errors = {}, {}, {}

    def adopted(self):
        blocks = {bytes.fromhex(row["txid"])[::-1]: row["blockhash"]
                  for row in self.node.evidence["transactions"].values()}
        return AdoptedBsvChain(self.node.node, blocks)

    def fund(self, name, *, fee=False):
        i = ACTIONS.index(name)
        owner, signer = self.sponsors[i % 2]
        pair = tuple(self.node.include(f"{name}-{label}", one_input(
            self.coins, 3*i+j, Output(120_000, lock), signer), (self.coins,))
                     for j, (label, lock) in enumerate((("companion", self.policy.companion),
                                                       ("verifier", self.policy.verifier))))
        if not fee:
            return pair
        payment = self.node.include(f"{name}-fee", one_input(
            self.coins, 3*i+2, Output(10_000, p2pk(owner)), signer), (self.coins,))
        return pair + (payment, signer)

    def prove(self, name, parents, action, *, reject=False):
        openings = tuple(self.policy.opening(item) for item in parents)
        wire = self.policy.statement(openings, action)
        result = self.session.prove(name, self.policy, openings, reject=reject, statement=wire)
        if reject:
            self.proof_errors[name] = result
        return openings, result

    def submit(self, name, parents, action, funded, signers, *, input_signers=(None, None), mint_auth=None):
        companion, verifier = funded[:2]
        draft = self.policy.draft(companion, verifier, parents, action)
        openings, (proof, artifact) = self.prove(f"{name}-proof", parents, action)

        def sign(transaction, callbacks=signers):
            digest = self.policy.verifier_digest(transaction, verifier)
            signatures = (mint_auth(transaction),) * 2 if mint_auth else tuple(cb(digest) for cb in callbacks)
            return self.policy.witness(transaction, companion, verifier, parents, action, proof, openings,
                                       signatures, input_signers)

        if name == "alice-to-bob":
            with_extra = replace(draft, outputs=draft.outputs + (draft.outputs[0],))
            self.node_errors["extra-copied-token"] = self.node.reject(sign(with_extra))
        if name == "freeze-carol":
            self.node_errors["wrong-manager-signature"] = self.node.reject(sign(draft, (self.issuer[1], self.issuer[1])))
        if name == "partial-burn":
            redirection = replace(action.burn, recipient=b"\x6e" * 20).output()
            self.node_errors["changed-burn-recipient"] = self.node.reject(
                sign(replace(draft, outputs=(*draft.outputs[:2], redirection, draft.outputs[3]))))
        tx = sign(draft)
        priors = tuple(dict.fromkeys((companion, verifier, *(item.parent for item in parents))))
        if any(item.source is not None and item.parent.serialize() in tx.serialize() for item in parents):
            raise AssertionError("recursive parent transaction was serialized into the settlement")
        self.node.include(name, tx, priors)
        self.node.node.call("generatetoaddress", 1, self.node.address)
        chain = header_chain(self.node.node)
        labels = {entry["txid"]: label for label, entry in self.node.evidence["transactions"].items()}
        packet = included_packet(self.node, name, tx)
        others = tuple(included_packet(self.node, labels[prior.txid()], prior)
                       for prior in dict.fromkeys(priors))
        item = ConfirmedAction(tx, companion, verifier, packet, others, chain, {
            "action": action.kind, "actual_outpoints": [prev.input.outpoint().hex() for prev in parents],
            "authorized_outputs": [state.encode().hex() for state in action.outputs],
            "proof_seconds": artifact["prove_seconds"], "host_verify_seconds": artifact["verify_seconds"],
            "statement_sha256d": artifact["statement_digest"],
            "cost": measure_bundle(preparation=(companion, verifier, *([funded[2]] if len(funded) == 4 else [])),
                                   settlement=(tx,)),
            "spv_packet_bytes": packet_bytes(packet, others),
        })
        self.results[name] = item
        print(f"{name} height {packet.inclusion.height}, {len(tx.serialize())} B", flush=True)
        return item

    def receive(self, record, vout, expected):
        before = perf_counter()
        paid = self.policy.receive(record.chain, record.packet, record.parents, record.transaction.txid_wire(), vout,
                                   expected)
        record.record.setdefault("spv_receipts", {})[vout] = {
            "outpoint": paid.outpoint.hex(), "confirmed": paid.confirmations,
            "seconds": perf_counter() - before, "spend_status": paid.spend_status.name,
        }
        source = record.parents[0].open(record.chain)[0]
        if source.txid_wire() != paid.transaction.inputs[0].txid:
            raise AssertionError("missing actual authorization source")
        return Previous(paid.transaction, int.from_bytes(paid.outpoint[32:], "little"), source)

    def mint(self, name, units, owner):
        deposit, source = self.reserve.deposit(units, owner)
        grant = MintGrant.prepare(self.policy, self.state, self.reserve.evm.rpc, self.reserve.scope,
                                  deposit.position)
        if grant.deposit != deposit:
            raise AssertionError("unexpected authenticated source deposit")
        old = self.policy.state(self.state)
        event = deposit.position.event_id()
        ledger = self.bridge.reopen().ledger
        action = grant.action
        funded = self.fund(name, fee=True)
        parents = self.state, Previous(funded[2], 0)

        def authorize(transaction):
            def unspent(point):
                return self.adopted().spend(point) == SpendStatus.UNSPENT

            return grant.authorize(self.policy, transaction, *funded[:2], parents, self.reserve.evm.rpc,
                                   ledger, unspent, self.issuer[1])

        if old.nonce:
            stale = replace(action, outputs=(replace(action.outputs[0], nonce=old.nonce), action.outputs[1]))
            self.prove(f"{name}-stale-nonce", parents, stale, reject=True)
        signed = self.submit(name, parents, action, funded, (self.issuer[1],) * 2,
                             input_signers=(self.issuer[1] if self.state.source is None else None, funded[3]),
                             mint_auth=authorize)
        adopted = self.adopted()
        reference = adopted.reference(signed.transaction, 1)
        if adopted.depth(reference.height, reference.block_hash) < 2:
            raise AssertionError("insufficient BSV mint finality")
        ledger.note_confirmed_mint_spend(self.state.input.outpoint(), event,
                                         self.policy.verifier_digest(signed.transaction, signed.funding))
        ledger.observe_mint(event, reference, units, owner, finalized=True)
        if ledger.state(event).phase != "settled":
            raise AssertionError("mint did not settle its journalled finalized deposit")
        signed.record["source_deposit"] = source | {"vault_nonce": grant.evidence.vault_nonce,
                                                    "cumulative_issued": action.outputs[0].units}
        self.state = signed.previous(0)
        if old.nonce == 0:
            try:
                MintGrant.prepare(self.policy, self.state, self.reserve.evm.rpc, self.reserve.scope, deposit.position)
            except ValueError as failure:
                signed.record["repeated_source_event_rejected"] = str(failure)
            else:
                raise AssertionError("same finalized reserve deposit was admitted a second time")
        return self.receive(signed, 1, action.outputs[1].output(self.policy.digest))

    def transfer(self, name, prev, outputs, signers):
        action = Action(TRANSFER, outputs, tuple(entry[0] for entry in signers))
        return self.submit(name, prev, action, self.fund(name), tuple(entry[1] for entry in signers))

    def manage(self, name, action_kind, prev, resulting):
        action = Action(action_kind, resulting, (self.manager[0],) * 2, mask=1)
        return self.submit(name, prev, action, self.fund(name), (self.manager[1],) * 2)

    def burn(self, name, prev, resulting, units, signers):
        receipt = BurnReceipt(self.reserve.asset.asset_id(), self.reserve.asset.reserve_domain, self.reserve.recipient, units)
        action = Action(BURN, resulting, tuple(item[0] for item in signers), burn=receipt)
        return self.submit(name, prev, action, self.fund(name), tuple(item[1] for item in signers)), receipt

    def release(self, action, expected, circulating):
        def provenance(observed, asset):
            if (asset != self.policy.asset or observed.reference.vout != 2
                    or observed.transaction != action.transaction or observed.receipt != expected
                    or observed.reference.block_hash != action.packet.inclusion.block_hash()):
                return False
            self.policy.receive(action.chain, action.packet, action.parents, observed.reference.txid, 2,
                                expected.output())
            return True

        result = self.bridge.release(self.adopted(), action.transaction, 2, provenance, circulating=circulating,
                                     interrupt=True, proof_bound=True)
        evm = self.reserve.evm
        raw = subprocess.run(("cast", "rpc", "--rpc-url", evm.url, "eth_getTransactionByHash", result["txid"]),
                             check=True, capture_output=True, text=True, timeout=30)
        tx = json.loads(raw.stdout)
        replay = subprocess.run(("cast", "call", "--rpc-url", evm.url, "--from", self.reserve.admin,
                                 "--data", tx["input"], self.reserve.vault),
                                capture_output=True, text=True, timeout=30)
        selector = _hash(b"AlreadySettled(bytes32)")[:4].hex()
        if replay.returncode == 0 or ("AlreadySettled" not in replay.stderr and selector not in replay.stderr):
            raise AssertionError(f"expected the reserve's AlreadySettled refusal: {replay.stderr}")
        result["reserve_replay_rejected"] = replay.stderr.strip()
        return result


def run(node, evm, out, session, *, layout):
    lab = Lifecycle(node, evm, out, session, layout=layout)
    a, b, c = lab.alice[0], lab.bob[0], lab.carol[0]
    minted = tuple(lab.mint(name, units, owner) for name, units, owner in
                   (("mint-300", 300, a), ("mint-200", 200, a), ("mint-150", 150, b)))
    state_as_token = replace(minted[0], vout=0)
    lab.prove("mint-issuance-vout-as-token", (state_as_token, minted[1]),
              Action(TRANSFER, (State(ACTIVE, 275, owner=b), State(ACTIVE, 225, owner=a)), (a, a)),
              reject=True)
    first = lab.transfer("alice-to-bob", minted[:2], (State(ACTIVE, 275, owner=b), State(ACTIVE, 225, owner=a)),
                         (lab.alice, lab.alice))
    bob_received = lab.receive(first, 0, State(ACTIVE, 275, owner=b).output(lab.policy.digest))
    retained = first.previous(1)
    second_outputs = (State(ACTIVE, 350, owner=c), State(ACTIVE, 75, owner=b))
    second = lab.transfer("bob-to-carol", (bob_received, minted[2]), second_outputs, (lab.bob, lab.bob))
    carol_received = lab.receive(second, 0, second_outputs[0].output(lab.policy.digest))
    if second.transaction.inputs[2].outpoint() != bob_received.input.outpoint():
        raise AssertionError("independently received outpoint was not spent")

    frozen_outputs = (State(FROZEN, 350, owner=c), second_outputs[1])
    frozen = lab.manage("freeze-carol", FREEZE, (carol_received, second.previous(1)), frozen_outputs)
    lab.receive(frozen, 0, frozen_outputs[0].output(lab.policy.digest))
    try:
        lab.receive(frozen, 0, second_outputs[0].output(lab.policy.digest))
    except ValueError as failure:
        lab.wallet_errors["frozen-not-an-active-receipt"] = str(failure)
    else:
        raise AssertionError("frozen output was credited as active")
    frozen_parents = (frozen.previous(0), frozen.previous(1))
    lab.prove("ordinary-frozen-spend", frozen_parents, Action(TRANSFER, second_outputs, (c, b)), reject=True)
    lab.prove("frozen-burn", frozen_parents, Action(
        BURN, (State(), State()), (c, b),
        burn=BurnReceipt(lab.policy.asset.asset_id(), lab.policy.asset.reserve_domain, lab.reserve.recipient, 425),
    ), reject=True)
    thawed = lab.manage("unfreeze-carol", UNFREEZE, frozen_parents, second_outputs)
    thawed_receipt = lab.receive(thawed, 0, second_outputs[0].output(lab.policy.digest))
    partial_outputs = (State(ACTIVE, 50, owner=c), State(ACTIVE, 75, owner=b))
    partial, claim = lab.burn("partial-burn", (thawed_receipt, thawed.previous(1)), partial_outputs, 300,
                              (lab.carol, lab.bob))
    first_release = lab.release(partial, claim, 350)
    full, claim = lab.burn("full-burn", (partial.previous(0), partial.previous(1)), (State(), State()), 125,
                           (lab.carol, lab.bob))
    second_release = lab.release(full, claim, 225)
    accounting = lab.bridge.reconcile(225, 0)
    if (accounting["net_reserve"], accounting["bsv_circulating"], accounting["minted"], accounting["released"]) != (
            225, 225, 650, 425):
        raise AssertionError("final reserve and circulation differ")
    if lab.adopted().spend(retained.input.outpoint()) != SpendStatus.UNSPENT:
        raise AssertionError("unexpected spend of remaining circulating balance")
    sizes = [len(record.transaction.serialize()) for record in lab.results.values()]
    if len(set(sizes)) != 1:
        raise AssertionError(f"same layout did not keep fixed width: {sizes}")
    bundles = [record.record["cost"]["total"]["bytes"] for record in lab.results.values()]
    if len(set(bundles[:3])) != 1 or len(set(bundles[3:])) != 1:
        raise AssertionError(f"same action shape did not keep fixed funded width: {bundles}")
    final = header_chain(node.node)
    archive = {"headers": [value.hex() for value in final.headers],
               "actions": {name: {"payment": archive_packet(item.packet),
                                   "parents": [archive_packet(p) for p in item.parents],
                                   "tip": len(item.chain.headers) - 1} for name, item in lab.results.items()}}
    scope = {name: getattr(lab.policy.asset, name) for name in
             ("network", "decimals", "reserve_domain", "issuance_outpoint", "reserve_asset", "policy_id")}
    archive["reserve"] = {
        "chain_id": evm.rpc("eth_chainId"),
        "finalized": evm.rpc("eth_getBlockByNumber", "finalized", False),
        "deposits": {name: evm.rpc("eth_getTransactionReceipt", item.record["source_deposit"]["txid"])
                     for name, item in lab.results.items() if "source_deposit" in item.record},
        "releases": [evm.rpc("eth_getTransactionReceipt", release["txid"])
                     for release in (first_release, second_release)],
    }
    report = {
        "scope": "Fixed two-slot lifecycle profile on independent regtest and mock USDC reserve on Anvil.",
        "asset": {name: value.hex() if isinstance(value, bytes) else value for name, value in scope.items()},
        "issuer": lab.issuer[0].hex(), "manager": lab.manager[0].hex(),
        "verifier_lock_sha256": sha256(lab.policy.verifier).hexdigest(),
        "key_sha256": session.pin, "constraints": lab.parameters["constraints"],
        "layout": lab.policy.layout,
        "checkpoint_suffix_bytes": SUFFIX_BYTES, "wire_bytes": sizes[0], "history_growth_bytes": 0,
        "total_funded_bytes": sum(bundles) + len(lab.coins.serialize()),
        "shared_sponsor_setup_bytes": len(lab.coins.serialize()),
        "actions": {name: row.record for name, row in lab.results.items()},
        "releases": [first_release, second_release], "reconciliation": accounting,
        "proof_rejections": lab.proof_errors, "node_rejections": lab.node_errors, "wallet_rejections": lab.wallet_errors,
        "evm": {"chain_id": lab.reserve.scope.chain_id, "vault": lab.reserve.vault, "token": lab.reserve.usdc,
                "recipient": lab.reserve.recipient.hex()},
        **node.evidence,
    }
    return report, archive


def replay(out):
    report = json.loads((out / "summary.json").read_text())
    data = report["asset"].copy()
    for name in ("issuance_outpoint", "reserve_asset", "policy_id"):
        data[name] = bytes.fromhex(data[name])
    asset = AssetDescriptor(**data)
    artifact = json.loads((out / "mint-300-proof.json").read_text())
    layout = report.get("layout", "shared" if report.get("share_funding_fragments") else "prefix")
    policy = Policy(asset, load_verification_key(artifact),
                    bytes.fromhex(report["issuer"]), bytes.fromhex(report["manager"]), layout=layout)
    if (artifact["verifying_key_sha256"] != report["key_sha256"]
            or sha256(policy.verifier).hexdigest() != report["verifier_lock_sha256"]):
        raise ValueError("replayed lifecycle policy disagrees with the test deployment")
    with lzma.open(out / "packets.json.xz", "rt") as stream:
        archive = json.load(stream)
    headers = tuple(bytes.fromhex(header) for header in archive["headers"])
    bob = None
    for name in ACTIONS:
        item = archive["actions"][name]
        chain = RegtestHeaderChain(headers[:item["tip"]+1])
        packet = read_packet(chain, item["payment"])
        parents = tuple(read_packet(chain, value) for value in item["parents"])
        txid = bytes.fromhex(report["transactions"][name]["txid"])[::-1]
        row = report["actions"][name]
        if row["action"] == BURN:
            burn = next(x for x in report["releases"] if x["burn_txid"] == txid[::-1].hex())
            # The configured local reserve recipient is independently recorded by the BSV proof output.
            tx, _ = packet.open(chain)
            expected = BurnReceipt.parse(tx.outputs[2])
            if expected.asset_id != asset.asset_id() or expected.reserve_domain != asset.reserve_domain:
                raise ValueError("burn outside the pinned reserve policy")
            if expected.quantity != burn["quantity"] or expected.recipient.hex() != report["evm"]["recipient"]:
                raise ValueError("different recorded burn quantity or recipient")
            position, output = 2, expected.output()
        else:
            position = 1 if row["action"] == MINT else 0
            output = State.parse(bytes.fromhex(row["authorized_outputs"][position])).output(policy.digest)
        received = policy.receive(chain, packet, parents, txid, position, output)
        if name == "alice-to-bob":
            bob = received.outpoint
        if name == "bob-to-carol" and received.transaction.inputs[2].outpoint() != bob:
            raise ValueError("Bob did not spend the independently accepted receipt")
        print(name, received.transaction.txid(), received.confirmations)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--zkey", type=Path)
    parser.add_argument("--assignments", type=Path)
    parser.add_argument("--ntt-shader", type=Path)
    parser.add_argument("--node-url")
    parser.add_argument("--cookie", type=Path)
    parser.add_argument("--layout", choices=LIFECYCLE_LAYOUTS, default="literal")
    parser.add_argument("--replay", action="store_true")
    args = parser.parse_args()
    if args.replay:
        replay(args.out)
        return
    if not all((args.zkey, args.assignments, args.ntt_shader, args.node_url, args.cookie)):
        parser.error("provide .zkey, circuit assignments, Metal NTT shader and a fresh isolated BSV node")
    from prepared_lifecycle_prover import LifecycleProver

    args.out.mkdir()
    with LifecycleProver(args.zkey, args.assignments, args.ntt_shader, args.out) as session, start_anvil() as evm:
        report, archive = run(Regtest(args.node_url, args.cookie), evm, args.out, session, layout=args.layout)
    save(args.out / "summary.json", report)
    with lzma.open(args.out / "packets.json.xz", "xt") as stream:
        json.dump(archive, stream, separators=(",", ":"))


if __name__ == "__main__":
    main()
