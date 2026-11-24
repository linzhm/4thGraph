"""Mine shared- or distinct-parent capacity payments on isolated BSV regtest."""

import argparse
from dataclasses import dataclass
from decimal import Decimal
from hashlib import sha256
import json
import os
from pathlib import Path
from time import perf_counter

from capacity_records import encode_capacity_record
from capacity_tree import capacity_plan
from capacity_verifier import CapacityVerifier
from certified_wallet_provenance import CertifiedWalletProvenance
from committed_verifier import load_verifying_key
from cross_chain_fixture import AdoptedBsvChain
from mint import MintPolicy
from mint_events import EMPTY_ROOT, MintEvents
from operational_token import ordinary_witness, shared_guard_witness
from projects.cctp.evm.bsv_burn_evidence import BsvTransactionLocation
from run_continuity_regtest import NativeProver, _checkpoint, _mint, _prove
from run_recursive_mimo import Regtest
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, blob, hash256, preimage_all
from statement import AssetDescriptor
from usdc_amount import USDC_DECIMALS


MODES = {64: (17, 18), 256: (19, 20)}
ISSUED = 1024
SPONSOR_SATS = 100_000_000
INITIAL_SUBSIDY = 5_000_000_000
COINBASE_MATURITY = 100
POOL_FEE = 1_000_000


@dataclass(frozen=True)
class Origin:
    transaction: Transaction
    funding: Transaction
    artifact: Path
    vout: int


def _save_durable(path, payload):
    pending = path.with_suffix(".json.tmp")
    with pending.open("w") as stream:
        json.dump(payload, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    pending.replace(path)


def _sponsor_pool(node, count):
    """Mine fresh same-owner coinbases and sign every input of the sponsor pool."""
    target = count * SPONSOR_SATS + POOL_FEE
    hashes = []
    parents = []
    funded = 0
    subsidy = INITIAL_SUBSIDY
    while funded < target:
        if subsidy <= 0:
            raise ValueError("regtest subsidy exhausted before the capacity sponsor pool was funded")
        required = (target - funded + subsidy - 1) // subsidy
        extra = min(required, 64) + (COINBASE_MATURITY if not hashes else 0)
        hashes.extend(node.node.call("generatetoaddress", extra, node.address))
        while funded < target and len(parents) + COINBASE_MATURITY < len(hashes):
            block_hash = hashes[len(parents)]
            coinbase_id = node.node.call("getblock", block_hash, 1)["tx"][0]
            raw = node.node.call("getrawtransaction", coinbase_id)
            coinbase = Transaction.parse(bytes.fromhex(raw))
            if coinbase.txid() != coinbase_id:
                raise ValueError("sponsor coinbase does not match the mined block")
            parents.append(coinbase)
            subsidy = coinbase.outputs[0].value
            funded += subsidy

    change = funded - target
    outputs = (Output(SPONSOR_SATS, asm("OP_1")),) * count
    if change:
        outputs += (Output(change, parents[0].outputs[0].script),)
    unsigned = Transaction(tuple(Input(parent.txid_wire(), 0) for parent in parents), outputs)
    signed = unsigned
    for index, parent in enumerate(parents):
        coin = parent.outputs[0]
        preimage = preimage_all(unsigned, index, coin.value, coin.script)
        witness = push(node.owner(hash256(preimage)) + b"\x41") + push(node.owner_key)
        signed = signed.with_script(index, witness)
    return node.include("setup", signed, tuple(parents))


def _fund(node, setup, index, label, lock):
    # The isolated miner's fee floor also applies to the multi-MB lock carried
    # by the funding output before any proof has been produced.
    funded_value = setup.outputs[index].value - max(1_000_000, len(lock) + 100)
    if funded_value <= 0:
        raise ValueError("sponsor output cannot cover the verifier funding fee")
    tx = Transaction((Input(setup.txid_wire(), index),), (Output(funded_value, lock),))
    return node.include(label, tx, (setup,))


def _prepare(node, key_artifact, capacity, topology):
    setup = _sponsor_pool(node, 6 + 2 * capacity) if topology == "distinct" else node.setup(outputs=6)
    anchor = Input(setup.txid_wire(), 0)
    asset = AssetDescriptor(1, anchor.outpoint(), USDC_DECIMALS, 7, b"r" * 32, b"p" * 32)
    template = MintPolicy(asset, 84532, b"r" * 20, node.minter_key, lambda _: b"")
    key, commitment = load_verifying_key(key_artifact)
    verifier = CapacityVerifier(
        template, node.freeze_key, key, commitment, bytes.fromhex(key_artifact["continuity_key_digest"]),
        certified_mints=True, certified_admin=True, shared_ordinary_guard=True, capacity=capacity,
        compressed_ancestry=topology == "distinct",
    )
    guard = verifier.policy.shared_guard_lock()
    funders = {}
    for index, (label, lock) in enumerate((
        ("mint-verifier", verifier.lock),
        ("fanout-verifier", verifier.lock),
        ("fanout-companion", guard),
        ("payment-verifier", verifier.lock),
        ("payment-companion", guard),
    ), start=1):
        funders[label] = _fund(node, setup, index, label, lock)

    policy = verifier.mint_policy
    genesis = node.include("mint-genesis", Transaction(
        (anchor,), (Output(setup.outputs[0].value - 50_000, policy.state_lock(EMPTY_ROOT)),),
    ), (setup,))
    policy.check_genesis(genesis)
    return verifier, genesis, funders, setup


def _measure_transaction(tx, spent):
    input_sats = sum(parent.outputs[vout].value for parent, vout in spent)
    output_sats = sum(output.value for output in tx.outputs)
    return {
        "transaction_bytes": len(tx.serialize()),
        "input_witness_bytes": [len(item.script) for item in tx.inputs],
        "input_sats": input_sats,
        "output_sats": output_sats,
        "fee_sats": input_sats - output_sats,
    }


def _aggregate(verifier, prover, label, plan, origins, checkpoint):
    steps = iter(enumerate(plan.steps, 1))

    def prove_child(context, child_artifacts):
        number, step = next(steps)
        if context != step.context:
            raise AssertionError("capacity proof order differs from its deterministic plan")
        step_label = f"{label}-aggregate-{number:03d}"
        started = perf_counter()
        artifact, public, _ = _prove(verifier, prover, step_label, step.receipt, context, child_artifacts)
        checkpoint(step_label, {
            "artifact": artifact.name,
            "proof_sha256": sha256(artifact.read_bytes()).hexdigest(),
            "context": context.hex(),
            "proof_digest": step.digest.hex(),
            "previous_proof_digests": [parent.hex() for parent in step.receipt.parents],
            "previous_artifacts": [parent.name for parent in child_artifacts],
            "public_signals": [str(value) for value in public],
            "prove_seconds": perf_counter() - started,
        })
        print(f"{step_label} proved ({number}/{len(plan.steps)})", flush=True)
        return artifact

    return plan.prove((origin.artifact for origin in origins), prove_child)


def _transfer(node, verifier, prover, label, mode, origins, quantities, funding, companion, *,
              dictionary_parent=b"", aggregate_checkpoint=None):
    started = perf_counter()
    identities = {id(origin.transaction): origin.transaction for origin in origins}
    txids = {identity: parent.txid_wire() for identity, parent in identities.items()}
    ordered = sorted(
        origins,
        key=lambda origin: (int.from_bytes(txids[id(origin.transaction)], "little"), origin.vout),
    )
    inputs = tuple(Input(txids[id(origin.transaction)], origin.vout) for origin in ordered)
    groups = tuple({txin.txid: origin for txin, origin in zip(inputs, ordered, strict=True)}.values())
    pairs = tuple((origin.funding, origin.transaction) for origin in groups)
    outputs = tuple(verifier.mint_policy.token_output(quantity, node.owner_key) for quantity in quantities)
    plan = capacity_plan(verifier.asset.asset_id(), verifier.key_digest, verifier.capacity,
                         (verifier.proof_digest(parent, support) for support, parent in pairs))
    candidate = verifier.prepare_capacity(mode, inputs, outputs, funding, companion, plan.receipt)
    receipt, context = verifier.validate_capacity(candidate, funding, companion, pairs)
    prepared = perf_counter()
    if plan.steps and aggregate_checkpoint is None:
        raise ValueError("wide ancestry requires an aggregate proof checkpoint")
    ancestors = _aggregate(verifier, prover, label, plan, groups, aggregate_checkpoint)
    aggregated = perf_counter()
    artifact, public, proof = _prove(verifier, prover, label, receipt, context, ancestors)
    proved = perf_counter()
    policy = verifier.policy
    signed = candidate.with_script(0, verifier.capacity_witness(
        proof, candidate, funding, companion, pairs, dictionary_parent=dictionary_parent,
    ))
    signed = signed.with_script(1, shared_guard_witness(candidate, policy, funding, companion))
    for index, origin in enumerate(ordered, start=2):
        witness = ordinary_witness(
            candidate, index, origin.transaction, policy, funding, node.owner, shared_guard_parent=companion,
        )
        signed = signed.with_script(index, witness)
    witnessed = perf_counter()
    node.include(label, signed, (funding, companion, *(origin.transaction for origin in groups)))
    confirmed = perf_counter()

    predecessors = tuple((origin.transaction, origin.vout) for origin in ordered)
    _, _, details = _checkpoint(node, prover, label, signed, funding, artifact, public, receipt,
                                quantities, predecessors, {})
    result = {
        **details,
        **_measure_transaction(signed, ((funding, 0), (companion, 0), *predecessors)),
        "artifact": artifact.name,
        "root_predecessor_artifacts": [parent.name for parent in ancestors],
        "capacity_mode": mode,
        "distinct_token_parent_transactions": len(groups),
        "aggregate_proof_count": len(plan.steps),
        "companion_txid": companion.txid(),
        "dictionary_parent_bytes": len(dictionary_parent),
        "prepare_seconds": prepared - started,
        "aggregate_prove_seconds": aggregated - prepared,
        "prove_seconds": proved - aggregated,
        "witness_seconds": witnessed - proved,
        "chain_gang_and_bsv_confirmation_seconds": confirmed - witnessed,
    }
    print(f"{label} confirmed ({result['transaction_bytes']} bytes)", flush=True)
    return signed, artifact, result


def _checked_outputs(node, verifier, tx, quantities):
    txid = tx.txid()
    results = []
    for vout in (0, len(quantities) - 1):
        output = tx.outputs[vout]
        found = node.node.call("gettxout", txid, vout, False)
        if (not found or found["scriptPubKey"]["hex"] != output.script.hex()
                or Decimal(str(found["value"])) * 100_000_000 != output.value):
            raise AssertionError("confirmed capacity output differs from the independent UTXO set")
        token = verifier.policy.parse(output.script)
        if (token is None or token.asset_id != verifier.asset.asset_id() or token.owner != node.owner_key
                or token.frozen or token.quantity != quantities[vout]):
            raise AssertionError("confirmed capacity output has incorrect token metadata")
        results.append({"txid": txid, "vout": vout, "quantity": token.quantity, "sats": output.value})
    return results


def _wallet_acceptance(node, verifier, tx, quantities):
    node.node.call("generatetoaddress", 1, node.address)
    locations = {
        bytes.fromhex(record["txid"])[::-1]: BsvTransactionLocation(
            bytes.fromhex(record["blockhash"])[::-1], record["height"],
        ) for record in node.evidence["transactions"].values()
    }
    chain = AdoptedBsvChain(node.node, {txid: location.block_hash[::-1].hex() for txid, location in locations.items()})
    provenance = CertifiedWalletProvenance(verifier, chain.call, chain.confirmation_policy(verifier.asset), locations.get)
    measurements = []
    for index in (0, len(quantities) - 1):
        started = perf_counter()
        receipt, fields = chain.payment(tx, index, verifier.asset, verifier.policy, provenance, node.owner_key)
        if receipt.quantity != quantities[index] or receipt.spend_status.value != "unspent":
            raise AssertionError("wallet disagrees with the capacity payment output")
        measurements.append(fields | {"elapsed_seconds": perf_counter() - started})
    if provenance.valid_creation(tx, len(quantities)):
        raise AssertionError("wallet accepted the capacity receipt as a token")
    return measurements


def _distinct_payment(node, verifier, prover, setup, funders, fanout, fanout_funding, fanout_artifact,
                      payment_label, payment_mode, payment_quantities, unit, progress, persist):
    origins = []
    guard = verifier.policy.shared_guard_lock()
    for position in range(verifier.capacity):
        label = f"capacity-{verifier.capacity}-parent-{position:03d}"
        index = 6 + 2 * position
        funding = _fund(node, setup, index, f"{label}-verifier", verifier.lock)
        companion = _fund(node, setup, index + 1, f"{label}-companion", guard)
        persist("distinct-parent-funded")
        branch, artifact, details = _transfer(
            node, verifier, prover, label, 16, (Origin(fanout, fanout_funding, fanout_artifact, position),),
            (unit,), funding, companion,
        )
        origins.append(Origin(branch, funding, artifact, 0))
        progress["proof_checks"][label] = details
        progress["distinct_parent_labels"].append(label)
        persist("distinct-parent-confirmed")

    # A compressed branch carries this exact record, including its segment
    # tags. The unencoded fanout is reconstructed by the branch's Script.
    dictionary = encode_capacity_record(fanout.serialize(), (blob(verifier.lock), b""))

    def record_aggregate(label, details):
        progress["aggregate_proofs"][label] = details
        persist("aggregate-proof-complete")

    return _transfer(
        node, verifier, prover, payment_label, payment_mode, origins, payment_quantities,
        funders["payment-verifier"], funders["payment-companion"], dictionary_parent=dictionary,
        aggregate_checkpoint=record_aggregate,
    )


def run(node, prover, key_artifact, capacity, topology="shared"):
    if capacity not in MODES or topology not in ("shared", "distinct"):
        raise ValueError("use capacity 64 or 256 and shared or distinct topology")
    fanout_mode, payment_mode = MODES[capacity]
    started = perf_counter()
    progress = {"capacity": capacity, "topology": topology, "proof_checks": {},
                "distinct_parent_labels": [], "aggregate_proofs": {}}

    def persist(stage):
        _save_durable(prover.out / "progress.json", {
            "stage": stage,
            "confirmed_1to1_parents": len(progress["distinct_parent_labels"]),
            "completed_aggregate_proofs": len(progress["aggregate_proofs"]),
            **progress, **node.evidence,
        })

    persist("starting")
    verifier, genesis, funders, setup = _prepare(node, key_artifact, capacity, topology)
    funded = perf_counter()
    progress.update(asset_id=verifier.asset.asset_id().hex(), continuity_key_digest=verifier.key_digest.hex(),
                    sponsor_coinbase_inputs=len(setup.inputs), setup_and_funding_seconds=funded - started)
    persist("funded")
    mint_funding = funders["mint-verifier"]
    mint_label = "certified-mint-test-attestation"
    minted, mint_artifact, mint_check, _ = _mint(
        node, verifier, prover, mint_label, genesis, MintEvents(), mint_funding, ISSUED,
    )
    mint_check.update(
        _measure_transaction(minted, ((genesis, 0), (mint_funding, 0))),
        artifact=mint_artifact.name,
        prepare_prove_and_confirm_seconds=perf_counter() - funded,
    )
    print(f"{mint_label} confirmed ({mint_check['transaction_bytes']} bytes)", flush=True)
    progress["proof_checks"][mint_label] = mint_check
    persist("mint-confirmed")

    unit = ISSUED // capacity
    fanout_quantities = (unit,) * capacity
    fanout_label = f"capacity-{capacity}-fanout"
    fanout_funding = funders["fanout-verifier"]
    fanout, fanout_artifact, fanout_check = _transfer(
        node, verifier, prover, fanout_label, fanout_mode, (Origin(minted, mint_funding, mint_artifact, 1),),
        fanout_quantities, fanout_funding, funders["fanout-companion"],
    )
    fanout_check["confirmed_first_and_last_outputs"] = _checked_outputs(node, verifier, fanout, fanout_quantities)
    progress["proof_checks"][fanout_label] = fanout_check
    persist("fanout-confirmed")

    payment_quantities = (unit - 1, unit + 1) * (capacity // 2)
    payment_label = f"capacity-{capacity}-payment"
    if topology == "distinct":
        payment, _, payment_check = _distinct_payment(
            node, verifier, prover, setup, funders, fanout, fanout_funding, fanout_artifact,
            payment_label, payment_mode, payment_quantities, unit, progress, persist,
        )
    else:
        origins = tuple(Origin(fanout, fanout_funding, fanout_artifact, vout) for vout in range(capacity))
        payment, _, payment_check = _transfer(
            node, verifier, prover, payment_label, payment_mode, origins, payment_quantities,
            funders["payment-verifier"], funders["payment-companion"],
        )
    progress["proof_checks"][payment_label] = payment_check
    persist("payment-confirmed")
    payment_check["confirmed_first_and_last_outputs"] = _checked_outputs(node, verifier, payment, payment_quantities)
    for txin in (payment.inputs[2], payment.inputs[-1]):
        if node.node.call("gettxout", txin.txid[::-1].hex(), txin.vout, False) is not None:
            raise AssertionError("confirmed payment did not consume the selected parent output")
    payment_check["wallet"] = _wallet_acceptance(node, verifier, payment, payment_quantities)

    preparation = [record for label, record in node.evidence["transactions"].items() if label != payment_label]
    progress.update(
        scope=f"{topology.capitalize()}-parent capacity payment on isolated BSV regtest, starting from a signed test deposit attestation.",
        transaction_proof_count=len(progress["proof_checks"]),
        distinct_parent_proof_count=len(progress["distinct_parent_labels"]),
        synthetic_aggregate_proof_count=len(progress["aggregate_proofs"]),
        preparation_transaction_count=len(preparation),
        preparation_transaction_bytes=sum(record["bytes"] for record in preparation),
        wall_seconds=perf_counter() - started,
    )
    persist("complete")
    return {
        **progress,
        "confirmation_timings": node.confirmation_timings,
        **node.evidence,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-url", default=os.environ.get("REGTEST_URL"))
    parser.add_argument("--cookie", type=Path, default=os.environ.get("REGTEST_COOKIE"))
    parser.add_argument("--prover", type=Path, required=True)
    parser.add_argument("--setup-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--capacity", type=int, choices=MODES, required=True)
    parser.add_argument("--topology", choices=("shared", "distinct"), default="shared")
    args = parser.parse_args()
    if not (args.node_url and args.cookie):
        parser.error("independent BSV regtest RPC and cookie are required")
    key_artifact = json.loads((args.setup_dir / "key.json").read_text())
    args.out.mkdir()
    node = Regtest(args.node_url, args.cookie)
    if node.node.call("getblockchaininfo")["chain"] != "regtest":
        raise ValueError("the capacity fixture requires an isolated regtest node")
    with NativeProver(args.prover, args.setup_dir, args.out, key_artifact["continuity_key_digest"]) as prover:
        _save_durable(args.out / "summary.json", run(node, prover, key_artifact, args.capacity, args.topology))


if __name__ == "__main__":
    main()
