"""Issue test tokens in a separate process, then pay and independently receive on BSV regtest."""
import argparse
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from time import perf_counter

from certified_wallet_provenance import CertifiedWalletError, CertifiedWalletProvenance
from committed_verifier import load_verifying_key
from continuity_statement import ParentReceipt
from continuity_verifier import ContinuityVerifier
from cross_chain_fixture import AdoptedBsvChain
from mint import MintPolicy
from mint_events import EMPTY_ROOT, MintEvents
from operational_token import ordinary_witness
from parent_prefix import align_output_count, output_offsets
from evm.bsv_burn_evidence import BsvTransactionLocation
from run_capacity_regtest import _fund, _measure_transaction, _save_durable
from run_continuity_regtest import NativeProver, _mint, _prove
from run_recursive_mimo import Regtest
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, blob, hash256, preimage_all
from statement import AssetDescriptor
from test_operational_token import fixture_signer
from usdc_amount import USDC_DECIMALS


def verifier_for(node, setup, artifact, *, aligned=False):
    asset = AssetDescriptor(1, Input(setup.txid_wire(), 0).outpoint(), USDC_DECIMALS, 7, b"r" * 32, b"p" * 32)
    template = MintPolicy(asset, 84532, b"r" * 20, node.minter_key, lambda _: b"", state_version=2)
    key, commitment = load_verifying_key(artifact)
    return ContinuityVerifier(template, node.freeze_key, key, commitment,
                              bytes.fromhex(artifact["continuity_key_digest"]), certified_mints=True,
                              certified_admin=True, align_output_count=aligned)


def read_tx(node, txid):
    tx = Transaction.parse(bytes.fromhex(node.node.call("getrawtransaction", txid)))
    if tx.txid() != txid:
        raise ValueError("wrong transaction returned by the regtest node")
    return tx


def bootstrap(node, prover, key_artifact, *, aligned=False):
    setup = node.setup(outputs=5, anchor_tag=b"BSV/CCTP/regtest/aligned-payments/v1" if aligned else b"")
    verifier = verifier_for(node, setup, key_artifact, aligned=aligned)
    policy = verifier.mint_policy
    state = node.include("mint-genesis", Transaction((Input(setup.txid_wire(), 0),), (
        Output(setup.outputs[0].value - 50_000, policy.state_lock(EMPTY_ROOT)),
    )), (setup,))
    policy.check_genesis(state)
    alice, bob = (fixture_signer(n)[0] for n in (21, 22))
    events = MintEvents()
    predecessor = None
    checks = {}
    for index, (label, recipient, quantity) in enumerate((
        ("alice-first-mint", alice, 300), ("alice-second-mint", alice, 200), ("bob-existing-mint", bob, 150),
    ), 1):
        funding = _fund(node, setup, index, label + "-verifier", verifier.lock)
        state, artifact, checks[label], events = _mint(
            node, verifier, prover, label, state, events, funding, quantity,
            predecessor=predecessor, recipient=recipient,
        )
        predecessor = funding, artifact
        print(f"{label} confirmed ({len(state.serialize())} bytes)", flush=True)

    total = policy.parse_state_lock(state.outputs[0].script).cumulative_minted
    if total != 650:
        raise AssertionError("unexpected anchored cumulative issuance")
    balance = (setup.outputs[4].value - 50_000) // 2
    sponsor = node.include("wallet-satoshis", Transaction((Input(setup.txid_wire(), 4),), tuple(
        Output(balance, push(key) + asm("OP_CHECKSIG")) for key in (alice, bob)
    )), (setup,))
    return {
        "scope": "Three BSV test mints backed by test deposit attestations. Minting process exits before ordinary payments.",
        "mint_public_key": node.minter_key.hex(), "freeze_public_key": node.freeze_key.hex(),
        "asset_id": verifier.asset.asset_id().hex(), "issuance_anchor": verifier.asset.issuance_outpoint.hex(),
        "continuity_key_digest": verifier.key_digest.hex(), "align_output_count": aligned,
        "verifier_lock_hash": sha256(blob(verifier.lock)).hexdigest(), "minted": total,
        "satoshi_funding_txid": sponsor.txid(), "proof_checks": checks,
        "confirmation_timings": node.confirmation_timings, **node.evidence,
    }


def wallet_at_tip(node, verifier):
    hints = {bytes.fromhex(r["txid"])[::-1]: BsvTransactionLocation(bytes.fromhex(r["blockhash"])[::-1], r["height"])
             for r in node.evidence["transactions"].values()}
    chain = AdoptedBsvChain(node.node, {txid: loc.block_hash[::-1].hex() for txid, loc in hints.items()})
    return CertifiedWalletProvenance(verifier, chain.call, chain.confirmation_policy(verifier.asset), hints.get)


def receive(wallet, tx, vout, owner, quantity):
    result = wallet.check_spendable(tx, vout, expected_owner=owner, expected_quantity=quantity)
    return {
        "txid": tx.txid(), "vout": vout, "owner": result.receipt.owner.hex(), "quantity": result.receipt.quantity,
        "frozen": result.receipt.frozen, "spend_status": result.receipt.spend_status.value,
        "confirmations": result.receipt.confirmations, "tip": result.tip_hash[::-1].hex(), "tip_height": result.tip_height,
        "block_header": result.inclusion.header.hex(), "height": result.inclusion.height,
        "leaf_count": result.inclusion.leaf_count, "index": result.inclusion.index,
        "merkle_siblings_wire": [s.hex() for s in result.inclusion.siblings],
        "verifier_outpoint_wire": result.creation.verifier_outpoint.hex(),
        "proof_digest": result.creation.proof_digest.hex(),
    }


def rejected_payment(wallet, tx, vout, owner, quantity):
    try:
        wallet.check_spendable(tx, vout, expected_owner=owner, expected_quantity=quantity)
    except CertifiedWalletError as error:
        return str(error)
    raise AssertionError("wallet accepted the negative case")


def wallet_funding(node, label, balance, vout, payer, sign, lock):
    coin = balance.outputs[vout]
    if coin.script != push(payer) + asm("OP_CHECKSIG"):
        raise ValueError("verifier setup needs the payer's ordinary native BSV balance")
    unsigned = Transaction((Input(balance.txid_wire(), vout),), (Output(coin.value - 2_000_000, lock),))
    signature = sign(hash256(preimage_all(unsigned, 0, coin.value, coin.script)))
    funding = unsigned.with_script(0, push(signature + b"\x41"))
    return node.include(label + "-verifier", funding, (balance,))


def pay(node, verifier, prover, key, label, funding, payer, sign, coins, payouts):
    from continuity_chain_proof import chain_prior_artifact
    wallet = wallet_at_tip(node, verifier)
    parents, supports, proof_paths, accepted = [], [], [], []
    for i, (txid, vout, quantity) in enumerate(coins):
        parent = read_tx(node, txid)
        accepted.append(receive(wallet, parent, vout, payer, quantity))
        sponsor_point = parent.inputs[verifier.verifier_input_index(parent)]
        support = read_tx(node, sponsor_point.txid[::-1].hex())
        recovered = chain_prior_artifact(verifier, key, parent, support)
        prior = prover.out / f"{label}-vin{i + 1}-from-chain.json"
        _save_durable(prior, recovered)
        proof_paths.append(prior)
        parents.append(parent)
        supports.append(support)
    if len({t.txid() for t in parents}) != 2:
        raise AssertionError("expected two distinct real token parents")
    parents, supports = tuple(parents), tuple(supports)
    receipt = ParentReceipt(tuple(verifier.proof_digest(parent, support)
                                 for parent, support in zip(parents, supports, strict=True)))
    tx = Transaction(
        (Input(funding.txid_wire(), 0), *(Input(parent.txid_wire(), vout)
          for parent, (_, vout, _) in zip(parents, coins, strict=True))),
        (*(verifier.mint_policy.token_output(quantity, who) for who, quantity in payouts), receipt.output()),
    )
    receipt, context = verifier.validate(tx, funding, parents, supports)
    started = perf_counter()
    artifact, public, proof = _prove(verifier, prover, label, receipt, context, tuple(proof_paths))
    proof_seconds = perf_counter() - started

    def signed(candidate):
        final = candidate.with_script(0, verifier.witness(proof, candidate, funding, parents, supports))
        for vin, parent in enumerate(parents, 1):
            final = final.with_script(vin, ordinary_witness(candidate, vin, parent, verifier.policy, funding, sign))
        return final

    negative = {}
    if label == "alice-to-bob":
        # Same quantities and newly signed transaction, but a different recipient.
        altered = replace(tx, outputs=(verifier.mint_policy.token_output(payouts[0][1], payer), *tx.outputs[1:]))
        changed = signed(altered)
        if verifier.align_output_count:
            changed = align_output_count(changed, 0)
        negative["new_holder_signatures_with_original_proof_on_changed_recipient"] = node.reject(changed)
    final = signed(tx)
    if verifier.align_output_count:
        if label == "alice-to-bob":
            oversized = final.with_script(0, final.inputs[0].script + push(bytes(256)))
            negative["oversized_zero_padding_256_bytes"] = node.reject(oversized)
        final = align_output_count(final, 0)
    final = node.include(label, final, (funding, *parents))
    input_positions = tuple((parent, vout) for parent, (_, vout, _) in zip(parents, coins, strict=True))
    measurement = _measure_transaction(final, ((funding, 0), *input_positions))
    material = verifier.transaction_material(tx, funding, parents, supports, count=verifier.transfer_mode(tx))
    padding = verifier.confirmed_witness_padding(final, 0, material)
    count_offset, _ = output_offsets(final.serialize())
    if verifier.align_output_count:
        if not padding or count_offset % 64:
            raise AssertionError("confirmed payment lacks its aligned output count")
        base = final.with_script(0, final.inputs[0].script[:-len(padding)])
        if align_output_count(base, 0) != final:
            raise AssertionError("confirmed payment differs from the shortest wallet padding")
    return final, {
        "txid": final.txid(), "payer": payer.hex(), "parent_receipts": accepted,
        "funding_txid": funding.txid(), "funding_bytes": len(funding.serialize()),
        "payment_and_verifier_funding_bytes": len(funding.serialize()) + len(final.serialize()),
        "proof_sha256": sha256(artifact.read_bytes()).hexdigest(), "proof_file": artifact.name,
        "prior_proofs_from_node": [p.name for p in proof_paths], "prove_seconds": proof_seconds,
        "proof_witness_bytes": len(final.inputs[0].script) - len(material) - len(padding),
        "verifier_material_bytes": len(material), "alignment_push_bytes": len(padding),
        "alignment_push_hex": padding.hex(), "output_count_offset": count_offset,
        "public_signals": list(map(str, public)), "parent_proof_digests": [p.hex() for p in receipt.parents],
        "direct_token_parent_bytes": [len(p.serialize()) for p in parents],
        "funding_of_direct_parents_bytes": [len(p.serialize()) for p in supports],
        "negative": negative, **measurement,
    }


def payments(node, prover, key, manifest, expected_asset, expected_verifier_hash, *, aligned=False):
    if node.minter is not None:
        raise AssertionError("ordinary payment process has a mint signer")
    node.evidence["transactions"].update(manifest["transactions"])
    records = node.evidence["transactions"]
    setup = read_tx(node, records["setup"]["txid"])
    verifier = verifier_for(node, setup, key, aligned=aligned)
    lock_hash = sha256(blob(verifier.lock)).digest()
    if verifier.asset.asset_id() != expected_asset or lock_hash != expected_verifier_hash:
        raise ValueError("deployment differs from the recipient's independently pinned asset or verifier")
    if (verifier.asset.asset_id().hex() != manifest["asset_id"]
            or verifier.asset.issuance_outpoint.hex() != manifest["issuance_anchor"]
            or verifier.key_digest.hex() != manifest["continuity_key_digest"]
            or lock_hash.hex() != manifest["verifier_lock_hash"]):
        raise ValueError("payment policy differs from the configured deployment")
    alice, sign_alice = fixture_signer(21)
    bob, sign_bob = fixture_signer(22)
    carol, _ = fixture_signer(23)
    balances = read_tx(node, manifest["satoshi_funding_txid"])
    alice_funding = wallet_funding(node, "alice-to-bob", balances, 0, alice, sign_alice, verifier.lock)
    first, alice_check = pay(node, verifier, prover, key, "alice-to-bob", alice_funding, alice, sign_alice,
                             ((records["alice-first-mint"]["txid"], 1, 300),
                              (records["alice-second-mint"]["txid"], 1, 200)),
                             ((bob, 275), (alice, 225)))
    _save_durable(prover.out / "alice-payment.json", {"payment": alice_check, **node.evidence})
    # The second payer creates a fresh verifier only after the first payment was mined.
    bob_funding = wallet_funding(node, "bob-to-carol", balances, 1, bob, sign_bob, verifier.lock)
    second, bob_check = pay(node, verifier, prover, key, "bob-to-carol", bob_funding, bob, sign_bob,
                            ((first.txid(), 0, 275), (records["bob-existing-mint"]["txid"], 1, 150)),
                            ((carol, 350), (bob, 75)))
    _save_durable(prover.out / "bob-payment.json", {"payment": bob_check, **node.evidence})
    node.node.call("generatetoaddress", 1, node.address)
    wallet = wallet_at_tip(node, verifier)
    carol_check = receive(wallet, second, 0, carol, 350)
    negatives = {
        "wrong_order_amount": rejected_payment(wallet, second, 0, carol, 351),
        "change_belongs_to_bob": rejected_payment(wallet, second, 1, carol, 75),
        "continuity_receipt_vout": rejected_payment(wallet, second, 2, carol, 350),
        "bob_output_already_spent": rejected_payment(wallet, first, 0, bob, 275),
    }
    if wallet.check_creation(first, 0).state.owner != bob:
        raise AssertionError("confirmed Bob payment lost creation validity after spend")
    return {
        "scope": "Confirmed same-key v3 B2G with test deposits. Ordinary payments recover recursive proofs "
                 "from real chain witnesses and require only the paying wallet's signatures.",
        "asset_id": manifest["asset_id"], "issuance_anchor": manifest["issuance_anchor"],
        "freeze_public_key": node.freeze_key.hex(), "mint_public_key": node.minter_key.hex(),
        "continuity_key_digest": verifier.key_digest.hex(), "verifier_lock_hash": manifest["verifier_lock_hash"],
        "recipient_expected_asset": expected_asset.hex(), "recipient_expected_verifier_hash": expected_verifier_hash.hex(),
        "minted": manifest["minted"], "mint_signer_loaded_in_payment_process": False,
        "ordinary_companion_inputs": 0, "mint_proof_checks": manifest["proof_checks"],
        "align_output_count": aligned,
        "payments": [alice_check, bob_check], "carol_receipt": carol_check, "wallet_negatives": negatives,
        "payment_byte_delta": bob_check["transaction_bytes"] - alice_check["transaction_bytes"],
        "funded_byte_delta": bob_check["payment_and_verifier_funding_bytes"]
                             - alice_check["payment_and_verifier_funding_bytes"],
        "confirmation_timings": manifest["confirmation_timings"] | node.confirmation_timings, **node.evidence,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("mint", "payments"), required=True)
    parser.add_argument("--node-url", required=True)
    parser.add_argument("--cookie", type=Path, required=True)
    parser.add_argument("--prover", type=Path, required=True)
    parser.add_argument("--setup-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--align-output-count", action="store_true",
                        help="use a fresh policy with zero-padding support and align each ordinary payment")
    parser.add_argument("--expected-asset", help="32-byte asset ID configured independently by the recipient")
    parser.add_argument("--expected-verifier-hash", help="recipient's SHA256 of the compact-length-prefixed verifier lock")
    args = parser.parse_args()
    key = json.loads((args.setup_dir / "key.json").read_text())
    manifest_path = args.out / "mint.json"
    if args.phase == "mint":
        args.out.mkdir()
        manifest = None
        node = Regtest(args.node_url, args.cookie)
    else:
        if not args.expected_asset or not args.expected_verifier_hash:
            parser.error("payments require --expected-asset and --expected-verifier-hash independently of the mint manifest")
        try:
            expected_asset = bytes.fromhex(args.expected_asset)
            expected_verifier_hash = bytes.fromhex(args.expected_verifier_hash)
            if len(expected_asset) != 32 or len(expected_verifier_hash) != 32:
                raise ValueError
        except ValueError:
            parser.error("both recipient pins must be 32-byte hex")
        manifest = json.loads(manifest_path.read_text())
        authorities = bytes.fromhex(manifest["mint_public_key"]), bytes.fromhex(manifest["freeze_public_key"])
        node = Regtest(args.node_url, args.cookie, public_authorities=authorities)
    if node.node.call("getblockchaininfo")["chain"] != "regtest" or node.node.call("getconnectioncount"):
        raise ValueError("this test requires an isolated BSV regtest")
    with NativeProver(args.prover, args.setup_dir, args.out, key["continuity_key_digest"]) as prover:
        if manifest is None:
            _save_durable(manifest_path, bootstrap(node, prover, key, aligned=args.align_output_count))
        else:
            _save_durable(args.out / "summary.json",
                          payments(node, prover, key, manifest, expected_asset, expected_verifier_hash,
                                   aligned=args.align_output_count))


if __name__ == "__main__":
    main()
