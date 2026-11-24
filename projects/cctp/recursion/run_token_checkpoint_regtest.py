"""Compare two owner spends of a native unfreeze parent on isolated BSV regtest."""
import argparse
from dataclasses import replace
import json
from pathlib import Path

from mint import MintPolicy, authorize_mint, prepare_mint
from mint_events import Deposit, DepositPosition, EMPTY_ROOT, MintEvents
from operational_token import TokenPolicy, freeze_witness, ordinary_witness
from parent_prefix import checkpoint_record
from run_freeze_probe_regtest import prove_statement, read_key
from run_recursive_mimo import Regtest
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction
from statement import AssetDescriptor
from test_operational_token import fixture_signer
from token_checkpoint_verifier import (NATIVE_WITNESS_BYTES, PARENT_BYTES, TOKEN_LOCK_BYTES,
                                       raw_verifier_lock, raw_verifier_material, statement_bytes,
                                       verifier_lock, verifier_material)
from usdc_amount import USDC_DECIMALS


def native_parent(node, lock):
    """Mint from an anchored test deposit and spend the token through freeze and unfreeze."""
    _, issuer = fixture_signer(13)
    _, admin = fixture_signer(12)
    setup = node.setup(outputs=5)
    anchor, mint_fee, freeze_fee, unfreeze_fee, verifier_fee = (
        Input(setup.txid_wire(), index) for index in range(5)
    )
    policy = TokenPolicy((lock,), node.freeze_key)
    asset = AssetDescriptor(1, anchor.outpoint(), USDC_DECIMALS, 7, b"r" * 32, b"p" * 32)
    mint_policy = MintPolicy(asset, 84532, b"r" * 20, node.minter_key, policy.lock)
    genesis = node.include("mint-genesis", Transaction((anchor,), (
        Output(100_000, mint_policy.state_lock(EMPTY_ROOT)),
    )), (setup,))
    deposit = Deposit(
        DepositPosition(84532, asset.reserve_domain, mint_policy.reserve_contract, b"d" * 32, 0),
        asset.reserve_asset, asset.network, asset.asset_id(), 640, 0, node.owner_key,
    )
    plan = prepare_mint(mint_policy, genesis, MintEvents(), deposit, mint_fee)
    minted = node.include("mint", authorize_mint(plan, lambda _: deposit, issuer), (genesis, setup))
    active = minted.outputs[1]
    state = policy.parse(active.script)
    frozen_output = Output(active.value, policy.lock(replace(state, frozen=True)))

    def toggle(previous, vout, sponsor, output, locktime=0):
        draft = Transaction((Input(previous.txid_wire(), vout), sponsor), (output,), locktime=locktime)
        return draft.with_script(0, freeze_witness(draft, 0, previous, policy, admin))

    frozen = node.include("freeze", toggle(minted, 1, freeze_fee, frozen_output), (minted, setup))
    # DER length is variable. Set locktime before signing to find the fixed test profile's encoding.
    for locktime in range(32):
        unfrozen = toggle(frozen, 0, unfreeze_fee, active, locktime)
        if len(unfrozen.inputs[0].script) == NATIVE_WITNESS_BYTES:
            break
    else:
        raise AssertionError("could not produce the canonical fixture witness length")
    if len(unfrozen.serialize()) != PARENT_BYTES or len(active.script) != TOKEN_LOCK_BYTES:
        raise AssertionError("native unfreeze transaction does not match the checkpoint profile")
    node.include("unfreeze-parent", unfrozen, (frozen, setup))
    funding = node.include("verifier-funding", Transaction((verifier_fee,), (Output(1_000_000, lock),)), (setup,))
    return unfrozen, funding, policy, state


def run(node, out, *, prover=None, parameters=None):
    if node.node.call("getconnectioncount") != 0:
        raise ValueError("use an isolated BSV regtest")
    _, holder = fixture_signer(11)
    if parameters is None:
        lock = raw_verifier_lock()
        manifest = key = None
    else:
        manifest = json.loads((parameters / "manifest.json").read_text())
        if (manifest["test_only"] is not True or manifest["profile"] != "parent-checkpoint-token"
                or manifest["commitments"] != 0):
            raise ValueError("expected the plain native token checkpoint test parameters")
        key, _ = read_key(json.loads((parameters / "key.json").read_text()), "plain")
        lock = verifier_lock(key)
    parent, funding, policy, token = native_parent(node, lock)
    raw = parent.serialize()
    checkpoint = checkpoint_record(raw)
    state, suffix = (bytes.fromhex(checkpoint[field]) for field in ("midstate", "suffix"))
    (out / "parent.hex").write_text(raw.hex() + "\n")
    (out / "parent-checkpoint.json").write_text(json.dumps(checkpoint, indent=2) + "\n")
    if parameters is None:
        proof, evidence = b"", None
        disclosure = push(raw)
    else:
        message = statement_bytes(parent.txid_wire(), state, suffix)
        proof, evidence = prove_statement(prover, parameters, out / "checkpoint-proof.json", message,
                                          manifest, key, raw_parent=raw)
        disclosure = push(state) + push(suffix)

    def candidate(outputs, *, midstate=state, tail=suffix, signer=holder):
        draft = Transaction((Input(funding.txid_wire(), 0), Input(parent.txid_wire(), 0)), outputs)
        checkpoint_witness = (raw_verifier_material(draft, funding, raw) if manifest is None else
                              verifier_material(draft, funding, midstate, tail))
        owner_witness = ordinary_witness(draft, 1, parent, policy, funding, signer)
        return draft.with_script(0, proof + checkpoint_witness).with_script(1, owner_witness)

    same_output = parent.outputs[0]
    _, wrong_key = fixture_signer(17)
    negative = {
        "changed-token-quantity": candidate((Output(same_output.value, policy.lock(replace(token, quantity=641))),)),
        "wrong-holder": candidate((same_output,), signer=wrong_key),
    }
    if manifest is not None:
        negative["wrong-midstate"] = candidate((same_output,), midstate=bytes([state[0] ^ 1]) + state[1:])
        negative["wrong-suffix"] = candidate((same_output,), tail=suffix[:-1] + bytes([suffix[-1] ^ 1]))
    rejected = {label: {"txid": tx.txid(), "rejection": node.reject(tx)} for label, tx in negative.items()}
    payment = node.include("token-rollover", candidate((same_output,)), (funding, parent))
    if node.node.call("gettxout", parent.txid(), 0, False) is not None:
        raise AssertionError("the real unfrozen token UTXO was not spent")
    if node.node.call("gettxout", payment.txid(), 0, False) is None:
        raise AssertionError("the exact successor token must remain live")
    return {
        "scope": "Anchored test mint, native freeze and unfreeze, and holder-authorized exact token rollover",
        "source": "test deposit attestation", "parent_profile": "legacy v2 native unfreeze",
        "mode": "raw-parent" if manifest is None else "checkpoint",
        "token_quantity": token.quantity, "carrier_satoshis": same_output.value,
        "checkpoint": checkpoint, "parameters": manifest, "proof": evidence, "rejections": rejected,
        "parent_disclosure_with_encoding_bytes": len(disclosure), "proof_witness_bytes": len(proof),
        "child_witness_bytes_by_vin": [len(txin.script) for txin in payment.inputs],
        "child_bytes": len(payment.serialize()), "verifier_lock_bytes": len(lock),
        "verifier_funding_transaction_bytes": len(funding.serialize()),
        "child_and_verifier_funding_bytes": len(payment.serialize()) + len(funding.serialize()),
        "child_fee_satoshis": funding.outputs[0].value,
        "node_timings": node.confirmation_timings["token-rollover"],
        **node.evidence,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-url", required=True)
    parser.add_argument("--cookie", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--prover", type=Path)
    parser.add_argument("--parameters", type=Path)
    args = parser.parse_args()
    if (args.prover is None) != (args.parameters is None):
        parser.error("supply both prover and parameters for checkpoint mode")
    args.out.mkdir()
    result = run(Regtest(args.node_url, args.cookie), args.out, prover=args.prover, parameters=args.parameters)
    (args.out / "summary.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
