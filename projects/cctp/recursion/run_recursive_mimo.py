"""Mine and verify a 2→2 recursive child of two independent v2 splits."""
import argparse
import json
import os
import subprocess
from dataclasses import replace
from hashlib import new, sha256
from pathlib import Path
from tempfile import TemporaryDirectory

from ecdsa import SECP256k1, SigningKey

from circom_fixture_prover import export_artifacts
from committed_verifier import load_artifact, load_verifying_key, verifier_fields
from mimo_verifier import MimoProfile
from mint import MintPolicy, authorize_mint, prepare_mint
from mint_events import Deposit, DepositPosition, EMPTY_ROOT, MintEvents
from operational_token import TokenPolicy, ordinary_witness
from recursive_mimo import RecursiveMimo, SplitLeaf
from regtest_mint import Node, RpcFailure, base58check, sign_p2pkh
from shared.chain_gang import validate_at_heights
from shared.script import asm
from shared.transaction import Input, Output, Transaction, hash256
from statement import AssetDescriptor, Slot
from test_mimo_verifier import TransferProver
from test_operational_token import fixture_signer
from transaction_relation import TokenState
from usdc_amount import USDC_DECIMALS
from verifier import unlocking_script


def _save(path, fields):
    path.write_text(json.dumps(fields, indent=2) + "\n")


class Regtest:
    def __init__(self, url, cookie):
        self.node = Node(url, cookie)
        # Public fixture keys for isolated regtest.
        self.owner_key, self.owner = fixture_signer(11)
        self.freeze_key, _ = fixture_signer(12)
        self.minter_key, self.minter = fixture_signer(13)
        owner_hash = new("ripemd160", sha256(self.owner_key).digest()).digest()
        self.address = base58check(b"\x6f" + owner_hash)
        self.evidence = {"node": self.node.call("getnetworkinfo")["subversion"], "transactions": {}}

    def include(self, label, tx, parents):
        validate_at_heights(tx, parents, spend_height=200, activation_height=2,
                            utxo_heights=(3,) * len(parents))
        self.node.submit(tx)
        blockhash = self.node.call("generatetoaddress", 1, self.address)[0]
        block = self.node.call("getblock", blockhash, 1)
        if tx.txid() not in block["tx"]:
            raise AssertionError("transaction absent from mined block")
        self.evidence["transactions"][label] = {
            "txid": tx.txid(), "blockhash": blockhash, "height": block["height"],
            "bytes": len(tx.serialize()),
        }
        return tx

    def reject(self, tx):
        try:
            self.node.submit(tx)
        except RpcFailure as failure:
            if failure.code == -26 and "mandatory-script-verify-flag-failed" in str(failure):
                return str(failure)
            raise
        raise AssertionError("regtest accepted an invalid recursive spend")

    def setup(self):
        coinbase = self.node.fund(self.address)
        value = min(100_000_000, coinbase.outputs[0].value // 7)
        if value < 5_000_000:
            raise ValueError("test node subsidy too small for this fixture; use a fresh regtest")
        unsigned = Transaction((Input(coinbase.txid_wire(), 0),), (Output(value, asm("OP_1")),) * 6)
        signer = SigningKey.from_secret_exponent(11, curve=SECP256k1)
        return self.include("setup", sign_p2pkh(unsigned, coinbase, 0, signer), (coinbase,))


def _prepare(node, leaf_prover, key, relation):
    setup = node.setup()
    anchor = Input(setup.txid_wire(), 3)
    asset = AssetDescriptor(1, anchor.outpoint(), USDC_DECIMALS, 7, b"r" * 32, b"p" * 32)
    leaf = SplitLeaf(leaf_prover.key, leaf_prover.profile)
    recursive = RecursiveMimo(leaf, key, relation)
    leaf_lock = leaf.profile.lock(asset, leaf.key)
    child_lock = recursive.lock(asset)
    policy = TokenPolicy((leaf_lock, child_lock), node.freeze_key)
    mint_policy = MintPolicy(asset, 84532, b"r" * 20, node.minter_key, policy.lock)

    funders = tuple(node.include(
        label, Transaction((Input(setup.txid_wire(), i),), (Output(setup.outputs[i].value - 1_000_000, lock),)),
        (setup,),
    ) for i, (label, lock) in enumerate((
        ("left-verifier", leaf_lock), ("right-verifier", leaf_lock), ("child-verifier", child_lock),
    )))
    mint_state = node.include(
        "mint-genesis", Transaction((anchor,), (
            Output(setup.outputs[3].value - 50_000, mint_policy.state_lock(EMPTY_ROOT)),
        )), (setup,),
    )
    mint_policy.check_genesis(mint_state)
    events, parents, records = MintEvents(), [], []
    for i, quantities in enumerate(((640, 384), (700, 324))):
        deposit = Deposit(DepositPosition(84532, asset.reserve_domain, mint_policy.reserve_contract,
                                           hash256(b"public test deposit" + bytes([i])), 0),
                          asset.reserve_asset, asset.network, asset.asset_id(), 1024, 0, node.owner_key)
        plan = prepare_mint(mint_policy, mint_state, events, deposit, Input(setup.txid_wire(), 4 + i))
        minted = authorize_mint(plan, lambda _: deposit, node.minter)
        node.include(f"mint-{i}", minted, (mint_state, setup))
        mint_state, events = minted, plan.successor

        funding = funders[i]
        unsigned = Transaction(
            (Input(funding.txid_wire(), 0), Input(minted.txid_wire(), 1)),
            tuple(mint_policy.token_output(q, node.owner_key) for q in quantities),
        )
        signals, proof = leaf_prover.prove(
            asset, unsigned, funding, (Slot(1, 1024),), tuple(Slot(j, q) for j, q in enumerate(quantities)),
        )
        verifier_unlock = leaf.profile.witness(asset, leaf.key, proof, unsigned, (funding, minted), policy)
        holder_unlock = ordinary_witness(unsigned, 1, minted, policy, funding, node.owner)
        signed = unsigned.with_script(0, verifier_unlock).with_script(1, holder_unlock)
        parents.append(node.include(f"split-{i}", signed, (funding, minted)))
        statement = leaf.statement(asset, policy, signed, funding)
        leaf_vk, proof_json, public = export_artifacts(leaf.key, signals, proof)
        records.append({"proof": proof_json, "signals": public, "statement": statement.hex(), "txid": signed.txid()})

    child_funding = funders[2]
    inputs = (Input(child_funding.txid_wire(), 0), Input(parents[0].txid_wire(), 0), Input(parents[1].txid_wire(), 1))
    tx = Transaction(inputs, tuple(mint_policy.token_output(q, node.owner_key) for q in (700, 264)))
    parents, preceding_funders = tuple(parents), funders[:2]
    child, preceding = recursive.statements(asset, policy, tx, child_funding, parents, preceding_funders)
    if preceding != tuple(bytes.fromhex(record["statement"]) for record in records):
        raise AssertionError("recursive parent statements disagree with leaf proofs")
    fixture_data = {
        "inner_vk": leaf_vk, "parents": records, "context": hash256(child).hex(), "context_statement": child.hex(),
        "inner_constraints": len(leaf_prover.prover.rows), "chain_gang_validated": True,
    }
    return recursive, asset, policy, tx, child_funding, parents, preceding_funders, fixture_data


def _verify(node, prepared, artifact_path):
    recursive, asset, policy, tx, verifier, parents, funders, _ = prepared
    key, relation, signals, proof = load_artifact(json.loads(artifact_path.read_text()))
    if key != recursive.key or relation != recursive.knowledge_relation:
        raise ValueError("proof verification key differs from the leaf-approved recursive lock")
    child, preceding = recursive.statements(asset, policy, tx, verifier, parents, funders)
    if signals != recursive.signals(child, preceding):
        raise ValueError("proof public inputs differ from the actual child and its parents")

    def add_owner_unlocks(unsigned, shared_witness):
        signed = unsigned.with_script(0, shared_witness)
        for i, parent in enumerate(parents, 1):
            signed = signed.with_script(i, ordinary_witness(unsigned, i, parent, policy, verifier, node.owner))
        return signed

    valid = recursive.witness(asset, policy, proof, tx, verifier, parents, funders)
    proof_fields = unlocking_script(verifier_fields(key, relation, signals, proof))
    wrong_funder = proof_fields + recursive.transaction_material(tx, verifier, parents, funders[::-1])
    rejected = {"swapped_funders": node.reject(add_owner_unlocks(tx, wrong_funder))}
    # Re-sign both owners for a different conserving payout and rebuild the
    # hints. The old outer proof cannot authorize the new public statement.
    bad_outputs = tuple(replace(output, script=policy.lock(TokenState(asset.asset_id(), quantity, node.owner_key)))
                        for output, quantity in zip(tx.outputs, (701, 263), strict=True))
    changed = replace(tx, outputs=bad_outputs)
    invalid = recursive.witness(asset, policy, proof, changed, verifier, parents, funders)
    rejected["changed_conserving_payout"] = node.reject(add_owner_unlocks(changed, invalid))
    signed = add_owner_unlocks(tx, valid)
    node.include("recursive-2to2", signed, (verifier, *parents))
    return {
        "scope": "Two real v2 split proofs, actual 2→2 spend, one layer of recursion, test-only setup",
        "asset_id": asset.asset_id().hex(),
        "spends": [{"txid": parent.txid(), "vout": txin.vout}
                   for txin, parent in zip(tx.inputs[1:], parents, strict=True)],
        "input_quantities": [640, 324], "output_quantities": [700, 264],
        "rejections": rejected, "public_signals": [str(signal) for signal in signals],
        "proof_file_sha256": sha256(artifact_path.read_bytes()).hexdigest(), **node.evidence,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-url", default=os.environ.get("REGTEST_URL"))
    parser.add_argument("--cookie", type=Path, default=os.environ.get("REGTEST_COOKIE"))
    parser.add_argument("--vk", type=Path, required=True)
    parser.add_argument("--prover", type=Path)
    parser.add_argument("--setup-dir", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if not (args.node_url and args.cookie) or bool(args.prover) != bool(args.setup_dir):
        parser.error("provide regtest RPC and cookie, with both prover and cache or neither")
    key, relation = load_verifying_key(json.loads(args.vk.read_text()))
    args.out.mkdir()
    node = Regtest(args.node_url, args.cookie)
    profile = MimoProfile(1, 2, 2, node.freeze_key)
    with TemporaryDirectory(prefix="cctp-recursive-regtest-") as directory:
        leaf_prover = TransferProver(Path(directory) / "leaf", profile)
        prepared = _prepare(node, leaf_prover, key, relation)
    fixture = (args.out / "gnark-input.json").resolve()
    _save(fixture, prepared[-1])
    if args.prover is None:
        _save(args.out / "parent-report.json", node.evidence)
        return
    artifact = (args.out / "outer-proof.json").resolve()
    subprocess.run([str(args.prover.resolve()), "-portable-asset", "-prove",
                    "-setup-dir", str(args.setup_dir.resolve()), "-artifact", str(artifact), str(fixture)],
                   check=True)
    _save(args.out / "summary.json", _verify(node, prepared, artifact))


if __name__ == "__main__":
    main()
