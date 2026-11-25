"""Verify same-key continuity on independent BSV regtest with actual UTXOs."""
import argparse
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess

from committed_verifier import load_artifact, load_verifying_key, verifier_fields
from continuity_statement import ParentReceipt
from continuity_verifier import ContinuityVerifier
from mint import MintPolicy, authorize_mint, prepare_mint
from mint_events import Deposit, DepositPosition, EMPTY_ROOT, MintEvents
from operational_token import ordinary_witness
from run_recursive_mimo import Regtest
from shared.transaction import Input, Output, Transaction, hash256
from statement import AssetDescriptor
from usdc_amount import USDC_DECIMALS, parse_usdc
from verifier import unlocking_script


def _save(path, payload):
    path.write_text(json.dumps(payload, indent=2) + "\n")


class NativeProver:
    def __init__(self, binary, setup, out, key_digest):
        self.setup = setup
        self.binary = binary.resolve()
        self.out = out
        self.key_digest = key_digest

    def _read_reply(self):
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError(f"native prover closed its session (status {self.process.poll()})")
        return json.loads(line)

    def __enter__(self):
        self.process = subprocess.Popen(
            [str(self.binary), "-mode", "session", "-dir", str(self.setup.resolve())],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        )
        try:
            ready = self._read_reply()
            if not ready.get("ready") or ready.get("continuity_key_digest") != self.key_digest:
                raise ValueError("native prover loaded a different continuity key")
        except BaseException:
            self.__exit__()
            raise
        return self

    def __exit__(self, *_):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.process.stdout.close()

    def prove(self, label, asset, context, ancestors):
        artifact = (self.out / f"{label}-proof.json").resolve()
        request = {
            "id": label, "asset": asset.hex(), "context": context.hex(),
            "prior": [str(item.resolve()) for item in ancestors], "out": str(artifact),
        }
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        response = self._read_reply()
        if response.get("id") != label or not response.get("ok"):
            raise RuntimeError(f"native proof request failed: {response}")
        key, commitment, signals, proof = load_artifact(json.loads(artifact.read_text()))
        return artifact, key, commitment, signals, proof


def _prepare(node, key_artifact, *, mint_state_version):
    setup = node.setup()
    anchor = Input(setup.txid_wire(), 3)
    asset = AssetDescriptor(1, anchor.outpoint(), USDC_DECIMALS, 7, b"r" * 32, b"p" * 32)
    mint_template = MintPolicy(asset, 84532, b"r" * 20, node.minter_key, lambda _: b"",
                               state_version=mint_state_version)
    key, commitment = load_verifying_key(key_artifact)
    verifier = ContinuityVerifier(mint_template, node.freeze_key, key, commitment,
                                  bytes.fromhex(key_artifact["continuity_key_digest"]), certified_mints=True)
    carriers = tuple(node.include(f"funding-{i}", Transaction(
        (Input(setup.txid_wire(), i),), (Output(setup.outputs[i].value - 1_000_000, verifier.lock),),
    ), (setup,)) for i in (0, 1, 2, 4))
    policy = verifier.mint_policy
    genesis = node.include("mint-genesis", Transaction(
        (anchor,), (Output(setup.outputs[3].value - 50_000, policy.state_lock(EMPTY_ROOT)),),
    ), (setup,))
    return verifier, carriers, genesis


def _sign(node, verifier, tx, funding, parents, funding_witness):
    signed = tx.with_script(0, funding_witness)
    for i, parent in enumerate(parents, 1):
        signed = signed.with_script(i, ordinary_witness(tx, i, parent, verifier.policy, funding, node.owner))
    return signed


def _candidate(node, verifier, funding, origins, quantities):
    parents, positions, supporting, proofs = zip(*origins, strict=True)
    receipt = ParentReceipt(tuple(verifier.proof_digest(parent, proof_funding)
                                  for parent, proof_funding in zip(parents, supporting, strict=True)))
    tx = Transaction(
        (Input(funding.txid_wire(), 0),
         *(Input(parent.txid_wire(), vout) for parent, vout in zip(parents, positions, strict=True))),
        (*(verifier.mint_policy.token_output(q, node.owner_key) for q in quantities), receipt.output()),
    )
    return tx, parents, supporting, proofs


def _prove(verifier, prover, label, receipt, context, ancestors):
    asset_id = verifier.asset.asset_id()
    artifact, key, commitment, public, proof = prover.prove(label, asset_id, context, ancestors)
    if (key, commitment, public) != (verifier.key, verifier.commitment, receipt.signals(
            asset_id, verifier.key_digest, context)):
        raise ValueError("proof not bound to the actual verifier and transaction")
    return artifact, public, proof


def _checkpoint(node, prover, label, signed, funding, artifact, public, receipt, quantities, predecessors, rejected):
    details = {
        "predecessors": [{"txid": parent.txid(), "vout": vout} for parent, vout in predecessors],
        "public_signals": [str(item) for item in public],
        "previous_proof_digests": [item.hex() for item in receipt.parents],
        "proof_sha256": sha256(artifact.read_bytes()).hexdigest(),
        "largest_input_script_bytes": max(len(txin.script) for txin in signed.inputs),
        "quantities": list(quantities),
        "rejections": rejected,
    }
    _save(prover.out / f"{label}-checkpoint.json", {
        "transaction": signed.serialize().hex(), "funding": funding.serialize().hex(),
        "details": details, **node.evidence,
    })
    return signed, artifact, details


def _mint(node, verifier, prover, label, state, events, funding, quantity, *, predecessor=None, recipient=None):
    policy = verifier.mint_policy
    asset = verifier.asset
    prior = None if predecessor is None else predecessor[0]
    receipt = ParentReceipt(() if prior is None else (verifier.proof_digest(state, prior),))
    deposit = Deposit(DepositPosition(policy.source_chain_id, asset.reserve_domain, policy.reserve_contract,
                                       hash256(label.encode("ascii")), 0),
                      asset.reserve_asset, asset.network, asset.asset_id(), quantity, 0,
                      node.owner_key if recipient is None else recipient)
    plan = prepare_mint(policy, state, events, deposit, Input(funding.txid_wire(), 0),
                        receipt=receipt, verifier_parent=funding)
    signed = authorize_mint(plan, lambda _: deposit, node.minter)
    receipt, context = verifier.validate_mint(signed, funding, state, prior)
    ancestors = () if predecessor is None else (predecessor[1],)
    artifact, public, proof = _prove(verifier, prover, label, receipt, context, ancestors)
    signed = signed.with_script(1, verifier.mint_witness(proof, signed, funding, state, prior))
    node.include(label, signed, (state, funding))
    return (*_checkpoint(node, prover, label, signed, funding, artifact, public, receipt,
                         (quantity,), ((state, 0),), {}), plan.successor)


def _include(node, verifier, prover, label, funding, origins, quantities):
    tx, parents, supporting, ancestors = _candidate(node, verifier, funding, origins, quantities)
    receipt, context = verifier.validate(tx, funding, parents, supporting)
    artifact, public, proof = _prove(verifier, prover, label, receipt, context, ancestors)

    rejected = {}
    if len(ancestors) == 2:
        fields = unlocking_script(verifier_fields(verifier.key, verifier.commitment, public, proof))
        bad_witness = fields + verifier.transaction_material(tx, funding, parents, supporting[::-1], count=2)
        rejected["substituted_predecessor_funding"] = node.reject(_sign(node, verifier, tx, funding, parents, bad_witness))
        altered = replace(tx, outputs=(
            verifier.mint_policy.token_output(quantities[0] + 1, node.owner_key),
            verifier.mint_policy.token_output(quantities[1] - 1, node.owner_key), tx.outputs[-1],
        ))
        invalid = verifier.witness(proof, altered, funding, parents, supporting)
        rejected["resigned_payout_with_old_proof"] = node.reject(_sign(node, verifier, altered, funding, parents, invalid))

    valid = verifier.witness(proof, tx, funding, parents, supporting)
    signed = _sign(node, verifier, tx, funding, parents, valid)
    node.include(label, signed, (funding, *parents))
    spent = tuple((parent, txin.vout) for txin, parent in zip(tx.inputs[1:], parents, strict=True))
    return _checkpoint(node, prover, label, signed, funding, artifact, public, receipt, quantities, spent, rejected)


def run(node, prover, key_artifact, *, mint_state_version=1):
    verifier, funders, genesis = _prepare(node, key_artifact, mint_state_version=mint_state_version)
    first, first_proof, first_check, events = _mint(
        node, verifier, prover, "certified-first-mint", genesis, MintEvents(), funders[0], parse_usdc("0.001024"),
    )
    second, second_proof, second_check, _ = _mint(
        node, verifier, prover, "certified-next-mint", first, events, funders[1], parse_usdc("0.000384"),
        predecessor=(funders[0], first_proof),
    )
    if mint_state_version == 2:
        policy = verifier.mint_policy
        totals = tuple(policy.parse_state_lock(tx.outputs[0].script).cumulative_minted for tx in (genesis, first, second))
        if totals != (0, parse_usdc("0.001024"), parse_usdc("0.001408")):
            raise AssertionError("confirmed mint states do not carry the expected cumulative issuance")
        first_check["cumulative_minted"], second_check["cumulative_minted"] = totals[1:]
    third, third_proof, third_check = _include(
        node, verifier, prover, "two-continuity-parents", funders[2],
        ((first, 1, funders[0], first_proof), (second, 1, funders[1], second_proof)), (640, 768),
    )
    _, _, fourth_check = _include(
        node, verifier, prover, "continuity-descendant", funders[3], ((third, 1, funders[2], third_proof),), (384, 384),
    )
    return {
        "scope": "Two certified mints using test attestations and two MIMO hops under the same BSB22 key on BSV regtest.",
        "mint_state_version": mint_state_version,
        "asset_id": verifier.asset.asset_id().hex(),
        "continuity_key_digest": verifier.key_digest.hex(),
        "proof_checks": {
            "certified-first-mint": first_check, "certified-next-mint": second_check,
            "two-continuity-parents": third_check, "continuity-descendant": fourth_check,
        },
        **node.evidence,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-url", default=os.environ.get("REGTEST_URL"))
    parser.add_argument("--cookie", type=Path, default=os.environ.get("REGTEST_COOKIE"))
    parser.add_argument("--prover", type=Path, required=True)
    parser.add_argument("--setup-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--mint-state-version", type=int, choices=(1, 2), default=1)
    args = parser.parse_args()
    if not (args.node_url and args.cookie):
        parser.error("independent BSV regtest RPC and cookie are required")
    key_artifact = json.loads((args.setup_dir / "key.json").read_text())
    args.out.mkdir()
    node = Regtest(args.node_url, args.cookie)
    with NativeProver(args.prover, args.setup_dir, args.out, key_artifact["continuity_key_digest"]) as prover:
        _save(args.out / "summary.json", run(node, prover, key_artifact, mint_state_version=args.mint_state_version))


if __name__ == "__main__":
    main()
