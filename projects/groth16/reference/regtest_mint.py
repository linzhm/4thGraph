"""Compile and prove a test-only 1,024-unit issuance, split and merge."""

import argparse
from base64 import b64encode
from dataclasses import replace
from hashlib import new, sha256
import json
from pathlib import Path
import subprocess
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from circom_fixture_prover import CompiledProver, export_artifacts
from field import R
from public_inputs import transaction_verifier_lock, transaction_verifier_unlock
from recursive_transfer import PriorProof, RecursiveTransfer
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, hash256, preimage_forkid
from snarkjs_adapter import load_artifacts
from token_transfer import TokenState, owned_token_lock
from transfer import TransferStatement, shared_guard_lock
from verifier import verify_host

FEE = 400_000
POOL_VALUE = 10_000_000
SUPPLY = 1024


class ProvingSession:
    def __init__(self, directory):
        self.directory = directory
        circuit = Path(__file__).resolve().parents[1] / "circuits" / "toolchain_smoke.circom"
        subprocess.run(
            ["circom", str(circuit), "--r1cs", "--wasm", "--prime", "bls12381", "-o", str(directory)],
            check=True,
        )
        self.prover = CompiledProver.load(directory / "toolchain_smoke.r1cs")
        self.key = self.prover.key

    def prove(self, label, public):
        a, b = public
        inputs = self.directory / f"{label}.input.json"
        inputs.write_text(json.dumps({"outputValue": str(a), "offset": str(b), "a": "1", "b": str((a - b) % R)}))
        witness = self.directory / f"{label}.wtns"
        wasm = self.directory / "toolchain_smoke_js"
        subprocess.run(
            ["node", str(wasm / "generate_witness.js"), str(wasm / "toolchain_smoke.wasm"),
             str(inputs), str(witness)], check=True,
        )
        exported, proof = self.prover.prove(witness)
        if exported != public:
            raise AssertionError("compiled witness did not export the requested statement")
        vk, encoded, signals = export_artifacts(self.key, public, proof)
        for name, artifact in (("verification_key", vk), ("proof", encoded), ("public", signals)):
            (self.directory / f"{label}.{name}.json").write_text(json.dumps(artifact, indent=2) + "\n")
        imported_key, imported_public, imported_proof = load_artifacts(vk, encoded, signals)
        if not verify_host(imported_key, imported_public, imported_proof):
            raise AssertionError("compiled proof did not verify after JSON round trip")
        return imported_proof


class RpcFailure(RuntimeError):
    def __init__(self, method, error):
        super().__init__(f"{method}: {error}")
        self.code = error["code"]


class Node:
    def __init__(self, url, cookie):
        endpoint = urlparse(url)
        if endpoint.scheme != "http" or endpoint.hostname not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError("use a loopback BSV regtest RPC")
        self.url = url
        self.auth = "Basic " + b64encode(cookie.read_bytes().strip()).decode()
        if self.call("getblockchaininfo")["chain"] != "regtest":
            raise ValueError("RPC endpoint is not regtest")
        if "Bitcoin SV" not in self.call("getnetworkinfo")["subversion"]:
            raise ValueError("RPC endpoint must run BSV Node")

    def call(self, method, *params):
        data = json.dumps({"jsonrpc": "1.0", "id": "groth16", "method": method, "params": params}).encode()
        headers = {"Authorization": self.auth, "Content-Type": "application/json"}
        try:
            with urlopen(Request(self.url, data, headers), timeout=120) as reply:
                result = json.load(reply)
        except HTTPError as error:
            result = json.load(error)
        if result["error"] is not None:
            raise RpcFailure(method, result["error"])
        return result["result"]

    def fund(self, address):
        blocks = self.call("generatetoaddress", 101, address)
        block = self.call("getblock", blocks[0], 1)
        txid = block["tx"][0]
        return Transaction.parse(bytes.fromhex(self.call("getrawtransaction", txid)))

    def submit(self, transaction):
        txid = self.call("sendrawtransaction", transaction.serialize().hex(), True)
        if txid != transaction.txid():
            raise AssertionError("node returned a different txid")

    def confirm(self, transaction, address):
        self.submit(transaction)
        block = self.call("generatetoaddress", 1, address)[0]
        if transaction.txid() not in self.call("getblock", block, 1)["tx"]:
            raise AssertionError("transaction was not included in the regtest block")


def base58check(data):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    value = int.from_bytes(data + hash256(data)[:4], "big")
    digits = []
    while value:
        value, digit = divmod(value, 58)
        digits.append(alphabet[digit])
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + "".join(reversed(digits))


def public(signer):
    return signer.verifying_key.to_string("compressed")


def authorization(signer, preimage):
    from ecdsa.util import sigencode_der_canonize

    return signer.sign_digest_deterministic(hash256(preimage), hashfunc=sha256,
                                             sigencode=sigencode_der_canonize) + b"\x41"


def sign_p2pkh(transaction, funding, vout, signer):
    prev = funding.outputs[vout]
    digest = preimage_forkid(transaction, 0, prev.value, prev.script, 0x41)
    return transaction.with_script(0, push(authorization(signer, digest)) + push(public(signer)))


def outpoint(parent, index=0):
    return Input(parent.txid_wire(), index)


def sign_transfer(tx, parents, statement, key, proof, owners):
    verifier, guard, *_ = parents
    prevouts = push(b"".join(item.outpoint() for item in tx.inputs))
    tx = tx.with_script(0, transaction_verifier_unlock(statement, tx, 0, verifier, key, proof))
    guard_output = guard.outputs[0]
    preimage = preimage_forkid(tx, 1, guard_output.value, guard_output.script, 0x41)
    tx = tx.with_script(1, push(verifier.serialize()) + prevouts + push(preimage))
    parent_push = push(guard.serialize())
    for index, (parent, signer) in enumerate(zip(parents[2:], owners, strict=True), 2):
        output = parent.outputs[tx.inputs[index].vout]
        preimage = preimage_forkid(tx, index, output.value, output.script, 0x41)
        witness = push(authorization(signer, preimage)) + parent_push + prevouts + push(preimage)
        tx = tx.with_script(index, witness)
    return tx


def build_run(directory, node):
    from ecdsa import SECP256k1, SigningKey
    from shared.chain_gang import validate_at_heights

    mining_key, alice, bob = (SigningKey.from_secret_exponent(i, curve=SECP256k1) for i in (13, 17, 19))
    miner_hash = new("ripemd160", sha256(public(mining_key)).digest()).digest()
    address = base58check(b"\x6f" + miner_hash)
    p2pkh = asm("OP_DUP OP_HASH160") + push(miner_hash) + asm("OP_EQUALVERIFY OP_CHECKSIG")
    proving = ProvingSession(directory)
    coinbase = node.fund(address) if node else Transaction(
        (Input(bytes(32), 0xFFFFFFFF, b"\x01\x05"),), (Output(5_000_000_000, p2pkh),), version=1,
    )
    if coinbase.outputs[0].script != p2pkh or coinbase.outputs[0].value < 5 * POOL_VALUE + FEE:
        raise ValueError("coinbase does not fund the selected test key")

    pool_change = coinbase.outputs[0].value - 5 * POOL_VALUE - FEE
    pool_outputs = (Output(POOL_VALUE, p2pkh),) * 5
    if pool_change:
        pool_outputs += (Output(pool_change, p2pkh),)
    pool = sign_p2pkh(Transaction((outpoint(coinbase),), pool_outputs), coinbase, 0, mining_key)
    anchor = outpoint(pool).outpoint()
    verifier_lock = transaction_verifier_lock(anchor, proving.key, compact_preimage=True)
    statement = TransferStatement(anchor, verifier_lock, compact_preimage=True)
    relation = RecursiveTransfer(statement, SUPPLY, shared_guard=True)
    lock_guard = shared_guard_lock(verifier_lock)
    results = {}

    def write(label, tx):
        (directory / f"{label}.hex").write_text(tx.serialize().hex() + "\n")
        results[label] = {"txid": tx.txid(), "bytes": len(tx.serialize())}

    def accept(label, tx, parents):
        validate_at_heights(tx, parents, spend_height=205, activation_height=2, utxo_heights=[3] * len(parents))
        write(label, tx)
        if node:
            node.confirm(tx, address)
        results[label]["chain_gang"] = "accepted"
        results[label]["node"] = "confirmed" if node else "not run"

    def reject(label, tx, parents):
        try:
            validate_at_heights(tx, parents, spend_height=205, activation_height=2, utxo_heights=[3] * len(parents))
        except (RuntimeError, ValueError) as error:
            if "Error evaluating the script" not in str(error):
                raise
        else:
            raise AssertionError(f"{label}: chain-gang accepted invalid script")
        write(label, tx)
        if node:
            try:
                node.submit(tx)
            except RpcFailure as error:
                if error.code != -26:
                    raise
            else:
                raise AssertionError(f"{label}: regtest accepted invalid spend")
        results[label]["chain_gang"] = "rejected"
        results[label]["node"] = "rejected" if node else "not run"

    def token(quantity, owner, value):
        return Output(value, owned_token_lock(TokenState(anchor, quantity, public(owner)), verifier_lock,
                                             shared_guard=True))

    write("coinbase", coinbase)
    accept("funding-pool", pool, (coinbase,))
    mint = sign_p2pkh(Transaction((outpoint(pool),), (token(SUPPLY, alice, POOL_VALUE - FEE),)), pool, 0, mining_key)
    accept("mint-1024", mint, (pool,))
    verifier_parents = []
    for index, lock in enumerate((verifier_lock, lock_guard) * 2, 1):
        parent = sign_p2pkh(Transaction((outpoint(pool, index),), (Output(POOL_VALUE - FEE, lock),)),
                            pool, index, mining_key)
        accept(f"support-{index}", parent, (pool,))
        verifier_parents.append(parent)

    a, b, c, d = verifier_parents
    split_parents = (a, b, mint)
    split_total = sum(parent.outputs[0].value for parent in split_parents) - FEE
    split = Transaction(tuple(map(outpoint, split_parents)),
                        (token(640, alice, split_total // 2), token(384, bob, split_total - split_total // 2)))
    split_public = relation.check(split, split_parents, {}, lambda *_: False)
    split_proof = proving.prove("split", split_public)
    split_signed = sign_transfer(split, split_parents, statement, proving.key, split_proof, (alice,))
    reject("bad-owner", sign_transfer(split, split_parents, statement, proving.key, split_proof, (bob,)), split_parents)
    wrong_public = ((split_public[0] + 1) % (2**128), split_public[1])
    wrong_proof = proving.prove("wrong-statement", wrong_public)
    reject("wrong-proof", sign_transfer(split, split_parents, statement, proving.key, wrong_proof, (alice,)),
           split_parents)
    changed = replace(split_signed, outputs=tuple(reversed(split_signed.outputs)))
    reject("outputs-reordered", changed, split_parents)
    reject("missing-proof", split_signed.with_script(0, b""), split_parents)
    inflated = replace(split, outputs=(split.outputs[0], token(385, bob, split.outputs[1].value)))
    try:
        relation.check(inflated, split_parents, {}, lambda *_: False)
    except ValueError as error:
        if "quantities do not conserve" not in str(error):
            raise
        results["inflation-reference-only"] = {"rejected": str(error)}
    else:
        raise AssertionError("inflation passed reference relation")
    overmint = replace(mint, outputs=(token(SUPPLY + 1, alice, mint.outputs[0].value),))
    wrong_anchor = replace(split, inputs=(*split.inputs[:2], outpoint(overmint)))
    try:
        relation.check(wrong_anchor, (a, b, overmint), {}, lambda *_: False)
    except ValueError as error:
        if "issuance supply mismatch" not in str(error):
            raise
        results["overmint-reference-only"] = {"rejected": str(error)}
    else:
        raise AssertionError("overmint passed reference relation")
    accept("split-640-384", split_signed, split_parents)

    final_total = sum(out.value for out in split.outputs) + c.outputs[0].value + d.outputs[0].value - FEE
    merge_parents = (c, d, split_signed, split_signed)
    merge = Transaction((outpoint(c), outpoint(d), outpoint(split_signed), outpoint(split_signed, 1)),
                        (token(SUPPLY, alice, final_total),))
    calls = []

    def verify_predecessor(public_inputs, proof):
        calls.append(public_inputs)
        if proof != b"split":
            return False
        return verify_host(proving.key, public_inputs, split_proof)

    previous = {split_signed.txid_wire(): PriorProof(a, b"split")}
    merge_public = relation.check(merge, merge_parents, previous, verify_predecessor)
    if calls != [split_public]:
        raise AssertionError("expected one predecessor verification for two outpoints")
    merge_proof = proving.prove("merge", merge_public)
    accept("merge-1024", sign_transfer(merge, merge_parents, statement, proving.key, merge_proof, (alice, bob)),
           merge_parents)
    (directory / "report.json").write_text(json.dumps({"regtest_confirmed": node is not None,
                                                       "cases": results}, indent=2) + "\n")
    print(f"Report: {directory / 'report.json'}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="new directory for circuit and transaction artifacts")
    parser.add_argument("--rpc-url", help="optional loopback BSV regtest endpoint")
    parser.add_argument("--cookie", type=Path, help="RPC cookie for the selected dedicated regtest node")
    args = parser.parse_args()
    if bool(args.rpc_url) != bool(args.cookie):
        parser.error("--rpc-url and --cookie must be supplied together")
    directory = args.out.resolve()
    directory.mkdir()
    build_run(directory, Node(args.rpc_url, args.cookie) if args.rpc_url else None)


if __name__ == "__main__":
    main()
