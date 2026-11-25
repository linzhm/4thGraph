"""Shared helpers for isolated Python regtest runners."""

from hashlib import new, sha256
import json
from time import perf_counter

from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_der_canonize

from regtest_mint import Node, RpcFailure, base58check, sign_p2pkh
from shared.chain_gang import validate_at_heights
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, hash256, preimage_all
from test_operational_token import fixture_signer
from wallet_receipt import BlockInclusion


def save(path, data):
    with path.open("x") as stream:
        print(json.dumps(data, indent=2), file=stream)


def confirmed(rpc, txid):
    record = rpc.call("getrawtransaction", txid, True)
    tx = Transaction.parse(bytes.fromhex(record["hex"]))
    block = rpc.call("getblock", record["blockhash"], 1)
    header = bytes.fromhex(rpc.call("getblockheader", block["hash"], False))
    txids = [bytes.fromhex(item)[::-1] for item in block["tx"]]
    proof = BlockInclusion.from_block(header, block["height"], txids, txids.index(tx.txid_wire()))
    if (tx.txid() != txid or proof.block_hash()[::-1].hex() != block["hash"]
            or rpc.call("getblockhash", block["height"]) != block["hash"] or block["confirmations"] < 1):
        raise ValueError("transaction is outside the adopted chain")
    return tx, block, proof


def test_signer(secret):
    """Public test keys only. Fixed DER length isolates history-dependent bytes."""
    key = SigningKey.from_secret_exponent(secret, curve=SECP256k1)

    def sign(digest):
        for nonce_attempt in range(256):
            der = key.sign_digest_deterministic(digest, hashfunc=sha256, sigencode=sigencode_der_canonize,
                                                extra_entropy=bytes([nonce_attempt]))
            if len(der) == 70:
                return der
        raise ValueError("could not obtain fixed-width test signature")

    return key.verifying_key.to_string("compressed"), sign


def p2pk(owner):
    return push(owner) + asm("OP_CHECKSIG")


def approve(tx, vin, previous, signer):
    digest = hash256(preimage_all(tx, vin, previous.value, previous.script))
    return push(signer(digest) + b"\x41")


def one_input(previous, vout, output, signer):
    tx = Transaction((Input(previous.txid_wire(), vout),), (output,))
    return tx.with_script(0, approve(tx, 0, previous.outputs[vout], signer))


class Regtest:
    def __init__(self, url, cookie, *, public_authorities=None):
        self.node = Node(url, cookie)
        # Public fixture keys for isolated regtest.
        self.owner_key, self.owner = fixture_signer(11)
        if public_authorities is None:
            self.freeze_key, _ = fixture_signer(12)
            self.minter_key, self.minter = fixture_signer(13)
        else:
            self.minter_key, self.freeze_key = public_authorities
            self.minter = None
        owner_hash = new("ripemd160", sha256(self.owner_key).digest()).digest()
        self.address = base58check(b"\x6f" + owner_hash)
        self.evidence = {"node": self.node.call("getnetworkinfo")["subversion"], "transactions": {}}
        self.confirmation_timings = {}

    def include(self, label, tx, parents):
        started = perf_counter()
        # A shared creating transaction supplies multiple distinct vouts.
        # Keep heights per actual vin while avoiding repeated multi-MB parses.
        funding = tuple({id(parent): parent for parent in parents}.values())
        validate_at_heights(tx, funding, spend_height=200, activation_height=2,
                            utxo_heights=(3,) * len(tx.inputs))
        checked = perf_counter()
        self.node.submit(tx)
        submitted = perf_counter()
        blockhash = self.node.call("generatetoaddress", 1, self.address)[0]
        block = self.node.call("getblock", blockhash, 1)
        if tx.txid() not in block["tx"]:
            raise AssertionError("transaction absent from mined block")
        self.evidence["transactions"][label] = {
            "txid": tx.txid(), "blockhash": blockhash, "height": block["height"],
            "bytes": len(tx.serialize()),
        }
        self.confirmation_timings[label] = {
            "chain_gang_seconds": checked - started,
            "node_submission_seconds": submitted - checked,
            "node_mining_and_confirmation_seconds": perf_counter() - submitted,
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

    def setup(self, outputs=6, *, anchor_tag=b""):
        coinbase = self.node.fund(self.address)
        value = min(100_000_000, coinbase.outputs[0].value // (outputs + 1))
        if value < 5_000_000:
            raise ValueError("test node subsidy too small for this fixture; use a fresh regtest")
        funding = (Output(value, asm("OP_1")),) * outputs
        if anchor_tag:
            funding += (Output(0, asm("OP_0 OP_RETURN") + push(anchor_tag)),)
        unsigned = Transaction((Input(coinbase.txid_wire(), 0),), funding)
        signer = SigningKey.from_secret_exponent(11, curve=SECP256k1)
        return self.include("setup", sign_p2pkh(unsigned, coinbase, 0, signer), (coinbase,))
