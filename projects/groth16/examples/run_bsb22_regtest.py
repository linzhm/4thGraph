"""Mine the independent arithmetic BSB22 fixture on an unpeered BSV regtest."""
import argparse
from hashlib import new, sha256
import json
from pathlib import Path
from time import perf_counter

from ecdsa import SECP256k1, SigningKey

from bsb22 import standalone_witness, verifier_lock
from regtest_mint import Node, RpcFailure, base58check, sign_p2pkh
from shared.script import asm, number
from shared.transaction import Input, Output, Transaction
from test_bsb22_independent import arithmetic_fixture


def run(node):
    if node.call("getconnectioncount") != 0:
        raise ValueError("use an isolated BSV regtest")
    key, relation, signals, proof = arithmetic_fixture()
    lock = verifier_lock(key, relation)
    witness = standalone_witness(key, relation, signals, proof)
    # Fixed public coinbase key for this isolated test.
    signer = SigningKey.from_secret_exponent(11, curve=SECP256k1)
    owner = signer.verifying_key.to_string("compressed")
    address = base58check(b"\x6f" + new("ripemd160", sha256(owner).digest()).digest())
    coinbase = node.fund(address)
    funding = Transaction((Input(coinbase.txid_wire(), 0),), (Output(100_000_000, lock),))
    funding = sign_p2pkh(funding, coinbase, 0, signer)
    node.confirm(funding, address)
    funding_block = node.call("getbestblockhash")

    spend = Transaction((Input(funding.txid_wire(), 0, witness),), (Output(98_000_000, asm("OP_1")),))
    low = signals[1]
    changed = spend.with_script(0, witness[:-len(number(low))] + number(low + 1))
    try:
        node.submit(changed)
    except RpcFailure as error:
        if error.code != -26 or "mandatory-script-verify-flag-failed" not in str(error):
            raise
        rejection = str(error)
    else:
        raise AssertionError("independent node accepted an altered public input")
    start = perf_counter()
    node.submit(spend)
    elapsed = perf_counter() - start
    block_hash = node.call("generatetoaddress", 1, address)[0]
    block = node.call("getblock", block_hash, 1)
    if spend.txid() not in block["tx"]:
        raise AssertionError("the valid generic proof spend was not mined")

    return {
        "scope": "isolated Bitcoin SV regtest, independent arithmetic BSB22 proof",
        "node": node.call("getnetworkinfo")["subversion"],
        "public_inputs": signals, "lock_bytes": len(lock), "witness_bytes": len(witness),
        "lock_sha256": sha256(lock).hexdigest(), "witness_sha256": sha256(witness).hexdigest(),
        "funding": {"txid": funding.txid(), "blockhash": funding_block},
        "spend": {"txid": spend.txid(), "blockhash": block_hash, "height": block["height"],
                  "bytes": len(spend.serialize()), "rpc_submission_seconds": elapsed},
        "changed_public_input": {"txid": changed.txid(), "rejection": rejection},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-url", required=True)
    parser.add_argument("--cookie", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("use a new report path")
    result = run(Node(args.node_url, args.cookie))
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
