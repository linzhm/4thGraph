"""Recheck the two covenant payments from another isolated BSV full node."""

import argparse
from hashlib import sha256
import json
from pathlib import Path

from covenant_backtrace import Policy
from regtest_mint import Node
from run_covenant_backtrace_regtest import receive, save
from run_freeze_probe_regtest import read_key
from run_secure_receipt_replay import BOB, CAROL, adopt_through


def replay(source, clone, records, pinned, key_artifact):
    if source.call("getconnectioncount") != 0 or clone.call("getconnectioncount") != 0:
        raise ValueError("use isolated source and replay nodes")
    if clone.call("getblockcount") != 0 or clone.call("getblockhash", 0) != source.call("getblockhash", 0):
        raise ValueError("use a fresh clone of the same regtest network")
    key, _ = read_key(key_artifact, "plain")
    policy = Policy(bytes.fromhex(pinned["issuance_root"])[::-1], key)
    if (sha256(policy.lock).hexdigest() != pinned["verifier_lock_sha256"]
            or key_artifact["verifying_key_sha256"] != pinned["verifying_key_sha256"]):
        raise ValueError("verifier key differs from recipient deployment pins")
    first, second = records["alice-to-bob"], records["bob-to-carol"]
    adopt_through(source, clone, first["height"])
    _, bob = receive(clone, pinned, policy, first["txid"], 0, BOB, 275)
    if clone.call("sendrawtransaction", source.call("getrawtransaction", second["txid"], False), True) != second["txid"]:
        raise ValueError("clone did not accept Bob's exact respend")
    if (clone.call("gettxout", first["txid"], 0, False) is None
            or clone.call("gettxout", first["txid"], 0, True) is not None):
        raise ValueError("mempool respend did not retire Bob's output from the wallet view")
    adopt_through(source, clone, second["height"])
    _, carol = receive(clone, pinned, policy, second["txid"], 0, CAROL, 350)
    try:
        receive(clone, pinned, policy, second["txid"], 1, CAROL, 350)
    except ValueError as error:
        if "wrong receipt outpoint or order" not in str(error):
            raise
        wrong_output = str(error)
    else:
        raise ValueError("wallet accepted Bob's change as Carol's receipt")
    return {"node": clone.call("getnetworkinfo")["subversion"], "bob": bob, "carol": carol,
            "bob_respend_accepted_on_clone": second["txid"], "mempool_excludes_bob_output": True,
            "wrong_receipt_vout_rejection": wrong_output}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--source-cookie", type=Path, required=True)
    parser.add_argument("--clone-url", required=True)
    parser.add_argument("--clone-cookie", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    records = json.loads(args.summary.read_text())["transactions"]
    report = replay(Node(args.source_url, args.source_cookie), Node(args.clone_url, args.clone_cookie),
                    records, json.loads(args.policy.read_text()), json.loads(args.key.read_text()))
    save(args.out, report)


if __name__ == "__main__":
    main()
