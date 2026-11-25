"""Replay issuer-independent receipts across a pending spend and a block rollback on a fresh regtest."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace

from certified_wallet_provenance import CertifiedWalletError
from evm.bsv_burn_evidence import BurnEvidenceError
from regtest_mint import Node
from run_secure_receipt_regtest import read_tx, receive, verifier_for, wallet_at_tip
from shared.transaction import Transaction, blob


# Public test invoice keys of Bob and Carol in run_secure_receipt_regtest.
BOB = bytes.fromhex("03421f5fc9a21065445c96fdb91c0c1e2f2431741c72713b4b99ddcb316f31e9fc")
CAROL = bytes.fromhex("032fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def adopt_through(source, clone, end):
    for height in range(clone.call("getblockcount") + 1, end + 1):
        block = source.call("getblockhash", height)
        result = clone.call("submitblock", source.call("getblock", block, 0))
        require(result is None and clone.call("getbestblockhash") == block,
                f"clone did not adopt block {height}: {result}")
    require(clone.call("getbestblockhash") == source.call("getblockhash", end),
            "source and clone disagree on replayed tip")


def observed(node, txid, vout):
    return {
        "height": node.call("getblockcount"), "tip": node.call("getbestblockhash"),
        "present_in_chain_utxos": node.call("gettxout", txid, vout, False) is not None,
        "present_in_utxos_with_mempool": node.call("gettxout", txid, vout, True) is not None,
    }


def rejected(wallet, tx, key, quantity, reason):
    try:
        receive(wallet, tx, 0, key, quantity)
    except (CertifiedWalletError, BurnEvidenceError) as error:
        if reason not in str(error):
            raise
        return {"accepted": False, "reason": str(error)}
    raise AssertionError("wallet accepted an ineligible output")


def replay(source, clone, summary, key, pins):
    records = summary["transactions"]
    first = records["alice-to-bob"]
    second = records["bob-to-carol"]
    funding = records["bob-to-carol-verifier"]
    two_conf = second["height"] + 1
    require(source.call("getblockchaininfo")["chain"] == clone.call("getblockchaininfo")["chain"] == "regtest",
            "replay requires two regtest nodes")
    require(source.call("getconnectioncount") == clone.call("getconnectioncount") == 0,
            "isolated source and clone required")
    clone_height = clone.call("getblockcount")
    require(source.call("getblockcount") >= two_conf and clone_height <= funding["height"]
            and clone.call("getbestblockhash") == source.call("getblockhash", clone_height),
            "source must contain both payments; the disposable replay node must be on its earlier prefix")
    require(clone.call("getblockhash", 0) == source.call("getblockhash", 0) == pins["bsv_genesis"],
            "unexpected regtest genesis")
    require(funding["height"] == second["height"] - 1 and first["height"] < funding["height"],
            "the payer's verifier funding must precede its payment")
    adopt_through(source, clone, funding["height"])
    # The locator hints and public mint/freeze keys can come from the sender.
    # The independent receiver's asset and verifier pins authenticate the policy.
    node = SimpleNamespace(node=clone, evidence={"transactions": records},
                           minter_key=bytes.fromhex(summary["mint_public_key"]),
                           freeze_key=bytes.fromhex(summary["freeze_public_key"]))
    verifier = verifier_for(node, read_tx(node, records["setup"]["txid"]), key,
                            aligned=summary.get("align_output_count", False))
    require(verifier.asset.asset_id().hex() == pins["asset"]
            and verifier.asset.issuance_outpoint.hex() == pins["anchor"]
            and sha256(blob(verifier.lock)).hexdigest() == pins["verifier_hash"],
            "wallet deployment differs from independently configured receiver pins")

    alice = read_tx(node, first["txid"])
    def wallet():
        return wallet_at_tip(node, verifier)

    require(clone.call("getrawmempool") == [], "initial clone mempool must be empty")
    report = {
        "node": clone.call("getnetworkinfo")["subversion"], "asset_id": pins["asset"],
        "verifier_lock_hash": pins["verifier_hash"], "continuity_key_digest": verifier.key_digest.hex(),
        "minimum_confirmations": wallet().confirmation_policy.minimum_confirmations,
        "bob_output": {"txid": first["txid"], "vout": 0},
        "carol_output": {"txid": second["txid"], "vout": 0},
        "prior_to_bob_spend": {
            "observation": observed(clone, first["txid"], 0),
            "bob_receipt": receive(wallet(), alice, 0, BOB, 275),
        },
    }
    # Supply exactly the signed payment from the source; all spend and reorg
    # RPCs in this experiment below are issued exclusively to the fresh clone.
    raw = source.call("getrawtransaction", second["txid"], False)
    require(Transaction.parse(bytes.fromhex(raw)).txid() == second["txid"], "incorrect signed payment")
    require(clone.call("sendrawtransaction", raw, True) == second["txid"]
            and clone.call("getrawmempool") == [second["txid"]], "pending Bob payment not in clone mempool")
    pending = observed(clone, first["txid"], 0)
    require(pending["present_in_chain_utxos"] and not pending["present_in_utxos_with_mempool"],
            "pending spend should be visible only in the local mempool view")
    report["pending_bob_spend"] = {
        "observation": pending, "spending_txid_in_mempool": second["txid"],
        "bob_wallet": rejected(wallet(), alice, BOB, 275, "spent, conflicted or unavailable"),
    }
    adopt_through(source, clone, second["height"])
    bob = read_tx(node, second["txid"])
    report["one_confirmation"] = {
        "observation": observed(clone, second["txid"], 0),
        "carol_wallet": rejected(wallet(), bob, CAROL, 350, "does not meet the confirmation policy"),
    }
    adopt_through(source, clone, two_conf)
    tip = clone.call("getbestblockhash")
    report["confirmed"] = {
        "observation": observed(clone, second["txid"], 0), "carol_receipt": receive(wallet(), bob, 0, CAROL, 350),
    }
    require(clone.call("getblockhash", second["height"]) == second["blockhash"],
            "unexpected block for clone rollback")
    clone.call("invalidateblock", second["blockhash"])
    try:
        require(clone.call("getbestblockhash") == funding["blockhash"], "clone failed to roll back both blocks")
        report["withdrawn"] = {
            "observation": observed(clone, second["txid"], 0),
            "carol_wallet": rejected(wallet(), bob, CAROL, 350, "does not meet the confirmation policy"),
            "invalidated_block": second["blockhash"],
            "payment_reentered_mempool": second["txid"] in clone.call("getrawmempool"),
        }
    finally:
        clone.call("reconsiderblock", second["blockhash"])
    require(clone.call("getbestblockhash") == tip == source.call("getblockhash", two_conf),
            "clone did not readopt the original confirming chain")
    report["restored"] = {
        "observation": observed(clone, second["txid"], 0), "carol_receipt": receive(wallet(), bob, 0, CAROL, 350),
    }
    require(report["restored"] == report["confirmed"], "restored receipt differs from original")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--source-cookie", type=Path, required=True)
    parser.add_argument("--clone-url", required=True)
    parser.add_argument("--clone-cookie", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--recipient-policy", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    report = replay(Node(args.source_url, args.source_cookie), Node(args.clone_url, args.clone_cookie),
                    json.loads(args.summary.read_text()), json.loads(args.key.read_text()),
                    json.loads(args.recipient_policy.read_text()))
    with args.out.open("x") as output:
        json.dump(report, output, indent=2)
        output.write("\n")


if __name__ == "__main__":
    main()
