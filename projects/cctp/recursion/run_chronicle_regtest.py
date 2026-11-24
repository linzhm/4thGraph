"""Exercise Chronicle activation with complete raw transactions and blocks.

Run against a fresh isolated Bitcoin SV regtest using the same configured
activation height, Genesis at height 1, and transaction indexing. For example:

    PYTHONPATH=.:projects/groth16/reference:projects/cctp/recursion \
      python projects/cctp/recursion/run_chronicle_regtest.py \
      --node-url http://127.0.0.1:19537 --cookie /path/to/regtest/.cookie \
      --activation-height 105 --out /tmp/cctp-chronicle-results.json

The miner key and fixed PUSHTX key are public test fixtures. RPC submission is
measured with no peers. Neither the transactions nor the blocks are public.
"""

import argparse
from dataclasses import dataclass
from hashlib import new, sha256
import json
from pathlib import Path
from struct import pack

from ecdsa import SECP256k1, SigningKey

from regtest_mint import Node, RpcFailure, base58check, sign_p2pkh
from shared.pushtx import PUBLIC, binding_der
from shared.script import asm, number, push
from shared.transaction import Input, Output, Transaction, compact, hash256, preimage_forkid, preimage_otda


INPUT_SATS = 100_000
FEE = 10_000
SKIPPED_SEPARATOR = asm("OP_0 OP_IF OP_CODESEPARATOR OP_ENDIF")
SKIPPED_CLEAN = asm("OP_0 OP_IF OP_ENDIF")
SEPARATOR = asm("OP_CODESEPARATOR")
# The same byte in pushed data stays in both digest algorithms' scriptCode.
SEPARATOR_DATA = push(bytes.fromhex("ab55")) + asm("OP_DROP")
PROFILES = {
    "forkid": ((0x41, 0x41), (0x43, 0x43)),
    "mixed": ((0x41, 0x61), (0x43, 0x63)),
    "reverse": ((0x61, 0x41), (0x63, 0x43)),
}
HEIGHT_DELTAS = (-1, 0, 1)
FUNDING_ERAS = ("old", "new")


def _binding(flag):
    return asm("OP_HASH256") + binding_der() + push(bytes([flag])) + asm("OP_CAT") + push(PUBLIC)


@dataclass(frozen=True)
class DualBinding:
    first_flag: int
    second_flag: int
    # An optional Script assertion before the first binding. It must preserve
    # both stacks. Its own bytes precede the first executed CODESEPARATOR.
    first_preimage_check: bytes = b""

    def __post_init__(self):
        if any(flag not in (0x41, 0x43, 0x61, 0x63) for flag in (self.first_flag, self.second_flag)):
            raise ValueError("expected a supported ALL or paired SINGLE flag")

    def _suffixes(self, *, otda):
        skipped = SKIPPED_CLEAN if otda else SKIPPED_SEPARATOR
        second = skipped + SEPARATOR_DATA + asm("OP_CHECKSIG")
        first = (skipped + asm("OP_CHECKSIGVERIFY") + _binding(self.second_flag)
                 + (b"" if otda else SEPARATOR) + second)
        return first, second

    @property
    def lock(self):
        first_suffix, _ = self._suffixes(otda=False)
        return self.first_preimage_check + _binding(self.first_flag) + SEPARATOR + first_suffix

    def script_code(self, check, *, wrong_separator=False):
        if check not in (0, 1):
            raise ValueError("dual binding check index must be zero or one")
        flag = (self.first_flag, self.second_flag)[check]
        suffixes = self._suffixes(otda=bool(flag & 0x20))
        return suffixes[1 if wrong_separator and check == 0 else check]

    def preimages(self, tx, index, previous_output, *, wrong_separator=False):
        if previous_output.script != self.lock:
            raise ValueError("funding output does not have this dual binding")
        results = []
        for check, flag in enumerate((self.first_flag, self.second_flag)):
            code = self.script_code(check, wrong_separator=wrong_separator)
            if flag & 0x20:
                results.append(preimage_otda(tx, index, code, flag))
            else:
                results.append(preimage_forkid(tx, index, previous_output.value, code, flag))
        return tuple(results)

    def witness(self, tx, index, previous_output, *, wrong_separator=False):
        first, second = self.preimages(tx, index, previous_output, wrong_separator=wrong_separator)
        return push(second) + push(first)


@dataclass(frozen=True)
class Case:
    height_delta: int
    version: int
    profile: str
    eras: tuple[str, str]
    wrong_separator: bool = False

    def __post_init__(self):
        if (self.height_delta not in HEIGHT_DELTAS or self.version not in (1, 2) or self.profile not in PROFILES
                or len(self.eras) != 2 or any(era not in FUNDING_ERAS for era in self.eras)
                or (self.height_delta < 0 and "new" in self.eras)):
            raise ValueError("unsupported Chronicle boundary case")

    @property
    def name(self):
        eras = "-".join(self.eras)
        negative = "-wrong-separator" if self.wrong_separator else ""
        return f"H{self.height_delta:+d}-v{self.version}-{eras}-{self.profile}{negative}"

    @property
    def consensus(self):
        return not self.wrong_separator and (self.height_delta >= 0 or self.profile == "forkid")


def boundary_cases():
    cases = []
    for delta in HEIGHT_DELTAS:
        for version in (1, 2):
            eras = (("old", "old"),)
            if delta >= 0:
                eras += (("old", "new"), ("new", "old"), ("new", "new"))
            cases.extend(Case(delta, version, profile, pair) for pair in eras for profile in PROFILES)
            profile = "forkid" if delta < 0 else "reverse"
            cases.append(Case(delta, version, profile, eras[-1], wrong_separator=True))
    return tuple(cases)


def _mining_key():
    signer = SigningKey.from_secret_exponent(41261, curve=SECP256k1)  # Public test key.
    public = signer.verifying_key.to_string("compressed")
    pkh = new("ripemd160", sha256(public).digest()).digest()
    lock = asm("OP_DUP OP_HASH160") + push(pkh) + asm("OP_EQUALVERIFY OP_CHECKSIG")
    return signer, lock, base58check(b"\x6f" + pkh)


def _funding(spends, coinbase, signer, lock):
    change = coinbase.outputs[0].value - len(spends) * INPUT_SATS - FEE
    if change <= 0:
        raise ValueError("local coinbase is too small for the funding fixture")
    outputs = tuple(Output(INPUT_SATS, binding.lock) for binding in spends) + (Output(change, lock),)
    tx = Transaction((Input(coinbase.txid_wire(), 0),), outputs)
    return sign_p2pkh(tx, coinbase, 0, signer)


def _spend(case, bindings, parents, locations, payment_lock):
    inputs = tuple(Input(parent.txid_wire(), vout, sequence=0xFFFFFFFC + index)
                   for index, (parent, vout) in enumerate(zip(parents, locations, strict=True)))
    outputs = (Output(INPUT_SATS, payment_lock), Output(INPUT_SATS - FEE, payment_lock))
    tx = Transaction(inputs, outputs, version=case.version)
    for index, (binding, parent, vout) in enumerate(zip(bindings, parents, locations, strict=True)):
        witness = binding.witness(tx, index, parent.outputs[vout], wrong_separator=case.wrong_separator and index == 0)
        tx = tx.with_script(index, witness)
    return tx


def merkle_root(transactions):
    level = [tx.txid_wire() for tx in transactions]
    if not level:
        raise ValueError("regtest block requires a coinbase")
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hash256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def raw_block(previous, transactions, payment_lock):
    """Mine a regtest header with the given result order and fixed local difficulty."""
    height = previous["height"] + 1
    coinbase = Transaction((Input(bytes(32), 0xFFFFFFFF, number(height) + push(b"CCTP Chronicle test")),),
                           (Output(0, payment_lock),), version=1)
    ordered = (coinbase, *transactions)
    bits = int(previous["bits"], 16)
    if bits != 0x207FFFFF:
        raise ValueError("raw block builder requires fixed regtest difficulty")
    target = (bits & 0x7FFFFF) << (8 * ((bits >> 24) - 3))
    timestamp = max(previous["time"], previous["mediantime"]) + 1
    header = (pack("<I", 0x20000000) + bytes.fromhex(previous["hash"])[::-1] + merkle_root(ordered)
              + pack("<II", timestamp, bits))
    for nonce in range(1 << 32):
        candidate = header + pack("<I", nonce)
        block_hash = hash256(candidate)
        if int.from_bytes(block_hash, "little") <= target:
            raw = candidate + compact(len(ordered)) + b"".join(tx.serialize() for tx in ordered)
            return block_hash[::-1].hex(), raw
    raise AssertionError("exhausted nonces at regtest difficulty")


def _admission(node, tx):
    try:
        node.submit(tx)
    except RpcFailure as failure:
        return {"accepted": False, "code": failure.code, "reason": str(failure)}
    present = tx.txid() in node.call("getrawmempool")
    if not present:
        raise AssertionError("RPC accepted the raw transaction without adding it to this isolated mempool")
    return {"accepted": True, "mempool": True}


def _block_result(node, previous, transactions, payment_lock):
    block_hash, raw = raw_block(previous, transactions, payment_lock)
    result = node.call("submitblock", raw.hex())
    receipt = {"accepted": result is None, "hash": block_hash, "height": previous["height"] + 1,
               "header": raw[:80].hex(), "previous": previous["hash"]}
    if result is None:
        block = node.call("getblock", block_hash, 1)
        if (node.call("getbestblockhash") != block_hash or block["height"] != receipt["height"]
                or block["tx"][1:] != [tx.txid() for tx in transactions]):
            raise AssertionError("adopted raw block does not contain the submitted transactions at the requested height")
    else:
        receipt["reason"] = result
        if node.call("getbestblockhash") != previous["hash"]:
            raise AssertionError("rejected raw block changed the adopted tip")
    return receipt


def run(node, activation_height, *, cases=None, binding_factory=None):
    """Run cases on a fresh node; a factory can replace either dual binding by input index."""
    if activation_height < 105 or activation_height >= 149:
        raise ValueError("use height 105–148 for this pre-halving fixture")
    if node.call("getblockcount") != 0 or node.call("getconnectioncount") != 0:
        raise ValueError("use a fresh isolated regtest with no peers")
    cases = boundary_cases() if cases is None else tuple(cases)
    if not cases or len({case.name for case in cases}) != len(cases):
        raise ValueError("provide a nonempty set of uniquely named cases")
    if binding_factory is None:
        def binding_factory(first, second, _index):
            return DualBinding(first, second)

    signer, payment_lock, address = _mining_key()
    blocks = node.call("generatetoaddress", activation_height - 3, address)
    coinbases = []
    for block_hash in blocks[:2]:
        txid = node.call("getblock", block_hash, 1)["tx"][0]
        coinbases.append(Transaction.parse(bytes.fromhex(node.call("getrawtransaction", txid))))

    slots = {era: [] for era in FUNDING_ERAS}
    prepared = {}
    for case in cases:
        bindings = tuple(binding_factory(*flags, index) for index, flags in enumerate(PROFILES[case.profile]))
        positions = []
        for era, binding in zip(case.eras, bindings, strict=True):
            positions.append(len(slots[era]))
            slots[era].append(binding)
        prepared[case.name] = bindings, positions
    fundings = {era: _funding(slots[era], coin, signer, payment_lock)
                for era, coin in zip(FUNDING_ERAS, coinbases, strict=True)}
    old = fundings["old"]
    new_height = activation_height
    old_height = activation_height - 2
    old_admission = _admission(node, old)
    old_block = _block_result(node, node.call("getblockheader", blocks[-1]), (old,), payment_lock)
    if not old_block["accepted"] or old_block["height"] != old_height:
        raise AssertionError(f"failed to create historical funding outputs: {old_block}")

    rows = []
    accepted_blocks = []
    new_admission = None
    for delta in HEIGHT_DELTAS:
        expected_height = activation_height + delta
        previous = node.call("getblockheader", node.call("getbestblockhash"))
        if previous["height"] + 1 != expected_height:
            raise AssertionError("candidate block is not at the requested activation boundary")
        same_block_funding = (fundings["new"],) if delta == 0 else ()
        if same_block_funding:
            new_admission = _admission(node, same_block_funding[0])
        positive = []
        for case in (case for case in cases if case.height_delta == delta):
            bindings, positions = prepared[case.name]
            parents = tuple(fundings[era] for era in case.eras)
            tx = _spend(case, bindings, parents, positions, payment_lock)
            row = {
                "case": case.name, "height": expected_height, "version": case.version,
                "created_heights": [old_height if era == "old" else new_height for era in case.eras],
                "signature_types": [[f"{flag:02x}" for flag in flags] for flags in PROFILES[case.profile]],
                "wrong_separator": case.wrong_separator, "expected_consensus": case.consensus,
                "txid": tx.txid(), "raw": tx.serialize().hex(), "admission": _admission(node, tx),
            }
            if case.consensus:
                positive.append((row, tx))
            else:
                row["block"] = _block_result(node, previous, (*same_block_funding, tx), payment_lock)
                if row["block"]["accepted"]:
                    raise AssertionError(f"{case.name}: independent node accepted the invalid raw block")
            rows.append(row)
        group = (*same_block_funding, *(tx for _, tx in positive))
        accepted = _block_result(node, previous, group, payment_lock)
        if not accepted["accepted"]:
            raise AssertionError(f"height {expected_height}: independent node rejected the valid raw block: {accepted}")
        for row, _ in positive:
            row["block"] = accepted
        accepted_blocks.append(accepted)

    return {
        "scope": "isolated regtest sendrawtransaction and explicit proof-of-work submitblock; no P2P peers",
        "node": node.call("getnetworkinfo")["subversion"], "activation_height": activation_height,
        "funding": {
            "old": {"height": old_height, "txid": old.txid(), "raw": old.serialize().hex(),
                    "admission": old_admission, "block": old_block},
            "new": {"height": new_height, "txid": fundings["new"].txid(), "raw": fundings["new"].serialize().hex(),
                    "admission": new_admission, "block": accepted_blocks[1]},
        },
        "mined_blocks": accepted_blocks, "cases": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-url", required=True)
    parser.add_argument("--cookie", type=Path, required=True)
    parser.add_argument("--activation-height", type=int, default=105)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        parser.error("choose a new result file")
    result = run(Node(args.node_url, args.cookie), args.activation_height)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    valid = sum(case["block"]["accepted"] for case in result["cases"])
    print(f"{valid} mined cases, {len(result['cases']) - valid} rejected raw block cases")


if __name__ == "__main__":
    main()
