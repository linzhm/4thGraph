"""Export receipt evidence from an untrusted regtest data source."""

from regtest_support import confirmed
from shared.transaction import Transaction
from spv_payment import RegtestHeaderChain, TxInclusion
from wallet_receipt import BlockInclusion


def header_chain(rpc, height=None):
    if height is None:
        height = rpc.call("getblockcount")
    if type(height) is not int or height < 0:
        raise ValueError("invalid header height")
    return RegtestHeaderChain(tuple(bytes.fromhex(rpc.call("getblockheader", block, False))
                                    for block in (rpc.call("getblockhash", i) for i in range(height + 1))))


def confirmed_packet(rpc, txid, block_hash=None):
    if block_hash is None:
        tx, _, inclusion = confirmed(rpc, txid)
        return TxInclusion(tx.serialize(), inclusion)
    # The sender's block hint avoids a verbose RPC that disassembles scriptSig.
    raw = bytes.fromhex(rpc.call("getrawtransaction", txid, False))
    packet = packet_from_raw(rpc, raw, block_hash)
    if Transaction.parse(raw).txid() != txid:
        raise ValueError("wrong raw transaction")
    return packet


def read_packet(chain, packet):
    height = packet["height"]
    if type(height) is not int or not 0 <= height < len(chain.headers):
        raise ValueError("unexpected packet block height")
    inclusion = BlockInclusion(chain.headers[height], height, packet["index"], packet["leaf_count"],
                               tuple(bytes.fromhex(sibling) for sibling in packet["siblings"]))
    return TxInclusion(bytes.fromhex(packet["raw"]), inclusion)


def packet_from_raw(rpc, raw, block_hash):
    """Add a verified Merkle path to bytes already held by the sender."""
    wire_txid = Transaction.parse(raw).txid_wire()
    block = rpc.call("getblock", block_hash, 1)
    txids = tuple(bytes.fromhex(item)[::-1] for item in block["tx"])
    header = bytes.fromhex(rpc.call("getblockheader", block_hash, False))
    if wire_txid not in txids:
        raise ValueError("wrong inclusion hint")
    inclusion = BlockInclusion.from_block(header, block["height"], txids, txids.index(wire_txid))
    if inclusion.block_hash()[::-1].hex() != block_hash:
        raise ValueError("wrong block header for inclusion hint")
    return TxInclusion(raw, inclusion)


def payment_packets(rpc, txid, locations=None):
    locations = {} if locations is None else locations
    payment = confirmed_packet(rpc, txid, locations.get(txid))
    tx = Transaction.parse(payment.raw)
    parents = tuple(confirmed_packet(rpc, wire[::-1].hex(), locations.get(wire[::-1].hex()))
                    for wire in dict.fromkeys(item.txid for item in tx.inputs))
    return payment, parents


def packet_bytes(payment, parents):
    """Separate raw transaction and branch size. Headers are already held by the wallet."""
    packets = (payment, *parents)
    return {"transactions": sum(len(packet.raw) for packet in packets),
            "merkle_siblings": sum(32 * len(packet.inclusion.siblings) for packet in packets)}



def included_packet(node, label, tx):
    """Attach the recorded block proof without a transaction index."""
    entry = node.evidence["transactions"][label]
    packet = packet_from_raw(node.node, tx.serialize(), entry["blockhash"])
    if packet.inclusion.height != entry["height"]:
        raise ValueError("confirmation height differs from the recorded block")
    return packet


def archive_packet(packet):
    return {
        "raw": packet.raw.hex(),
        "height": packet.inclusion.height,
        "index": packet.inclusion.index,
        "leaf_count": packet.inclusion.leaf_count,
        "siblings": [sibling.hex() for sibling in packet.inclusion.siblings],
    }
