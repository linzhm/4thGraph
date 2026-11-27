"""Build a synthetic BRC-29 spend with the 4thGraph wallet SDK."""

import json
import sys

from bsv.keys import PrivateKey
from bsv.script import Spend
from bsv.transaction import Transaction as BsvTransaction
from bsv.wallet import Counterparty, CounterpartyType, KeyDeriver
from bsv_wallet_toolbox.brc29 import PROTOCOL, KeyID, lock_for_counterparty

from fourthgraph.bsv.transaction import Input, Output, Transaction
from sdk.python.client import WalletClient


def main():
    # Public fixture keys for a synthetic funding output.
    sender = PrivateKey.from_hex(f"{1:064x}")
    recipient = PrivateKey.from_hex(f"{2:064x}")
    sender_public_key = sender.public_key()
    recipient_public_key = recipient.public_key()
    key_id = KeyID(derivation_prefix="fourthgraph", derivation_suffix="payment")
    derived_key = KeyDeriver(recipient).derive_private_key(
        PROTOCOL, str(key_id), Counterparty(CounterpartyType.OTHER, sender_public_key),
    )
    public_key = derived_key.public_key().serialize()

    wallet = WalletClient("p2pk-p2pkh-baseline", template="p2pkh")
    lock = wallet.create_lock(public_key=public_key)
    toolbox_lock = lock_for_counterparty(sender, key_id, recipient_public_key)
    if lock.hex() != toolbox_lock.hex():
        raise RuntimeError("The derived BRC-29 scripts differ")

    funding = Transaction((Input(b"\x17" * 32, 0),), (Output(10_000, lock),))
    funding_raw = funding.serialize()
    prevout = wallet.prevout_from_funding(funding_raw, 0)
    signed_raw = wallet.sign_payment(
        prevout, [(9_900, b"\x51")], 100, public_key,
        lambda request: derived_key.sign(request.payload, hasher=None),
    )
    parent = BsvTransaction.from_hex(funding_raw.hex())
    signed = BsvTransaction.from_hex(signed_raw.hex())
    if parent is None or signed is None or signed.hex() != signed_raw.hex():
        raise RuntimeError("Python BSV SDK could not round-trip the payment")
    (tx_input,) = signed.inputs
    if tx_input.source_txid != parent.txid() or tx_input.source_output_index != 0:
        raise RuntimeError("The payment does not spend the fixture output")
    spend = Spend({
        "sourceTXID": parent.txid(),
        "sourceOutputIndex": 0,
        "sourceSatoshis": parent.outputs[0].satoshis,
        "lockingScript": parent.outputs[0].locking_script,
        "transactionVersion": signed.version,
        "otherInputs": [],
        "inputIndex": 0,
        "unlockingScript": tx_input.unlocking_script,
        "outputs": signed.outputs,
        "inputSequence": tx_input.sequence,
        "lockTime": signed.locktime,
    })
    if not spend.validate():
        raise RuntimeError("Python BSV SDK rejected the spending script")
    txid = signed.txid()
    print(json.dumps({
        "senderTestKey": sender.hex(),
        "recipientPublicKey": recipient_public_key.hex(),
        "derivationPrefix": key_id.derivation_prefix,
        "derivationSuffix": key_id.derivation_suffix,
        "funding": funding_raw.hex(),
        "signed": signed_raw.hex(),
        "txid": txid,
    }, indent=2))
    print(f"Python SDK and Wallet Toolbox: {txid}", file=sys.stderr)


if __name__ == "__main__":
    main()
