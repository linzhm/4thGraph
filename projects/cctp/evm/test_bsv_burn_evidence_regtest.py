"""Exercise the outbound observation boundary against a disposable BSV Node."""

import os
from pathlib import Path
import unittest
from hashlib import new, sha256

from ecdsa import SECP256k1, SigningKey

from burn_receipt import BurnReceipt
from regtest_mint import Node, base58check, sign_p2pkh
from shared.transaction import Input, Output, Transaction
from statement import AssetDescriptor

from projects.cctp.evm.bsv_burn_evidence import (
    BsvConfirmationPolicy, BurnEvidenceError, BurnReference, read_confirmed_burn,
)
from projects.cctp.evm.release_adapter import ReleaseEvidenceError, authorize_release
from projects.cctp.evm.reserve_rpc import ReserveScope


def _address(signer):
    pubkey = signer.verifying_key.to_string("compressed")
    return base58check(b"\x6f" + new("ripemd160", sha256(pubkey).digest()).digest())


@unittest.skipUnless(os.environ.get("CCTP_RELEASE_BSV_COOKIE"), "requires a disposable BSV regtest")
class BsvBurnEvidenceRegtest(unittest.TestCase):
    def test_bsv_confirmation_and_reorg_do_not_confer_provenance(self):
        node = Node(os.environ.get("CCTP_RELEASE_BSV_RPC", "http://127.0.0.1:19446"),
                    Path(os.environ["CCTP_RELEASE_BSV_COOKIE"]))
        signer = SigningKey.from_secret_exponent(11, curve=SECP256k1)  # Public fixture key.
        address = _address(signer)
        funding = node.fund(address)
        asset = AssetDescriptor(1, b"i" * 36, 6, 7, bytes(12) + b"u" * 20, b"p" * 32)
        scope = ReserveScope(31337, 7, 1, b"v" * 20, b"u" * 20, asset.asset_id())
        receipt = BurnReceipt(asset.asset_id(), 7, b"r" * 20, 640)
        # A bare receipt is valid BSV data and has no authentic token provenance.
        tx = Transaction((Input(funding.txid_wire(), 0),), (Output(100_000_000, b"\x51"), receipt.output()))
        signed = sign_p2pkh(tx, funding, 0, signer)
        node.confirm(signed, address)
        confirmed_hash = node.call("getrawtransaction", signed.txid(), True)["blockhash"]
        confirmed_height = node.call("getblock", confirmed_hash, 1)["height"]
        policy = BsvConfirmationPolicy(
            1, "regtest", bytes.fromhex(node.call("getblockhash", 0))[::-1], 2,
        )
        reference = BurnReference(signed.txid_wire(), 1, bytes.fromhex(confirmed_hash)[::-1], confirmed_height)
        with self.assertRaisesRegex(BurnEvidenceError, "confirmation policy"):
            read_confirmed_burn(node.call, policy, reference, asset)

        node.call("generatetoaddress", 1, address)
        observed = read_confirmed_burn(node.call, policy, reference, asset)
        self.assertEqual(observed.transaction, signed)
        self.assertEqual(observed.receipt, receipt)
        self.assertGreaterEqual(observed.confirmations, 2)

        def unexpected_call(*_):
            self.fail("unproven BSV burn reached the reserve or the release signer")

        with self.assertRaisesRegex(ReleaseEvidenceError, "provenance was not authenticated"):
            authorize_release(node.call, unexpected_call, policy, scope, asset, reference,
                              verify_provenance=lambda *_: False, sign_digest=unexpected_call)

        node.call("invalidateblock", confirmed_hash)
        replacement_address = _address(SigningKey.from_secret_exponent(12, curve=SECP256k1))
        node.call("generatetoaddress", 2, replacement_address)
        with self.assertRaisesRegex(BurnEvidenceError, "changed on the active BSV chain"):
            read_confirmed_burn(node.call, policy, reference, asset)


if __name__ == "__main__":
    unittest.main()
