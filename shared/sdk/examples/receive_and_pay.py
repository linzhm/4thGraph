"""Create, recognize and spend a synthetic output using a public test key."""

import argparse
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import sys

from shared.sdk.python.bridge import PROJECTS
from shared.sdk.python.client import WalletClient
from shared.transaction import Input, Output, Transaction


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", nargs="?", default="p2pk-p2pkh-baseline", choices=sorted(PROJECTS))
    project = parser.parse_args().project

    root = Path(__file__).resolve().parents[3]
    reference = root / "projects" / project / "reference"
    sys.path.insert(0, str(reference))
    spec = spec_from_file_location("sdk_fixture", reference / "sdk_fixture.py")
    fixture = module_from_spec(spec)
    spec.loader.exec_module(fixture)
    case = next(case for case in fixture.cases() if case["sighash"] == 0x41)

    wallet = WalletClient(project, template=case["profile"])
    public_key = case["public_key"]
    lock = wallet.create_lock(public_key=public_key)
    funding = Transaction((Input(b"\x17" * 32, 0),), (Output(10_000, lock),))
    prevout = wallet.prevout_from_funding(funding.serialize(), 0)
    recognized = wallet.recognize(prevout.script, public_key=public_key)
    if not recognized or recognized["template"] != case["profile"]:
        raise RuntimeError("the SDK did not recognize its own receiving script")

    def sign_fixture(request):
        if request.user_id is None:
            return case["signer"](request.payload)
        return case["signer"](request.payload, request.user_id)

    # OP_TRUE stands in for the payment recipient in this synthetic example.
    destination = Output(9_900, b"\x51")
    signed = wallet.sign_payment(prevout, [(destination.value, destination.script)], 100, public_key, sign_fixture)
    transaction = Transaction.parse(signed)
    (spend,) = transaction.inputs
    if spend.txid != funding.txid_wire() or spend.vout != 0 or not spend.script:
        raise RuntimeError("the signed input does not spend the example funding output")
    if transaction.outputs != (destination,):
        raise RuntimeError("the signed transaction does not contain the approved output")

    print(json.dumps({
        "project": project,
        "template": recognized["template"],
        "lockBytes": len(lock),
        "signedTransactionBytes": len(signed),
        "transactionId": transaction.txid(),
    }, indent=2))


if __name__ == "__main__":
    main()
