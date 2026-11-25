"""Local JSON bridge for wallet SDKs that share the Script Lab reference code."""
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from shared.transaction import CHRONICLE, SIGHASH_TYPES, Input, Output, Transaction, amount  # noqa: E402

PROJECTS = frozenset(("p2pk-p2pkh-baseline", "p2pkh-sm2", "lamport-ots", "wots-plus", "ml-dsa"))
PROTOCOL = 1


def hex_bytes(value):
    if not isinstance(value, str) or re.fullmatch(r"(?:[0-9a-fA-F]{2})*", value) is None:
        raise ValueError("expected an even-length unprefixed hex string")
    return bytes.fromhex(value)


def sats(value):
    if not isinstance(value, str) or re.fullmatch(r"0|[1-9][0-9]{0,15}", value) is None:
        raise ValueError("expected a canonical decimal satoshi string")
    result = int(value)
    amount(result)
    return result


def boolean(options, name):
    value = options.get(name, False)
    if type(value) is not bool:
        raise ValueError(f"{name} must be a boolean")
    return value


def adapter_for(project):
    if project not in PROJECTS:
        raise ValueError("unknown SDK project")
    root = ROOT / "projects" / project
    spec = spec_from_file_location("sdk_adapter", root / "sdk/adapter.py")
    adapter = module_from_spec(spec)
    # Each request gets its own process and one project's reference modules.
    sys.path.insert(0, str(root / "reference"))
    spec.loader.exec_module(adapter)
    return adapter


class NeedsSignature(Exception):
    def __init__(self, *values):
        self.arguments = [value.hex() for value in values]


def prepared_transaction(options, funding):
    index = options.get("index")
    if type(index) is not int or index < 0:
        raise ValueError("index must be a nonnegative integer")
    if "transaction" in options:
        tx = Transaction.parse(hex_bytes(options["transaction"]))
        if index >= len(tx.inputs):
            raise ValueError("input index out of range")
        current = tx.inputs[index]
        if current.script:
            raise ValueError("selected input already has an unlocking script")
        if current.txid != funding.txid_wire() or current.vout >= len(funding.outputs):
            raise ValueError("funding outpoint does not match selected input")
        if not tx.outputs:
            raise ValueError("payment requires outputs")
        return tx, index
    if index >= len(funding.outputs):
        raise ValueError("funding output index out of range")
    values = options["outputs"]
    if not isinstance(values, list) or not values:
        raise ValueError("payment requires outputs")
    outputs = tuple(Output(sats(out["valueSats"]), hex_bytes(out["script"])) for out in values)
    fee = sats(options["feeSats"])
    if sum(out.value for out in outputs) + fee != funding.outputs[index].value:
        raise ValueError("outputs and fee must equal the funding amount")
    return Transaction((Input(funding.txid_wire(), index),), outputs), 0


def run(message):
    if not isinstance(message, dict) or type(message.get("protocol")) is not int or message["protocol"] != PROTOCOL:
        raise ValueError("unsupported SDK bridge protocol")
    project = message["project"]
    adapter = adapter_for(project)
    operation = message["operation"]
    options = message["request"]
    if not isinstance(options, dict):
        raise ValueError("request must be an object")
    if operation == "lock":
        return adapter.lock(hex_bytes(options["publicKey"]), options.get("profile")).hex()
    if operation == "lockOwner":
        if project not in ("p2pkh-sm2", "p2pk-p2pkh-baseline"):
            raise ValueError("this SDK project requires the full public key to create a lock")
        return adapter.lock_owner(hex_bytes(options["ownerHash160"])).hex()
    if operation == "recognize":
        key = hex_bytes(options["publicKey"]) if "publicKey" in options else None
        return adapter.recognize(hex_bytes(options["script"]), key)
    if operation not in ("prepare", "finish"):
        raise ValueError("unknown SDK operation")

    funding_raw = hex_bytes(options["funding"])
    tx, index = prepared_transaction(options, Transaction.parse(funding_raw))
    sighash = options.get("sighash", 0x41)
    if type(sighash) is not int or sighash not in SIGHASH_TYPES:
        raise ValueError("unsupported sighash")
    chronicle_active = boolean(options, "chronicleActive")
    compress = boolean(options, "compressOtda")
    if sighash & CHRONICLE and not chronicle_active:
        raise ValueError("Chronicle authorization requires an active spend context")
    if compress and project != "wots-plus":
        raise ValueError("this SDK project does not support OTDA reconstruction")
    if compress and not chronicle_active:
        raise ValueError("functional unlocking requires an active spend context")
    if "signerIdentifier" in options:
        if project != "p2pkh-sm2":
            raise ValueError("signerIdentifier is only used for SM2 SignedData authorization")
        options["signerIdentifier"] = hex_bytes(options["signerIdentifier"])

    def signer(*args):
        if operation == "prepare":
            raise NeedsSignature(*args)
        if [arg.hex() for arg in args] != message["arguments"]:
            raise ValueError("signing arguments changed between prepare and finish")
        return hex_bytes(message["signature"])

    try:
        tx = adapter.sign_spend(tx, index, funding_raw, hex_bytes(options["publicKey"]),
                                signer, sighash, options)
    except NeedsSignature as request:
        return request.arguments
    if operation != "finish":
        raise RuntimeError("reference signer returned without requesting a signature")
    return tx.serialize().hex()


def main():
    try:
        result = run(json.load(sys.stdin))
        response = {"ok": True, "result": result}
    except (ValueError, KeyError, TypeError, OverflowError, OSError, RuntimeError) as error:
        response = {"ok": False, "error": str(error)}
    print(json.dumps(response, separators=(",", ":")))


if __name__ == "__main__":
    main()
