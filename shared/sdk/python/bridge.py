"""Local JSON bridge for wallet SDKs that share the Script Lab reference code."""
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from shared.transaction import (  # noqa: E402
    CHRONICLE, SIGHASH_SINGLE, SIGHASH_TYPES, Input, Output, Transaction, amount,
)

PROJECTS = frozenset(("p2pk-p2pkh-baseline", "p2pkh-sm2", "lamport-ots", "wots-plus", "ml-dsa"))
WALLET_PROJECTS = PROJECTS | {"p2pkh-r1", "p2pkh-r1-deferred"}
SIGNATURE_FORMATS = {
    "p2pk-p2pkh-baseline": ("ecdsa-secp256k1", "der-low-s"),
    "p2pkh-r1": ("ecdsa-p256", "raw-rs"),
    "p2pkh-sm2": ("sm2", "raw-rs"),
    "lamport-ots": ("lamport-ots", "raw"),
    "wots-plus": ("wots-plus", "raw"),
    "ml-dsa": ("pure-ml-dsa-44", "raw"),
}
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
    if project not in WALLET_PROJECTS:
        raise ValueError("unknown SDK project")
    root = ROOT / "projects" / project
    spec = spec_from_file_location("sdk_adapter", root / "reference/sdk_adapter.py")
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


def signing_options(project, options, default=0x41):
    sighash = options.get("sighash", default)
    if type(sighash) is not int or sighash not in SIGHASH_TYPES:
        raise ValueError("unsupported sighash")
    chronicle_active = boolean(options, "chronicleActive")
    compress = boolean(options, "compressOtda")
    if sighash & CHRONICLE and not chronicle_active:
        raise ValueError("Chronicle authorization requires an active spend context")
    if compress and project not in ("p2pkh-sm2", "wots-plus", "p2pkh-r1"):
        raise ValueError("this SDK project does not support OTDA reconstruction")
    if compress and not chronicle_active:
        raise ValueError("functional unlocking requires an active spend context")
    if "signerIdentifier" in options:
        if project != "p2pkh-sm2":
            raise ValueError("signerIdentifier is only used for SM2 SignedData authorization")
        options["signerIdentifier"] = hex_bytes(options["signerIdentifier"])

    if boolean(options, "signMessage") and project != "p2pkh-r1":
        raise ValueError("signMessage is only used for P-256 devices that hash internally")
    return sighash


def uint32(value, name):
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"{name} must be an unsigned 32-bit integer")
    return value


def wallet_transaction(options):
    prevout = options["prevout"]
    txid = hex_bytes(prevout["txid"])
    if len(txid) != 32:
        raise ValueError("expected a 32-byte txid in display order")
    outpoint = Input(txid[::-1], uint32(prevout["vout"], "vout"))
    previous = Output(sats(prevout["valueSats"]), hex_bytes(prevout["script"]))
    if "transaction" in options:
        if "outputs" in options or "feeSats" in options:
            raise ValueError("prepared transaction and payment fields cannot be combined")
        tx = Transaction.parse(hex_bytes(options["transaction"]))
        index = uint32(options["inputIndex"], "inputIndex")
        if index >= len(tx.inputs):
            raise ValueError("input index out of range")
        current = tx.inputs[index]
        if current.script or current.outpoint() != outpoint.outpoint():
            raise ValueError("select an unsigned input matching the prevout")
        if not tx.outputs:
            raise ValueError("payment requires outputs")
        return tx, index, previous

    if "inputIndex" in options:
        raise ValueError("a prepared input requires a transaction")
    outputs = tuple(Output(sats(out["valueSats"]), hex_bytes(out["script"])) for out in options["outputs"])
    if not outputs:
        raise ValueError("payment requires outputs")
    if sum(out.value for out in outputs) + sats(options["feeSats"]) != previous.value:
        raise ValueError("outputs and fee must equal the funding amount")
    return Transaction((outpoint,), outputs), 0, previous


def run_wallet(project, adapter, operation, options, message):
    if operation == "prevoutFromFunding":
        funding = Transaction.parse(hex_bytes(options["funding"]))
        vout = uint32(options["vout"], "vout")
        if vout >= len(funding.outputs):
            raise ValueError("funding output index out of range")
        previous = funding.outputs[vout]
        return {"txid": funding.txid(), "vout": vout, "valueSats": str(previous.value),
                "script": previous.script.hex()}
    if operation == "createLock":
        key = "publicKey" in options
        if key == ("ownerHash160" in options):
            raise ValueError("provide either a public key or an owner hash")
        profile = options.get("template")
        if not key and not hasattr(adapter, "lock_owner"):
            raise ValueError("this SDK project requires a full public key")
        args = (profile, sats(options["valueSats"])) if project == "p2pkh-r1-deferred" else (profile,)
        if key:
            return adapter.lock(hex_bytes(options["publicKey"]), *args).hex()
        return adapter.lock_owner(hex_bytes(options["ownerHash160"]), *args).hex()
    if operation == "recognizeLock":
        key = hex_bytes(options["publicKey"]) if "publicKey" in options else None
        args = (sats(options["valueSats"]),) if project == "p2pkh-r1-deferred" else ()
        details = {"include_public_key": True} if project == "p2pk-p2pkh-baseline" else {}
        result = adapter.recognize(hex_bytes(options["script"]), key, *args, **details)
        return None if result is None else {"project": project, **result}

    tx, index, previous = wallet_transaction(options)
    if operation == "activate":
        if project != "p2pkh-r1-deferred" or "transaction" not in options:
            raise ValueError("activation requires a prepared Deferred transaction")
        sighash = signing_options(project, options, default=0x43)
        return adapter.activate_previous(tx, index, previous, sighash=sighash).serialize().hex()
    if project == "p2pkh-r1-deferred":
        raise ValueError("use activate for a Deferred input")
    sighash = signing_options(project, options)
    if sighash & 31 == SIGHASH_SINGLE and index >= len(tx.outputs):
        raise ValueError("wallet SINGLE requires a same-index output")

    algorithm, fmt = SIGNATURE_FORMATS[project]
    if "signerIdentifier" in options:
        fmt = "signed-data"
    is_message = project in ("p2pkh-sm2", "ml-dsa") or options.get("signMessage", False)
    metadata = {"algorithm": algorithm, "payloadKind": "message" if is_message else "digest",
                "signatureFormat": fmt, "sighash": sighash}
    public_key = hex_bytes(options["publicKey"])

    return authorize_signature(
        message, operation == "prepareWallet",
        lambda signer: adapter.sign_previous(tx, index, previous, public_key, signer, sighash, options),
        metadata=metadata,
    )


def authorize_signature(message, prepare, authorize, *, metadata=None):
    def signer(*args):
        if prepare:
            raise NeedsSignature(*args)
        if [arg.hex() for arg in args] != message["arguments"]:
            raise ValueError("signing arguments changed between prepare and finish")
        return hex_bytes(message["signature"])

    try:
        signed = authorize(signer)
    except NeedsSignature as request:
        return request.arguments if metadata is None else {**metadata, "arguments": request.arguments}
    if prepare:
        raise RuntimeError("reference signer returned without requesting a signature")
    return signed.serialize().hex()


def run(message):
    if not isinstance(message, dict) or type(message.get("protocol")) is not int or message["protocol"] != PROTOCOL:
        raise ValueError("unsupported SDK bridge protocol")
    project = message["project"]
    adapter = adapter_for(project)
    operation = message["operation"]
    options = message["request"]
    if not isinstance(options, dict):
        raise ValueError("request must be an object")
    if operation in ("prevoutFromFunding", "createLock", "recognizeLock", "activate", "prepareWallet", "finishWallet"):
        return run_wallet(project, adapter, operation, options, message)
    if project not in PROJECTS:
        raise ValueError("use the unified wallet API for this project")
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
    sighash = signing_options(project, options)

    public_key = hex_bytes(options["publicKey"])
    return authorize_signature(
        message, operation == "prepare",
        lambda signer: adapter.sign_spend(tx, index, funding_raw, public_key, signer, sighash, options),
    )


def main():
    try:
        result = run(json.load(sys.stdin))
        response = {"ok": True, "result": result}
    except (ValueError, KeyError, TypeError, OverflowError, OSError, RuntimeError) as error:
        response = {"ok": False, "error": str(error)}
    print(json.dumps(response, separators=(",", ":")))


if __name__ == "__main__":
    main()
