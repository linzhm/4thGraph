"""Generate public, deterministic SDK integration vectors from project references."""
import argparse
from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from shared.benchmark_validation import Node, chain_verdict
from shared.sdk.python.bridge import PROJECTS, adapter_for
from shared.sdk.python.client import Client
from shared.transaction import Input, Output, Transaction


def generate(project, node):
    adapter = adapter_for(project)
    path = ROOT / "projects" / project / "sdk/fixture.py"
    spec = spec_from_file_location("sdk_fixture", path)
    fixture = module_from_spec(spec)
    spec.loader.exec_module(fixture)
    vectors = []
    python_sdk = spec_from_file_location("project_sdk", path.parent / "python/__init__.py")
    entry = module_from_spec(python_sdk)
    python_sdk.loader.exec_module(entry)
    client = entry.create_client()
    assert isinstance(client, Client)
    for case in fixture.cases():
        key = case["public_key"]
        profile = case["profile"]
        lock = adapter.lock(key, profile)
        if "bytes" in case:
            assert len(lock) == case["bytes"]
        funding = Transaction((Input(bytes([17 + len(vectors)]) * 32, 0),), (Output(10_000, lock),))
        outputs = (Output(9_900, case.get("destination", b"\x51")),)
        tx = Transaction((Input(funding.txid_wire(), 0),), outputs)
        sighash = case.get("sighash", 0x41)
        active = bool(sighash & 0x20)
        compress = case.get("compress_otda", False)
        signer_id = case.get("signer_identifier")
        options = dict(chronicleActive=active, compressOtda=compress)
        if signer_id is not None:
            options["signerIdentifier"] = signer_id
        calls = []

        def fixture_signer(*arguments):
            result = case["signer"](*arguments)
            calls.append((arguments, result))
            return result

        signed = adapter.sign_spend(tx, 0, funding.serialize(), key, fixture_signer, sighash, options)
        (arguments, signature), = calls
        assert chain_verdict(signed, (funding,))
        if node:
            assert node.verdicts(signed, (funding,)) == [True]

        def replay_signer(*supplied):
            assert supplied == arguments
            return signature

        callback_options = dict(sighash=sighash, chronicle_active=active, compress_otda=compress,
                                signer_identifier=signer_id)
        assert client.lock(key, profile=profile) == lock
        recognized = adapter.recognize(lock, key)
        assert client.recognize(lock, public_key=key) == recognized
        if owner := recognized.get("ownerHash160"):
            assert client.lock_for_owner(bytes.fromhex(owner)) == lock
        assert client.sign_spend(tx.serialize(), funding.serialize(), 0, key, replay_signer,
                                 **callback_options) == signed.serialize()
        assert client.sign_payment(funding.serialize(), 0, [(out.value, out.script) for out in outputs],
                                   100, key, replay_signer, **callback_options) == signed.serialize()
        vectors.append({
            "profile": profile, "lock": lock.hex(), "recognition": recognized,
            "request": {"funding": funding.serialize().hex(), "index": 0, "publicKey": key.hex(),
                        "transaction": tx.serialize().hex(), "sighash": sighash, **options},
            "outputs": [{"valueSats": str(out.value), "script": out.script.hex()} for out in outputs],
            "arguments": [arg.hex() for arg in arguments], "signature": signature.hex(),
            "signed": signed.serialize().hex(),
        })
        if signer_id is not None:
            vectors[-1]["request"]["signerIdentifier"] = signer_id.hex()
    return vectors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", choices=sorted(PROJECTS))
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"]) if "REGTEST_COOKIE" in os.environ else None
    vectors = generate(args.project, node)
    args.output.write_text(json.dumps(vectors), encoding="utf-8")
    print(f"{args.project}: {len(vectors)} Python SDK vectors passed, {'both engines' if node else 'chain-gang'}")


if __name__ == "__main__":
    main()
