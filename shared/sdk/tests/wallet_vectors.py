"""Replay the unified wallet API against public reference vectors."""
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import sys

from vector import Node, adapter_for, chain_verdict, generate
from shared.sdk.python.client import WalletClient
from shared.script import push
from shared.transaction import Input, Output, Transaction

CALLBACKS = {
    "p2pk-p2pkh-baseline": ("ecdsa-secp256k1", "digest", "der-low-s"),
    "p2pkh-r1": ("ecdsa-p256", "digest", "raw-rs"),
    "p2pkh-sm2": ("sm2", "message", "raw-rs"),
    "p2pkh-schnorr": ("schnorr-secp256k1", "message", "bip340"),
    "lamport-ots": ("lamport-ots", "digest", "raw"),
    "wots-plus": ("wots-plus", "digest", "raw"),
    "ml-dsa": ("pure-ml-dsa-44", "message", "raw"),
}


def r1_vectors(project, directory, node):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    adapter = adapter_for(project)
    private = ec.derive_private_key(5, ec.SECP256R1())
    public_key = private.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint,
    )
    deferred = project == "p2pkh-r1-deferred"
    layouts = [("v0.2.0", False), ("v0.1.0", False)]
    if deferred:
        layouts.append(("v0.1.0", True))
    for profile, embedded_key in layouts:
        yield from r1_layout_vectors(project, directory, node, adapter, private, public_key,
                                     profile, embedded_key)


def r1_layout_vectors(project, directory, node, adapter, private, public_key, profile, embedded_key):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from tx_engine import Tx

    deferred = project == "p2pkh-r1-deferred"
    existing_output = deferred and profile == "v0.1.0"
    value = 10_000
    if existing_output:
        from deferred import funding_output
        lock = funding_output(value, public_key, target_r1_version="0.1.0").script
        if embedded_key:
            lock = push(public_key) + lock[21:]
    elif deferred:
        lock = adapter.lock(public_key, profile, value)
    else:
        lock = adapter.lock(public_key, profile)
    # Put the lock at vout 1 and spend it at input 0.
    funding = Transaction((Input(b"\xf1" * 32, 0),), (Output(1, b"\x51"), Output(value, lock)))
    vout = 1
    if deferred:
        # Keep the v0.2.0 acceptance domain independent of the production flag set.
        flags = (0x41, 0x42, 0x43, 0x61, 0x62, 0x63, 0xc1, 0xc2, 0xc3, 0xe1, 0xe2, 0xe3)
        if existing_output:
            flags = (0x43, 0x63)
        modes = [(flag, False) for flag in flags]
    else:
        modes = ((0x41, False), (0x41, True), (0x61, False))
    for sighash, sign_message in modes:
        compress = sighash == 0x61
        if deferred:
            from deferred import activate_input, target_output
            outputs = (target_output(value, public_key, target_r1_version=profile[1:]),)
        else:
            outputs = (Output(value - 100, lock if compress else b"\x51"),)
        tx = Transaction((Input(funding.txid_wire(), vout),), outputs)
        request = {
            "funding": funding.serialize().hex(), "transaction": tx.serialize().hex(),
            "publicKey": public_key.hex(), "sighash": sighash, "chronicleActive": bool(sighash & 0x20),
        }
        arguments = []
        signature = None
        if deferred:
            signed = activate_input(tx, 0, funding.serialize(), sighash=sighash)
            recognition = adapter.recognize(lock, public_key, value)
        else:
            from signature import authorization, current_input_unlock
            raw_tx = Tx.parse(tx.serialize())
            auth = authorization(raw_tx, 0, value, sighash)
            digest = sha256(auth.preimage).digest() if sign_message else auth.digest()
            arguments = [digest.hex()]
            der = private.sign(auth.digest(), ec.ECDSA(utils.Prehashed(hashes.SHA256()), deterministic_signing=True))
            r, s = utils.decode_dss_signature(der)
            signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
            witness = current_input_unlock(
                auth, public_key, signature, compress_otda_for=raw_tx if compress else None,
                shared_kernels=compress, paired_single_index=0 if compress else None,
            )
            signed = tx.with_script(0, bytes(witness.raw_serialize()))
            request.update(historyPath=str(directory / "r1-history.sqlite"), signMessage=sign_message,
                           compressOtda=compress)
            recognition = adapter.recognize(lock, public_key)
        assert chain_verdict(signed, (funding,))
        if node:
            assert node.verdicts(signed, (funding,)) == [True]
        yield {
            "profile": profile, "lock": lock.hex(), "recognition": recognition, "request": request, "vout": vout,
            "existingOutput": existing_output,
            "outputs": [dict(script=out.script.hex(), valueSats=str(out.value)) for out in outputs],
            "signature": signature.hex() if signature else None, "arguments": arguments,
            "signed": signed.serialize().hex(),
        }


def replay(project, rows):
    for row in rows:
        request = row["request"]
        funding = bytes.fromhex(request.pop("funding"))
        row["funding"] = funding.hex()
        row["vout"] = row.get("vout", 0)
        request["inputIndex"] = request.pop("index", 0)
        client = WalletClient(project, template=row["profile"])
        prevout = client.prevout_from_funding(funding, row["vout"])
        request["prevout"] = prevout.request()
        tx = bytes.fromhex(request["transaction"])
        key = bytes.fromhex(request["publicKey"])
        lock = bytes.fromhex(row["lock"])
        scoped = {"value_sats": prevout.value_sats} if project == "p2pkh-r1-deferred" else {}
        if not row.get("existingOutput"):
            assert client.create_lock(public_key=key, **scoped) == lock
        row["recognition"]["project"] = project
        if project == "p2pk-p2pkh-baseline" and row["profile"] == "p2pk":
            row["recognition"]["publicKey"] = key.hex()
        assert client.recognize(lock, public_key=key, **scoped) == row["recognition"]
        assert client.recognize(b"\x00" + lock[1:], public_key=key, **scoped) is None
        if (owner := row["recognition"].get("ownerHash160")) and not row.get("existingOutput"):
            assert client.create_lock(owner_hash160=bytes.fromhex(owner), **scoped) == lock
        if project == "p2pkh-r1-deferred":
            assert client.activate(tx, request["inputIndex"], prevout, sighash=request["sighash"],
                                   chronicle_active=request["chronicleActive"]).hex() == row["signed"]
            if request["sighash"] == 0x43:
                assert client.recognize(lock, public_key=key, value_sats=prevout.value_sats + 1) is None
                prepared = Transaction.parse(tx)
                target = prepared.outputs[0]
                changed_target = replace(prepared, outputs=(replace(target, value=target.value - 1),))
                try:
                    client.activate(changed_target.serialize(), request["inputIndex"], prevout)
                except ValueError as error:
                    assert "does not match the committed value and R1 script" in str(error)
                else:
                    raise AssertionError("Deferred activation accepted a different target amount")
            continue
        algorithm, kind, fmt = CALLBACKS[project]
        if request.get("signMessage"):
            kind = "message"
        if "signerIdentifier" in request:
            fmt = "signed-data"
        row["metadata"] = dict(algorithm=algorithm, payloadKind=kind, signatureFormat=fmt, sighash=request["sighash"])
        calls = 0

        def signer(prepared):
            nonlocal calls
            calls += 1
            assert (prepared.algorithm, prepared.payload_kind, prepared.signature_format, prepared.sighash) == (
                algorithm, kind, fmt, request["sighash"],
            )
            arguments = [prepared.payload.hex()]
            if prepared.user_id is not None:
                arguments.append(prepared.user_id.hex())
            assert arguments == row["arguments"]
            return bytes.fromhex(row["signature"])

        options = dict(sighash=request["sighash"], chronicle_active=request["chronicleActive"],
                       sign_message=request.get("signMessage", False))
        if "compressOtda" in request:
            options["compress_otda"] = request["compressOtda"]
        if "signerIdentifier" in request:
            options["signer_identifier"] = bytes.fromhex(request["signerIdentifier"])
        if "historyPath" in request:
            options["history_path"] = Path(request["historyPath"])
        outputs = [(int(out["valueSats"]), bytes.fromhex(out["script"])) for out in row["outputs"]]
        assert client.sign_input(tx, request["inputIndex"], prevout, key, signer, **options).hex() == row["signed"]
        assert client.sign_payment(prevout, outputs, 100, key, signer, **options).hex() == row["signed"]
        for sign in (lambda: client.sign_input(tx, 1, prevout, key, signer, **options),
                     lambda: client.sign_payment(prevout, outputs, 99, key, signer, **options)):
            try:
                sign()
            except ValueError:
                pass
            else:
                raise AssertionError("invalid input or fee accepted")
        assert calls == 2


if __name__ == "__main__":
    import os

    project, file = sys.argv[1:]
    path = Path(file).resolve()
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"]) if "REGTEST_COOKIE" in os.environ else None
    rows = (list(r1_vectors(project, path.parent, node)) if project.startswith("p2pkh-r1")
            else generate(project, node))
    replay(project, rows)
    path.write_text(json.dumps(rows), encoding="utf-8")
    print(f"{project}: {len(rows)} unified Python SDK vectors passed, {'both engines' if node else 'chain-gang'}")
