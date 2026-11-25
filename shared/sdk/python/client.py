"""Python client for the local wallet bridge. Signers remain in the caller."""
from collections.abc import Callable
from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
import sys


class Client:
    def __init__(self, project: str, *, python: str = sys.executable, bridge: Path | None = None):
        self._project = project
        self._command = [python, str(bridge or Path(__file__).with_name("bridge.py"))]

    def _call(self, operation, request, **extra):
        message = dict(protocol=1, project=self._project, operation=operation, request=request, **extra)
        completed = subprocess.run(self._command, input=json.dumps(message), capture_output=True,
                                   text=True, check=False)
        if completed.returncode:
            raise RuntimeError(f"local SDK bridge exited with code {completed.returncode}")
        reply = json.loads(completed.stdout)
        if not reply["ok"]:
            raise ValueError(reply["error"])
        return reply["result"]

    def lock(self, public_key: bytes, *, profile=None) -> bytes:
        options = dict(publicKey=public_key.hex())
        if profile is not None:
            options["profile"] = profile
        return bytes.fromhex(self._call("lock", options))

    def lock_for_owner(self, owner_hash160: bytes) -> bytes:
        return bytes.fromhex(self._call("lockOwner", {"ownerHash160": owner_hash160.hex()}))

    def recognize(self, script: bytes, *, public_key: bytes | None = None) -> dict | None:
        options = dict(script=script.hex())
        if public_key is not None:
            options["publicKey"] = public_key.hex()
        return self._call("recognize", options)

    def _sign(self, request, signer: Callable[..., bytes]) -> bytes:
        arguments = self._call("prepare", request)
        signature = signer(*(bytes.fromhex(value) for value in arguments))
        if not isinstance(signature, bytes):
            raise TypeError("the signer must return bytes")
        return bytes.fromhex(self._call("finish", request, arguments=arguments, signature=signature.hex()))

    def sign_spend(self, transaction: bytes, funding: bytes, index: int, public_key: bytes,
                   signer: Callable[..., bytes], *, sighash: int = 0x41, chronicle_active: bool = False,
                   compress_otda: bool | None = None, signer_identifier: bytes | None = None) -> bytes:
        request = dict(transaction=transaction.hex(), funding=funding.hex(), index=index, publicKey=public_key.hex(),
                       sighash=sighash, chronicleActive=chronicle_active)
        if compress_otda is not None:
            request["compressOtda"] = compress_otda
        if signer_identifier is not None:
            request["signerIdentifier"] = signer_identifier.hex()
        return self._sign(request, signer)

    def sign_payment(self, funding: bytes, vout: int, outputs, fee_sats: int, public_key: bytes,
                     signer: Callable[..., bytes], *, sighash: int = 0x41, chronicle_active: bool = False,
                     compress_otda: bool | None = None, signer_identifier: bytes | None = None) -> bytes:
        request = dict(funding=funding.hex(), index=vout, publicKey=public_key.hex(), feeSats=str(fee_sats),
                       outputs=[dict(valueSats=str(amount), script=script.hex()) for amount, script in outputs],
                       sighash=sighash, chronicleActive=chronicle_active)
        if compress_otda is not None:
            request["compressOtda"] = compress_otda
        if signer_identifier is not None:
            request["signerIdentifier"] = signer_identifier.hex()
        return self._sign(request, signer)


@dataclass(frozen=True)
class Prevout:
    txid: str
    vout: int
    value_sats: int
    script: bytes

    def request(self):
        return dict(txid=self.txid, vout=self.vout, valueSats=str(self.value_sats), script=self.script.hex())


@dataclass(frozen=True)
class SigningRequest:
    algorithm: str
    payload_kind: str
    signature_format: str
    sighash: int
    payload: bytes
    user_id: bytes | None = None


class WalletClient:
    def __init__(self, project: str, *, template: str | None = None,
                 python: str = sys.executable, bridge: Path | None = None):
        self._bridge = Client(project, python=python, bridge=bridge)
        self._template = template

    def prevout_from_funding(self, funding: bytes, vout: int) -> Prevout:
        result = self._bridge._call("prevoutFromFunding", dict(funding=funding.hex(), vout=vout))
        return Prevout(result["txid"], result["vout"], int(result["valueSats"]), bytes.fromhex(result["script"]))

    def create_lock(self, *, public_key: bytes | None = None, owner_hash160: bytes | None = None,
                    value_sats: int | None = None) -> bytes:
        request = dict(template=self._template)
        if public_key is not None:
            request["publicKey"] = public_key.hex()
        if owner_hash160 is not None:
            request["ownerHash160"] = owner_hash160.hex()
        if value_sats is not None:
            request["valueSats"] = str(value_sats)
        return bytes.fromhex(self._bridge._call("createLock", request))

    def recognize(self, script: bytes, *, public_key: bytes | None = None, value_sats: int | None = None) -> dict | None:
        request = dict(script=script.hex())
        if public_key is not None:
            request["publicKey"] = public_key.hex()
        if value_sats is not None:
            request["valueSats"] = str(value_sats)
        return self._bridge._call("recognizeLock", request)

    def _sign(self, request, key: bytes, signer: Callable[[SigningRequest], bytes], *,
              sighash: int = 0x41, chronicle_active: bool = False, compress_otda: bool | None = None,
              signer_identifier: bytes | None = None, history_path: Path | None = None,
              sign_message: bool = False) -> bytes:
        request.update(publicKey=key.hex(), sighash=sighash, chronicleActive=chronicle_active,
                       signMessage=sign_message)
        if compress_otda is not None:
            request["compressOtda"] = compress_otda
        if signer_identifier is not None:
            request["signerIdentifier"] = signer_identifier.hex()
        if history_path is not None:
            request["historyPath"] = str(history_path)
        prepared = self._bridge._call("prepareWallet", request)
        arguments = prepared["arguments"]
        payload, *aux = (bytes.fromhex(value) for value in arguments)
        signing_request = SigningRequest(prepared["algorithm"], prepared["payloadKind"],
                                        prepared["signatureFormat"], prepared["sighash"],
                                        payload, aux[0] if aux else None)
        signature = signer(signing_request)
        if not isinstance(signature, bytes):
            raise TypeError("the signer must return bytes")
        return bytes.fromhex(self._bridge._call("finishWallet", request, arguments=arguments,
                                                signature=signature.hex()))

    def sign_payment(self, prevout: Prevout, outputs, fee_sats: int, public_key: bytes,
                     signer: Callable[[SigningRequest], bytes], **options) -> bytes:
        request = dict(prevout=prevout.request(), feeSats=str(fee_sats),
                       outputs=[dict(valueSats=str(amount), script=script.hex()) for amount, script in outputs])
        return self._sign(request, public_key, signer, **options)

    def sign_input(self, transaction: bytes, input_index: int, prevout: Prevout, public_key: bytes,
                   signer: Callable[[SigningRequest], bytes], **options) -> bytes:
        request = dict(transaction=transaction.hex(), inputIndex=input_index, prevout=prevout.request())
        return self._sign(request, public_key, signer, **options)

    def activate(self, transaction: bytes, input_index: int, prevout: Prevout, *,
                 sighash: int = 0x43, chronicle_active: bool = False) -> bytes:
        request = dict(transaction=transaction.hex(), inputIndex=input_index, prevout=prevout.request(),
                       sighash=sighash, chronicleActive=chronicle_active)
        return bytes.fromhex(self._bridge._call("activate", request))
