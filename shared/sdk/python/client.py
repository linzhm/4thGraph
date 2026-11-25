"""Python client for the local wallet bridge. Signers remain in the caller."""
from collections.abc import Callable
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
                   compress_otda: bool = False, signer_identifier: bytes | None = None) -> bytes:
        request = dict(transaction=transaction.hex(), funding=funding.hex(), index=index, publicKey=public_key.hex(),
                       sighash=sighash, chronicleActive=chronicle_active, compressOtda=compress_otda)
        if signer_identifier is not None:
            request["signerIdentifier"] = signer_identifier.hex()
        return self._sign(request, signer)

    def sign_payment(self, funding: bytes, vout: int, outputs, fee_sats: int, public_key: bytes,
                     signer: Callable[..., bytes], *, sighash: int = 0x41, chronicle_active: bool = False,
                     compress_otda: bool = False, signer_identifier: bytes | None = None) -> bytes:
        request = dict(funding=funding.hex(), index=vout, publicKey=public_key.hex(), feeSats=str(fee_sats),
                       outputs=[dict(valueSats=str(amount), script=script.hex()) for amount, script in outputs],
                       sighash=sighash, chronicleActive=chronicle_active, compressOtda=compress_otda)
        if signer_identifier is not None:
            request["signerIdentifier"] = signer_identifier.hex()
        return self._sign(request, signer)
