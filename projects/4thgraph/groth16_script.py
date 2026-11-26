"""Build BSV Script for a fixed BN254 Groth16 verification key and statement."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from compiler import PROJECT_NAME
from r1cs import FIELD, scalar
from protocol import FLAG, artifact_digest, authorize, is_compressed_public_key
from shared.script import asm

RUNAR_REVISION = "dbcc4269f8e0895c4738cf86948b05b7d62a2010"
BASE_FIELD = 21888242871839275222246405745257275088696311157297823662689037894645226208583
PUBLIC_COUNT = 5
ADAPTER = Path(__file__).resolve().parent / "proof/groth16/adapter.go"


def checked(command, *, cwd=None, env=None, stdin=None):
    result = subprocess.run(command, cwd=cwd, env=env, input=stdin, capture_output=True, text=True, check=False)
    if result.returncode:
        raise ValueError(f"{Path(command[0]).name} failed: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout


def build_adapter(repository, output, *, go="go"):
    repository = Path(repository).resolve()
    revision = checked(["git", "rev-parse", "HEAD"], cwd=repository).strip()
    if revision != RUNAR_REVISION or checked(["git", "status", "--porcelain", "-uno"], cwd=repository).strip():
        raise ValueError(f"expected an unmodified Rúnar checkout at {RUNAR_REVISION}")
    checked([go, "build", "-o", str(Path(output).resolve()), str(ADAPTER)], cwd=repository / "compilers/go",
            env={**os.environ, "GOWORK": str(repository / "go.work")})


def canonical(value, modulus):
    number = scalar(value)
    if not 0 <= number < modulus or str(number) != str(value):
        raise ValueError("noncanonical BN254 element")
    return number


def public_signals(raw):
    values = json.loads(raw)
    if not isinstance(values, list) or len(values) != PUBLIC_COUNT:
        raise ValueError(f"expected exactly {PUBLIC_COUNT} public scalars")
    return tuple(str(canonical(value, FIELD)) for value in values)


def g1(point):
    if not isinstance(point, list) or len(point) != 3 or point[2] != "1":
        raise ValueError("expected a snarkjs affine G1 point")
    return {name: str(canonical(coord, BASE_FIELD)) for name, coord in zip(("x", "y"), point[:2], strict=True)}


def g2(point, *, negate=False):
    # snarkjs JSON already orders Fp2 as (real, imaginary).
    if (not isinstance(point, list) or len(point) != 3 or point[2] != ["1", "0"]
            or any(not isinstance(pair, list) or len(pair) != 2 for pair in point[:2])):
        raise ValueError("expected a snarkjs affine G2 point")
    x, y = (tuple(canonical(coord, BASE_FIELD) for coord in pair) for pair in point[:2])
    if negate:
        y = tuple(-coord % BASE_FIELD for coord in y)
    return dict(zip(("x0", "x1", "y0", "y1"), map(str, (*x, *y)), strict=True))


def require_bn254(document):
    if document["protocol"] != "groth16" or document["curve"] != "bn128":
        raise ValueError("expected a snarkjs Groth16 artifact for BN254")


def runar_key(raw):
    document = json.loads(raw)
    require_bn254(document)
    if document["nPublic"] != PUBLIC_COUNT or len(document["IC"]) != PUBLIC_COUNT + 1:
        raise ValueError("verification key must have five public inputs and six IC points")
    return {
        "curve": "bn254", "numPubInputs": PUBLIC_COUNT, "version": "snarkjs-groth16",
        "alphaG1": g1(document["vk_alpha_1"]), "betaNegG2": g2(document["vk_beta_2"], negate=True),
        "gammaNegG2": g2(document["vk_gamma_2"], negate=True), "deltaNegG2": g2(document["vk_delta_2"], negate=True),
        "ic": [g1(point) for point in document["IC"]],
    }


def runar_proof(raw):
    document = json.loads(raw)
    require_bn254(document)
    return {"A": list(g1(document["pi_a"]).values()), "B": list(g2(document["pi_b"]).values()),
            "C": list(g1(document["pi_c"]).values())}


class ScriptVerifier:
    def __init__(self, adapter, verification_key, directory):
        self.adapter = str(Path(adapter).resolve())
        self.directory = Path(directory).resolve()
        self.adapter_key = json.dumps(runar_key(verification_key), sort_keys=True)
        self.key_digest = sha256(verification_key).hexdigest()

    def emit(self, signals, proof=None):
        with TemporaryDirectory(prefix="runar-", dir=self.directory) as temporary:
            key_path = Path(temporary) / "vk.json"
            key_path.write_text(self.adapter_key, encoding="utf-8")
            request = {"VK": str(key_path), "Public": signals, "Proof": proof}
            return bytes.fromhex(json.loads(checked([self.adapter], stdin=json.dumps(request))))

    def compile(self, signals, owner):
        if not is_compressed_public_key(owner):
            raise ValueError("owner must be a valid compressed secp256k1 public key")
        template = self.emit(signals)
        prefix = asm("OP_0 OP_CHECKSIGVERIFY")
        if not template.startswith(prefix):
            raise ValueError("unexpected owner constructor slot in Rúnar artifact")
        return authorize(owner) + template[len(prefix):]

    def witness(self, signals, proof):
        return self.emit(signals, runar_proof(proof))

    def artifact(self, signals, owner, script):
        artifact = {
            "project": PROJECT_NAME, "schema_version": 1, "proof_system": "groth16", "curve": "bn254",
            "required_era": "chronicle",
            "runar_revision": RUNAR_REVISION, "verification_key_sha256": self.key_digest,
            "public_signals": signals, "owner_public_key": owner.hex(), "script_hex": script.hex(),
            "sighash": f"{FLAG:02x}", "script_bytes": len(script), "script_sha256": sha256(script).hexdigest(),
        }
        return {**artifact, "artifact_sha256": artifact_digest(artifact)}


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--runar", type=Path, required=True, help="path to the pinned Rúnar checkout")
    cli.add_argument("--go", default="go")
    cli.add_argument("--verification-key", type=Path, required=True, help="snarkjs verification_key.json")
    cli.add_argument("--public", type=Path, required=True, help="trusted expected public signals as a JSON array")
    cli.add_argument("--owner", required=True, help="compressed secp256k1 public key in hex")
    cli.add_argument("--output", type=Path, required=True)
    cli.add_argument("--proof", type=Path, help="snarkjs proof.json for the pinned public signals")
    cli.add_argument("--witness-output", type=Path, help="write the push-only witness prefix in hex")
    args = cli.parse_args()
    if bool(args.proof) != bool(args.witness_output):
        cli.error("--proof and --witness-output must be supplied together")
    if args.witness_output and args.witness_output.resolve() == args.output.resolve():
        cli.error("artifact and witness need separate output paths")
    try:
        with TemporaryDirectory(prefix="4thgraph-groth16-") as temporary:
            adapter = Path(temporary) / "adapter"
            build_adapter(args.runar, adapter, go=args.go)
            verifier = ScriptVerifier(adapter, args.verification_key.read_bytes(), temporary)
            signals, owner = public_signals(args.public.read_bytes()), bytes.fromhex(args.owner)
            script = verifier.compile(signals, owner)
            artifact = verifier.artifact(signals, owner, script)
            witness = verifier.witness(signals, args.proof.read_bytes()) if args.proof else None
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(artifact, indent=2) + "\n")
        if witness is not None:
            args.witness_output.parent.mkdir(parents=True, exist_ok=True)
            args.witness_output.write_text(witness.hex() + "\n")
    except (OSError, ValueError, KeyError, TypeError) as error:
        cli.error(str(error))


if __name__ == "__main__":
    main()
