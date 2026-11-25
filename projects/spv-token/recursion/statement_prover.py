"""Use a standard snarkjs key with a transaction-derived CCTP statement."""

from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

from circom_witness import calculate_witness
from metal_ntt import MetalNtt
from public_inputs import verification_key_point
from python_prover import ZKey, prove, write_witness
from snarkjs_adapter import load_artifacts, load_verification_key
from statement import public_inputs
from verifier import unlocking_fields, unlocking_script


class StatementProver:
    def __init__(self, zkey, wasm, shader, domain):
        self.zkey, self.wasm, self.domain = zkey, wasm, domain
        with zkey.open("rb") as source:
            prepared = ZKey.read(source)
        self.key_data = prepared.verification_key()
        if prepared.public != 2:
            raise ValueError("CCTP statement expects two public digest limbs")
        encoded = json.dumps(self.key_data, sort_keys=True, separators=(",", ":")).encode()
        self.key_digest = sha256(encoded).hexdigest()
        self.key = load_verification_key(self.key_data)
        self.transform = MetalNtt(shader)

    def prove(self, wire, output, **private_inputs):
        if not wire.startswith(self.domain):
            raise ValueError("wrong CCTP statement domain")
        public = public_inputs(wire)
        started = perf_counter()
        inputs = {"payload": list(wire[len(self.domain):]), "digestHigh": public[0], "digestLow": public[1]}
        if inputs.keys() & private_inputs.keys():
            raise ValueError("private witness data collides with the CCTP statement")
        inputs.update(private_inputs)
        with TemporaryDirectory(prefix="cctp-wtns-") as temporary:
            witness = Path(temporary) / "witness.wtns"
            write_witness(witness, calculate_witness(self.wasm, inputs))
            artifact = prove(self.zkey, witness, self.transform)
        key, signals, proof = load_artifacts(artifact["key"], artifact["proof"], artifact["public_signals"])
        if key != self.key or signals != public:
            raise ValueError("proof is bound to a different key or transaction statement")
        timing = artifact["timings"]
        evidence = {
            "proving_seconds": timing["prove_seconds"], "verify_seconds": timing["verify_seconds"],
            "total_proving_seconds": perf_counter() - started, "public_inputs": artifact["public_signals"],
            "verifying_key_sha256": self.key_digest,
        }
        with output.open("x") as stream:
            json.dump({**artifact, "statement": wire.hex(), **evidence}, stream, indent=2)
            stream.write("\n")
        point = verification_key_point(key.ic, signals) or (0, 0)
        fields = unlocking_fields(key, signals, proof, projective_g1=True, projective_g2=True)
        return unlocking_script((*point, *fields)), evidence


def add_prover_arguments(parser, *, required=True):
    for name in ("zkey", "wasm", "ntt-shader"):
        parser.add_argument(f"--{name}", type=Path, required=required)
