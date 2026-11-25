"""Adapt CCTP lifecycle requests to the common snarkjs-format Python prover."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

from metal_ntt import MetalNtt
from portable_r1cs import R1CS, UnsatisfiedConstraint
from settlement_checkpoint import COMPANION_BYTES, META_BYTES
from prepared_lifecycle_wire import BODY_BYTES, DOMAIN, SUFFIX_BYTES
from python_prover import ZKey, prove, write_witness
from shared.transaction import hash256
from snarkjs_adapter import load_artifacts


POLICY_BYTES = 36 + 32 + 33 + 33
OUTPOINT_BYTES = 36
SLOT_BYTES = SUFFIX_BYTES + COMPANION_BYTES
BODY_START = POLICY_BYTES + 2 * (OUTPOINT_BYTES + META_BYTES)


def lifecycle_witness(wire, parents):
    if (len(wire) != len(DOMAIN) + BODY_START + BODY_BYTES or not wire.startswith(DOMAIN)
            or len(parents) != 2 * SLOT_BYTES):
        raise ValueError("invalid lifecycle statement or parent witness")
    data = wire[len(DOMAIN):]
    witness = bytearray(data[:POLICY_BYTES])
    for slot in range(2):
        point = POLICY_BYTES + slot * OUTPOINT_BYTES
        checkpoint = POLICY_BYTES + 2 * OUTPOINT_BYTES + slot * META_BYTES
        witness += data[point:point + OUTPOINT_BYTES]
        witness += data[checkpoint:checkpoint + META_BYTES]
        witness += parents[slot * SLOT_BYTES:(slot + 1) * SLOT_BYTES]
    witness += data[BODY_START:]
    digest = hash256(wire)
    return (int.from_bytes(digest[:16], "big"), int.from_bytes(digest[16:], "big")), witness


class LifecycleProver:
    """Serialize each CCTP witness in the standard .wtns format."""

    def __init__(self, zkey, circuit_path, shader, out):
        self.zkey, self.circuit_path, self.shader, self.out = zkey, circuit_path, shader, out

    def __enter__(self):
        with self.zkey.open("rb") as source:
            prepared = ZKey.read(source)
        self.key_data = prepared.verification_key()
        # Use the canonical encoding of the actual key shipped in the zkey.
        encoded = json.dumps(self.key_data, sort_keys=True, separators=(",", ":")).encode()
        self.pin = sha256(encoded).hexdigest()
        self.circuit = R1CS(self.circuit_path)
        try:
            if prepared.variables != self.circuit.wires or prepared.public + 1 != self.circuit.n_public:
                raise ValueError("the .zkey does not have the CCTP circuit's witness shape")
            if prepared.size != (1 << (self.circuit.rows + self.circuit.n_public - 1).bit_length()):
                raise ValueError("the .zkey does not have the CCTP circuit's proving domain")
            self.transform = MetalNtt(self.shader)
        except BaseException:
            self.circuit.close()
            raise
        self.key_data.update({"verifying_key_sha256": self.pin, "constraints": self.circuit.rows})
        return self

    def __exit__(self, *_):
        self.circuit.close()

    def prove(self, label, policy, openings, *, reject=False, statement=None):
        wire = policy.statement(openings) if statement is None else statement
        parents = b"".join(opening.private for opening in openings)
        started = perf_counter()
        public, private = lifecycle_witness(wire, parents)
        try:
            wires = self.circuit.solve(public, private)
        except UnsatisfiedConstraint as error:
            if not reject:
                raise
            return str(error)
        if reject:
            raise AssertionError(f"invalid lifecycle witness accepted by R1CS: {label}")
        with TemporaryDirectory(prefix="cctp-wtns-") as temporary:
            witness_file = Path(temporary) / "transaction.wtns"
            write_witness(witness_file, wires)
            del wires
            result = prove(self.zkey, witness_file, self.transform)

        signals_json = result["public_signals"]
        key, signals, proof = load_artifacts(result["key"], result["proof"], signals_json)
        if key != policy.key or signals != public:
            raise ValueError("proof does not match the deployed policy and the actual public statement")
        artifact = {**self.key_data, **result["proof"], "format": "CCTP prepared lifecycle snarkjs proof v1",
                    "statement": wire.hex(), "statement_digest": hash256(wire).hex(),
                    "public_signals": signals_json, "backend": "python-snarkjs-metal",
                    "prove_seconds": perf_counter() - started, "verify_seconds": result["timings"]["verify_seconds"]}
        with (self.out / f"{label}.json").open("x") as output:
            json.dump(artifact, output, indent=2)
            output.write("\n")
        return proof, artifact


def main():
    parser = argparse.ArgumentParser(description="Export the CCTP circuit or witness in the standard snarkjs format")
    parser.add_argument("--assignments", type=Path, required=True, help="prepared circuit assignment tape")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--r1cs-out", type=Path)
    action.add_argument("--wtns-out", type=Path)
    parser.add_argument("--statement", type=Path)
    parser.add_argument("--parents", type=Path)
    args = parser.parse_args()
    if args.wtns_out and (args.statement is None or args.parents is None):
        parser.error("--wtns-out requires --statement and --parents")
    circuit = R1CS(args.assignments)
    try:
        if args.r1cs_out:
            circuit.export(args.r1cs_out)
        else:
            public, private = lifecycle_witness(bytes.fromhex(args.statement.read_text()),
                                                bytes.fromhex(args.parents.read_text()))
            wires = circuit.solve(public, private)
            write_witness(args.wtns_out, wires)
    finally:
        circuit.close()


if __name__ == "__main__":
    main()
