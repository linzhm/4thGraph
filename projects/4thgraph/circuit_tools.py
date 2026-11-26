"""Pinned Circom and snarkjs commands for experimental circuit fixtures."""

from hashlib import sha256
import json
from pathlib import Path
import subprocess

from proof_contract import VerificationKey

CIRCOM_PACKAGE, SNARKJS_PACKAGE = "circom2@0.2.22", "snarkjs@0.7.5"
PUBLIC_WIRES = ("main.next", "main.current", "main.bindLo", "main.bindHi")


class CircuitFixture:
    def __init__(self, source, directory, *, has_route=False):
        self.directory = Path(directory)
        self.source = self.directory / "counter.circom"
        self.source.write_bytes(source)
        self.run(CIRCOM_PACKAGE, "circom2", self.source.name, "--r1cs", "--sym", "--wasm", "--O1")
        self.public_wires = ("main.next", "main.route", *PUBLIC_WIRES[1:]) if has_route else PUBLIC_WIRES
        rows = [line.split(",") for line in (self.directory / "counter.sym").read_text().splitlines()]
        public = tuple((int(row[1]), row[3]) for row in rows[:len(self.public_wires)])
        if public != tuple(enumerate(self.public_wires, 1)):
            raise ValueError(f"unexpected circuit public wire order {public}")
        self.run(SNARKJS_PACKAGE, "snarkjs", "r1cs", "export", "json", "counter.r1cs", "key.json")
        self.key = VerificationKey.load((self.directory / "key.json").read_bytes())

    def run(self, package, executable, *arguments):
        result = subprocess.run(["npx", "--yes", f"--package={package}", executable, *arguments],
                                cwd=self.directory, capture_output=True, text=True)
        if result.returncode:
            raise ValueError(f"{executable} {' '.join(arguments)} failed: {result.stdout}{result.stderr}")

    def prove(self, *, current, binding):
        inputs = dict(current=str(current), bindLo=str(binding[0]), bindHi=str(binding[1]))
        (self.directory / "input.json").write_text(json.dumps(inputs))
        self.run(SNARKJS_PACKAGE, "snarkjs", "wtns", "calculate", "counter_js/counter.wasm", "input.json", "proof.wtns")
        self.run(SNARKJS_PACKAGE, "snarkjs", "wtns", "check", "counter.r1cs", "proof.wtns")
        self.run(SNARKJS_PACKAGE, "snarkjs", "wtns", "export", "json", "proof.wtns", "proof.json")
        return self.key.assignment((self.directory / "proof.json").read_bytes())

    def describe(self):
        return {"circom": CIRCOM_PACKAGE, "snarkjs": SNARKJS_PACKAGE, "public_wires": self.public_wires,
                "source_sha256": sha256(self.source.read_bytes()).hexdigest(),
                "r1cs_sha256": sha256((self.directory / "counter.r1cs").read_bytes()).hexdigest(),
                "verification_key_sha256": self.key.sha256}
