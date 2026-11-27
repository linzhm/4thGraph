"""Pinned Circom and snarkjs commands for experimental circuit fixtures."""

from hashlib import sha256
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from fourthgraph.verification.r1cs import VerificationKey

CIRCOM_PACKAGE, SNARKJS_PACKAGE = "circom2@0.2.22", "snarkjs@0.7.5"
PUBLIC_WIRES = ("main.next", "main.current", "main.bindLo", "main.bindHi")


class CircuitBuild:
    def __init__(self, source, directory, *, has_route=False, prime="bn128", public_wires=None):
        self.directory = Path(directory).resolve()
        self.prime = prime
        self.source = self.directory / "counter.circom"
        self.source_sha256 = sha256(source).hexdigest()
        self.source.write_bytes(source)
        self.run(CIRCOM_PACKAGE, "circom2", self.source.name, "--r1cs", "--sym", "--wasm", "--O1", "--prime", prime)
        self.public_wires = public_wires
        if self.public_wires is None:
            self.public_wires = ("main.next", "main.route", *PUBLIC_WIRES[1:]) if has_route else PUBLIC_WIRES
        rows = [line.split(",") for line in (self.directory / "counter.sym").read_text().splitlines()]
        public = tuple((int(row[1]), row[3]) for row in rows[:len(self.public_wires)])
        if public != tuple(enumerate(self.public_wires, 1)):
            raise ValueError(f"unexpected circuit public wire order {public}")

    def run(self, package, executable, *arguments, cwd=None):
        result = subprocess.run(["npx", "--yes", f"--package={package}", executable, *arguments],
                                cwd=self.directory if cwd is None else cwd, capture_output=True, text=True)
        if result.returncode:
            raise ValueError(f"{executable} {' '.join(arguments)} failed: {result.stdout}{result.stderr}")

    def describe(self):
        return {"circom": CIRCOM_PACKAGE, "snarkjs": SNARKJS_PACKAGE, "prime": self.prime,
                "public_wires": self.public_wires, "source_sha256": self.source_sha256,
                "r1cs_sha256": sha256((self.directory / "counter.r1cs").read_bytes()).hexdigest()}


class CircuitFixture(CircuitBuild):
    def __init__(self, source, directory, *, has_route=False):
        super().__init__(source, directory, has_route=has_route)
        self.run(SNARKJS_PACKAGE, "snarkjs", "r1cs", "export", "json", "counter.r1cs", "key.json")
        self.key = VerificationKey.load((self.directory / "key.json").read_bytes())

    def prove(self, *, current, binding):
        inputs = dict(current=str(current), bindLo=str(binding[0]), bindHi=str(binding[1]))
        with TemporaryDirectory(prefix="witness-", dir=self.directory) as temporary:
            folder = Path(temporary)
            (folder / "input.json").write_text(json.dumps(inputs))
            self.run(SNARKJS_PACKAGE, "snarkjs", "wtns", "calculate", str(self.directory / "counter_js/counter.wasm"),
                     "input.json", "proof.wtns", cwd=folder)
            self.run(SNARKJS_PACKAGE, "snarkjs", "wtns", "check", str(self.directory / "counter.r1cs"), "proof.wtns",
                     cwd=folder)
            self.run(SNARKJS_PACKAGE, "snarkjs", "wtns", "export", "json", "proof.wtns", "proof.json", cwd=folder)
            assignment = self.key.assignment((folder / "proof.json").read_bytes())
            start = self.key.current_wire
            if assignment[start:start + 3] != (current, *binding):
                raise ValueError("R1CS witness returned different public inputs")
            return assignment

    def describe(self):
        return {**super().describe(), "verification_key_sha256": self.key.sha256}
