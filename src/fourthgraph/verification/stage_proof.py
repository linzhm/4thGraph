"""Spend-time evidence for typed state and route stages."""

from hashlib import file_digest, sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from fourthgraph.bsv.evaluate import evaluate as evaluate_script
from fourthgraph.bsv.script import asm, encode_num, number, push
from fourthgraph.bsv.transaction import hash256
from fourthgraph.compiler.source import evaluate
from fourthgraph.verification.bls12381.build import ForthVerifier
from fourthgraph.verification.bls12381.verifier import AFFINE_BYTES, Dynamic, PACKET_BYTES, public_packet
from fourthgraph.verification.circuit_backend import emit_stage_circuit
from fourthgraph.verification.circuit_tools import CircuitBuild, SNARKJS_PACKAGE
from fourthgraph.verification.proof_contract import AssignmentScript
from fourthgraph.verification.r1cs import VerificationKey
from fourthgraph.workflow.cpn import canonical
from fourthgraph.workflow.protocol import BINDING_CODE, copy_preimage, field

DOMAIN = b"4thGraph/stage-bind/v1\0"
GROTH16 = "groth16-bls12-381"
TRANSPARENT = "r1cs"
VERIFIER_SOURCE = b"REQUIRE stdlib/groth16-bls12-381.fth\n"


class StageProof:
    def __init__(self, stage, directory, backend, setup=None):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        source, self.public = emit_stage_circuit(stage)
        self.stage, self.backend = stage, backend
        self.output_width = 1 if self.public[0] == "route" else 4
        self.sources = tuple(Dynamic(width) for width in (
            1 if self.output_width == 1 else 32, 32, 128, 128,
            *([32] * (len(self.public) - 4))))
        self.statement = {
            "stage": stage.name, "word": stage.word.name, "circuit_source_sha256": sha256(source).hexdigest(),
            "input": stage.source.name, "output": stage.result.name,
            "witnesses": [(name.name, private) for name, private in stage.witnesses],
            "public": self.public, "sighash": "41", "encoding": "ordered little-endian scalars",
        }
        self.statement_sha256 = sha256(canonical(self.statement)).hexdigest()
        self.prefix = DOMAIN + bytes.fromhex(self.statement_sha256)
        self.circuit = CircuitBuild(
            source, directory, prime="bls12381" if backend == GROTH16 else "bn128",
            public_wires=tuple(f"main.{name}" for name in self.public),
        )

        self.circuit.run(SNARKJS_PACKAGE, "snarkjs", "r1cs", "export", "json", "counter.r1cs", "key.json")
        self.constraints = json.loads((self.circuit.directory / "key.json").read_bytes())["nConstraints"]

        if backend == GROTH16:
            if setup is None:
                raise ValueError("a matching Groth16 setup is required")
            self.zkey, ptau = map(Path, setup)
            self.circuit.run(SNARKJS_PACKAGE, "snarkjs", "zkey", "verify",
                             "counter.r1cs", str(ptau.resolve()), str(self.zkey.resolve()))
            self.circuit.run(SNARKJS_PACKAGE, "snarkjs", "zkey", "export", "verificationkey",
                             str(self.zkey.resolve()), "vk.json")
            raw = (self.circuit.directory / "vk.json").read_bytes()
            self.key_sha256 = sha256(raw).hexdigest()
            with self.zkey.open("rb") as handle:
                self.setup_sha256 = file_digest(handle, "sha256").hexdigest()
            self.verifier = ForthVerifier(raw, VERIFIER_SOURCE, witness_layout="projective")
            self.script = self.verifier.compile(self.sources)
            self.proof_widths = (PACKET_BYTES + AFFINE_BYTES,)
        elif backend == TRANSPARENT:
            if not stage.assignment_disclosure or stage.private or stage.policy == "require-zk":
                raise ValueError("transparent R1CS requires disclosure of the whole assignment")
            key = VerificationKey.load((self.circuit.directory / "key.json").read_bytes(),
                                       stage_inputs=len(self.public) - 1)
            self.verifier = key
            self.key_sha256 = key.sha256
            self.setup_sha256 = None
            layout = AssignmentScript(key, compact=True)
            # Save the packed public values, check all assignment wires, then
            # compare each public wire with the exact bytes consumed by PELS.
            code = asm("OP_TOALTSTACK") + layout.validate()
            code += b"".join(layout.constraint(*terms) for terms in key.constraints)
            code += asm("OP_FROMALTSTACK")
            offset = 0
            for index, source in enumerate(self.sources, 1):
                code += (asm("OP_DUP") + field(offset, source.width)
                         + push(b"\x00") + asm("OP_CAT OP_BIN2NUM")
                         + layout.wire(index, 2) + asm("OP_NUMEQUALVERIFY"))
                offset += source.width
            self.script = code + asm("OP_DROP") + layout.cleanup() + asm("OP_1")
            self.proof_widths = (32,) * layout.size
        else:
            raise ValueError(f"unsupported stage proof backend {backend!r}")

    @property
    def packet_bytes(self):
        return sum(source.width for source in self.sources)

    def binding_check(self):
        # Proof fields below this public packet survive the transaction checks.
        return (asm("OP_DUP") + field(self.output_width + 4, 32) + push(self.prefix)
                + copy_preimage() + asm("OP_CAT OP_HASH256 OP_EQUALVERIFY"))

    def placeholder(self):
        return tuple(bytes(width) for width in (*self.proof_widths, self.packet_bytes))

    def describe(self):
        return {
            "backend": self.backend, "statement": self.statement, "statement_sha256": self.statement_sha256,
            "verification_key_sha256": self.key_sha256, "setup_sha256": self.setup_sha256,
            "verifier_script_sha256": sha256(self.script).hexdigest(), "circuit": self.circuit.describe(),
            "constraints": self.constraints, "proof_field_widths": self.proof_widths,
            "public_packet_bytes": self.packet_bytes,
        }

    def prove(self, draft, vin, state, operands):
        result, = evaluate(self.stage.word, state, *operands)
        digest = hash256(self.prefix + draft.preimage(vin, BINDING_CODE))
        limbs = tuple(int.from_bytes(digest[i:i + 16], "little") for i in (0, 16))
        signals = (result, state, *limbs, *(value for value, (_, private) in
                    zip(operands, self.stage.witnesses, strict=True) if not private))
        inputs = dict(state=state, bindLo=limbs[0], bindHi=limbs[1],
                      **{f"witness{i}": value for i, value in enumerate(operands)})
        packet = public_packet(self.sources, signals)
        with TemporaryDirectory(dir=self.circuit.directory) as temporary:
            folder = Path(temporary)
            (folder / "input.json").write_text(json.dumps({name: str(value) for name, value in inputs.items()}))
            wasm = str(self.circuit.directory / "counter_js/counter.wasm")
            r1cs = str(self.circuit.directory / "counter.r1cs")
            run = self.circuit.run
            if self.backend == GROTH16:
                run(SNARKJS_PACKAGE, "snarkjs", "groth16", "fullprove", "input.json", wasm,
                    str(self.zkey.resolve()), "proof.json", "public.json", cwd=folder)
                if tuple(map(int, json.loads((folder / "public.json").read_bytes()))) != signals:
                    raise ValueError("Groth16 public signals differ from the draft")
                run(SNARKJS_PACKAGE, "snarkjs", "groth16", "verify", str(self.circuit.directory / "vk.json"),
                    "public.json", "proof.json", cwd=folder)
                witness = self.verifier.witness(signals, (folder / "proof.json").read_bytes(), sources=self.sources)
                (proof, encoded), alt = evaluate_script(witness)
                if alt or encoded != packet:
                    raise ValueError("unexpected Groth16 witness packet")
                return proof, encoded
            run(SNARKJS_PACKAGE, "snarkjs", "wtns", "calculate", wasm, "input.json", "proof.wtns", cwd=folder)
            run(SNARKJS_PACKAGE, "snarkjs", "wtns", "check", r1cs, "proof.wtns", cwd=folder)
            run(SNARKJS_PACKAGE, "snarkjs", "wtns", "export", "json", "proof.wtns", "proof.json", cwd=folder)
            assignment = self.verifier.assignment((folder / "proof.json").read_bytes())
            if assignment[1:1 + len(signals)] != signals:
                raise ValueError("R1CS public signals differ from the draft")
            return (*map(encode_num, assignment[1:]), packet)
