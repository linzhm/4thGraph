"""Build BSV Script for a fixed BN254 Groth16 verification key and statement."""

import argparse
from contextlib import contextmanager
from dataclasses import asdict
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from fourthgraph.compiler.source import MAX_EXPANSION, PROJECT_NAME, CompileError, SourceCompiler, check_word_expansion, expanded
from fourthgraph.compiler.wordsets import Primitive, TYPES
from fourthgraph.verification.r1cs import FIELD, scalar
from fourthgraph.workflow.protocol import FLAG, artifact_digest, authorize, build_artifact, is_compressed_public_key
from fourthgraph.bsv.script import asm

RUNAR_REVISION = "dbcc4269f8e0895c4738cf86948b05b7d62a2010"
BASE_FIELD = 21888242871839275222246405745257275088696311157297823662689037894645226208583
PUBLIC_COUNT = 5
ADAPTER = Path(__file__).resolve().parent / "groth16_bn254_adapter.go"
RUNAR_EXTENSION = ADAPTER.parent / "runar"
RUNAR_FILES = ("compilers/go/codegen/bn254_groth16.go", "compilers/go/compiler/groth16_wa.go")
COMPACT_SUBGROUP = "projective-naf"
COMPACT_MODULO_THRESHOLD = 64


def checked(command, *, cwd=None, env=None, stdin=None):
    result = subprocess.run(command, cwd=cwd, env=env, input=stdin, capture_output=True, text=True, check=False)
    if result.returncode:
        raise ValueError(f"{Path(command[0]).name} failed: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout


@contextmanager
def runar_overlay(repository):
    repository = Path(repository).resolve()
    revision = checked(["git", "rev-parse", "HEAD"], cwd=repository).strip()
    if revision != RUNAR_REVISION or checked(["git", "status", "--porcelain", "-uno"], cwd=repository).strip():
        raise ValueError(f"expected an unmodified Rúnar checkout at {RUNAR_REVISION}")
    # Apply the verifier extension to copies of the two pinned source files.
    # Go overlays use those copies without editing the caller's checkout.
    with TemporaryDirectory(prefix="4thgraph-runar-overlay-") as temporary:
        directory = Path(temporary)
        files = {}
        for name in RUNAR_FILES:
            path = directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((repository / name).read_bytes())
            files[str(repository / name)] = str(path)
        checked(["git", "apply", "--unidiff-zero", str(RUNAR_EXTENSION / "compact_groth16.patch")], cwd=directory)
        for extension in RUNAR_EXTENSION.glob("*.go"):
            files[str(repository / "compilers/go/codegen" / extension.name)] = str(extension)
        overlay = directory / "overlay.json"
        overlay.write_text(json.dumps({"Replace": files}), encoding="utf-8")
        yield overlay, repository / "compilers/go", {**os.environ, "GOWORK": str(repository / "go.work")}


def build_adapter(repository, output, *, go="go"):
    with runar_overlay(repository) as (overlay, cwd, env):
        checked([go, "build", "-overlay", str(overlay), "-o", str(Path(output).resolve()), str(ADAPTER)], cwd=cwd, env=env)


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
        self.adapter_key = runar_key(verification_key)
        self.key_digest = sha256(verification_key).hexdigest()

    def emit(self, signals, proof=None, *, fixed_msm=False, compact_statement=False,
             compact_subgroup=COMPACT_SUBGROUP, modulo_threshold=COMPACT_MODULO_THRESHOLD):
        key = self.adapter_key
        if fixed_msm:
            key = {**key, "pinnedPublicInputs": dict(enumerate(signals))}
        with TemporaryDirectory(prefix="runar-", dir=self.directory) as temporary:
            key_path = Path(temporary) / "vk.json"
            key_path.write_text(json.dumps(key, sort_keys=True), encoding="utf-8")
            request = {"VK": str(key_path), "Public": signals, "Proof": proof}
            if compact_statement:
                request.update(CompactStatement=True, CompactSubgroup=compact_subgroup, ModuloThreshold=modulo_threshold)
            return bytes.fromhex(json.loads(checked([self.adapter], stdin=json.dumps(request))))

    @staticmethod
    def owner_guard(owner):
        if not is_compressed_public_key(owner):
            raise ValueError("owner must be a valid compressed secp256k1 public key")
        return authorize(owner)

    def compile_predicate(self, signals, *, fixed_msm=False, compact_statement=False):
        template = self.emit(signals, fixed_msm=fixed_msm, compact_statement=compact_statement)
        prefix = asm("OP_0 OP_CHECKSIGVERIFY")
        if not template.startswith(prefix):
            raise ValueError("unexpected owner constructor slot in Rúnar artifact")
        return template[len(prefix):]

    def compile(self, signals, owner):
        return self.owner_guard(owner) + self.compile_predicate(signals)

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



BN254_ENTRY = "verify-bn254-proof"
COMPACT_WORD = "bn254-compact-fixed-pairing"
BN254_WORDS = {
    "bn254-owner-guard": Primitive((), ("bn254-authority",), None,
                                   lambda verifier, _signals, owner: (verifier.owner_guard(owner),),
                                   "BIP143 owner authorization", build_only=True),
    "bn254-fixed-public-inputs": Primitive((), ("bn254-statement",), None,
                                           lambda _verifier, signals, _owner: (public_signals(json.dumps(signals)),),
                                           "compile-time public inputs", build_only=True),
    "bn254-msm-and-pairing": Primitive(("bn254-authority", "bn254-statement"), ("bn254-verified",), None,
                                       lambda verifier, _signals, _owner, guard, statement: (
                                           guard + verifier.compile_predicate(statement),
                                       ),
                                       "Rúnar Groth16 lock with bound public inputs", build_only=True),
    "bn254-fixed-msm-and-pairing": Primitive(("bn254-authority", "bn254-statement"), ("bn254-verified",), None,
                                             lambda verifier, _signals, _owner, guard, statement: (
                                                 guard + verifier.compile_predicate(statement, fixed_msm=True),
                                             ),
                                             "Rúnar Groth16 lock with a precomputed public-input MSM", build_only=True),
    COMPACT_WORD: Primitive(("bn254-authority", "bn254-statement"), ("bn254-verified",), None,
                            lambda verifier, _signals, _owner, guard, statement: (
                                guard + verifier.compile_predicate(statement, fixed_msm=True, compact_statement=True),
                            ), "fixed pairing terms and projective G2 subgroup check", build_only=True),
}
BN254_TYPES = TYPES | {kind for word in BN254_WORDS.values() for kind in (*word.takes, *word.gives)}


class ForthVerifier(ScriptVerifier):
    """Connect typed Forth build stages to the pinned BN254 backend."""

    def __init__(self, adapter, verification_key, directory, source, *, source_path=None):
        super().__init__(adapter, verification_key, directory)
        self.source = source
        frontend = SourceCompiler(source.decode("utf-8"), vocabulary=BN254_WORDS, stack_types=BN254_TYPES,
                                  backend="groth16-bn254", source_path=source_path)
        word = frontend.words.get(BN254_ENTRY)
        if word is None or (word.takes, word.gives) != ((), ("bn254-verified",)):
            raise CompileError(f"{BN254_ENTRY} requires the stack effect -- bn254-verified")
        check_word_expansion(word, MAX_EXPANSION)
        self.instructions = tuple(expanded(word.body))
        for instruction, token in self.instructions:
            if all(instruction is not stage for stage in BN254_WORDS.values()):
                raise token.error(f"{token.text!r} cannot build a BN254 verifier lock")
        self.libraries = frontend.library_imports
        self.compact_statement = any(instruction is BN254_WORDS[COMPACT_WORD]
                                     for instruction, _ in self.instructions)

    def compile(self, signals, owner):
        stack = []
        for instruction, _ in self.instructions:
            start = len(stack) - len(instruction.takes)
            stack[start:] = instruction.run(self, signals, owner, *stack[start:])
        return stack[0]

    def artifact(self, signals, owner, script):
        document = super().artifact(signals, owner, script)
        document.update(forth_entry=BN254_ENTRY, libraries=tuple(map(asdict, self.libraries)))
        if self.compact_statement:
            document.update(witness_layout="compact-fixed-statement", runar_extension_sha256={
                name: sha256((RUNAR_EXTENSION / name).read_bytes()).hexdigest()
                for name in ("compact_groth16.go", "compact_groth16.patch")
            })
            document.update(subgroup_schedule=COMPACT_SUBGROUP, modulo_threshold=COMPACT_MODULO_THRESHOLD)
        return build_artifact(document, self.source)

    def witness(self, signals, proof):
        return self.emit(signals, runar_proof(proof), compact_statement=self.compact_statement)


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--source", type=Path, help="typed BN254 Forth verifier source")
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
            key = args.verification_key.read_bytes()
            verifier = (ForthVerifier(adapter, key, temporary, args.source.read_bytes(), source_path=args.source)
                        if args.source else ScriptVerifier(adapter, key, temporary))
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
