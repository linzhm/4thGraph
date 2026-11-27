"""The bundled 4thGraph Forth library and its public interfaces."""

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from pathlib import Path
from zipimport import zipimporter

ROOT = Path(__file__).parent.parent
GROTH16_ENTRY = "groth16-bls12-381-verify"
LEGACY_GROTH16_ENTRY = "groth16-verify"
WALLET_BACKEND = "wallet-construction"


def p256_vocabulary():
    from fourthgraph.bsv.script import asm, number

    from fourthgraph.compiler.wordsets import Primitive, script_word

    integer = "script-int"

    def access(depth, move):
        takes = (integer,) * (depth + 1)
        gives = takes if move else (*takes, integer)
        code = number(depth) + asm("OP_ROLL" if move else "OP_PICK")

        def run(*values):
            return (*(values[1:] if move else values), values[0])

        return Primitive(takes, gives, code, run, "static Script stack depth")

    return {
        "int-nonzero?": script_word(integer, "cell", asm("OP_0NOTEQUAL OP_NEGATE"), lambda x: -int(x != 0)),
        **{f"int-{op}-{depth}": access(depth, op == "roll")
           for op in ("pick", "roll") for depth in range(2, 12)},
    }


@dataclass(frozen=True)
class Parameter:
    name: str
    type: str
    description: str


@dataclass(frozen=True)
class Export:
    name: str
    takes: tuple[str, ...]
    gives: tuple[str, ...]
    backends: tuple[str, ...]
    runtime_inputs: tuple[Parameter, ...]
    failure: str
    build_parameters: tuple[Parameter, ...] = ()
    transaction_context: tuple[Parameter, ...] = ()
    aliases: tuple[str, ...] = ()
    failure_mode: str = "abort"

    @property
    def names(self):
        return (self.name, *self.aliases)


@dataclass(frozen=True)
class Library:
    source: Path
    exports: tuple[Export, ...] = ()
    backend: str | None = None
    declarations: tuple[str, ...] = ()


def lock_export(name, parameter, width):
    return Export(name, ("bytes",), ("bytes",), ("host", "script"),
                  (Parameter(parameter, "bytes", f"Exactly {width} bytes"),),
                  f"An input width other than {width} bytes aborts construction.")


def p256_export(name, inputs):
    descriptions = ("Positive field modulus", "Three times curve coefficient b")
    descriptions += ("Projective coordinate",) * (len(inputs) - 2)
    operands = tuple(Parameter(operand, "script-int", description)
                     for operand, description in zip(inputs, descriptions, strict=True))
    return Export(name, ("script-int",) * len(inputs), ("script-int",) * 5, ("host", "script"), operands,
                  "Invalid numeric operations, including division by zero, abort evaluation.")


def wallet_library(module, entries, *, accumulator="bytes", parameters=()):
    exports = tuple(Export(entry, (accumulator,), (accumulator,), (WALLET_BACKEND,),
                           (Parameter("prefix", accumulator, "Serialized Script to extend"),),
                           "Invalid build inputs or missing Script fragments abort construction.",
                           tuple(Parameter(name, "build-input", description) for name, description in parameters))
                    for entry in entries)
    return Library(ROOT / library_resource(f"std/wallet/{module}"), exports, WALLET_BACKEND)


def script_fragment(name, runtime_inputs=(), *, takes=("script",), failure=""):
    return Export(name, takes, ("script",), (WALLET_BACKEND,), runtime_inputs, failure)


def library_resource(name):
    return Path("stdlib", name.removeprefix("std/") + ".fth")


GROTH16_VERIFY = Export(
    GROTH16_ENTRY, (), ("groth16-verified",), ("groth16-bls12-381",),
    (Parameter("proof", "groth16-proof", "Encoded BLS12-381 Groth16 proof"),
     Parameter("public-signals", "field-elements", "Spend-time slots in verification-key order"),
     Parameter("arithmetic-witness", "bytes", "Auxiliary packets for the selected layout")),
    "Malformed encodings, out-of-range signals, invalid points or an invalid pairing abort the spend.",
    (Parameter("verification-key", "groth16-verification-key", "Fixed at build time"),
     Parameter("input-sources", "public-input-layout", "Fixed values and spend-time slot bounds"),
     Parameter("witness-layout", "enum", "Projective or affine witness encoding"),
     Parameter("script-era", "enum", "Available Script opcodes")),
    aliases=(LEGACY_GROTH16_ENTRY,),
)


LIBRARIES = {
    "std/bsv": Library(ROOT / "stdlib/bsv.fth", (
        Export("verify", ("cell",), (), ("host", "script"), (Parameter("flag", "cell", "Assertion result"),),
               "A zero result aborts verification."),
    )),
    "std/u32": Library(ROOT / "stdlib/u32.fth", (
        Export("u32-inc", ("u32",), ("u32",), ("host", "script", "circom"),
               (Parameter("value", "u32", "Unsigned 32-bit integer"),),
               "Returns value plus one modulo 2^32 for every u32 input.", failure_mode="total"),
    )),
    "std/native-p2pk": Library(ROOT / "stdlib/native-p2pk.fth", declarations=("bytes-param:", "lock:")),
    "std/p2pk": Library(ROOT / "stdlib/p2pk.fth", (
        lock_export("p2pk-lock", "compressed-public-key", 33),
    )),
    "std/native-p2pkh": Library(ROOT / "stdlib/native-p2pkh.fth", declarations=("bytes-param:", "lock:")),
    "std/pels": Library(ROOT / "stdlib/pels.fth", declarations=("lock:",)),
    "std/p2pkh": Library(ROOT / "stdlib/p2pkh.fth", (
        lock_export("p2pkh-lock", "public-key-hash", 20),
    )),
    "std/p256": Library(ROOT / "stdlib/p256.fth", (
        p256_export("p256-add", ("p", "b3", "x1", "y1", "z1", "x2", "y2", "z2")),
        p256_export("p256-double", ("p", "b3", "x", "y", "z")),
    )),
    "std/script-fragments": Library(ROOT / "stdlib/script-fragments.fth", (
        script_fragment("script-pick-depth", takes=("script", "cell"),
                        failure="The spend stack must contain the selected depth."),
        script_fragment("script-save-depth", takes=("script", "cell"),
                        failure="The spend stack must contain the selected depth."),
        script_fragment("script-drop-pairs", takes=("script", "cell"),
                        failure="The spend stack must contain twice the build count."),
        script_fragment("script-restore-items", takes=("script", "cell"),
                        failure="The alternate stack must contain the build count."),
        script_fragment("script-reverse32", (Parameter("value", "bytes", "Exactly 32 bytes"),),
                        failure="Pass a 32-byte element."),
        script_fragment("script-uint256be", (Parameter("value", "bytes", "Exactly 32 bytes"),),
                        failure="Pass a 32-byte element."),
    ), WALLET_BACKEND),
    "std/secp256k1": Library(ROOT / "stdlib/secp256k1.fth", (
        script_fragment("secp256k1-field"),
        script_fragment("secp256k1-order"),
        script_fragment("secp256k1-gx"),
        script_fragment("secp256k1-gy"),
        script_fragment("secp256k1-reduce", (Parameter("integer", "script-int", "Value to reduce"),),
                        failure="The caller places the field prime at the bottom of the main stack."),
        script_fragment("secp256k1-endomorphism-x", (Parameter("x", "script-int", "Projective x coordinate"),),
                        failure="The caller places the field prime at the bottom of the main stack."),
        script_fragment("secp256k1-lambda-split", (Parameter("k", "script-int", "Scalar in [0, n]"),),
                        failure="The caller supplies a scalar in range. Leaves the two signed components."),
        script_fragment("secp256k1-lambda-split-with-order", (
            Parameter("k", "script-int", "Scalar in [0, n]"),
            Parameter("n", "script-int", "The secp256k1 group order"),
        ), failure="The caller supplies a scalar in range and the fixed group order. Leaves the two signed components."),
        script_fragment("secp256k1-add", (
            Parameter("left", "projective-point", "Three homogeneous ScriptNum coordinates"),
            Parameter("right", "projective-point", "Three homogeneous ScriptNum coordinates"),
        ), failure="The caller supplies valid points and the field prime at the bottom of the main stack."),
        script_fragment("secp256k1-add-affine", (
            Parameter("left", "projective-point", "Three homogeneous ScriptNum coordinates"),
            Parameter("right", "affine-point", "Two affine ScriptNum coordinates"),
        ), failure="The caller supplies valid points and the field prime at the bottom of the main stack."),
        script_fragment("secp256k1-double", (
            Parameter("point", "projective-point", "Three homogeneous ScriptNum coordinates"),
        ), failure="The caller supplies a valid point and the field prime at the bottom of the main stack."),
        script_fragment("secp256k1-scale-affine-pair", (
            Parameter("left", "affine-point", "Two secp256k1 coordinates"),
            Parameter("right", "affine-point", "Two secp256k1 coordinates"),
        ), failure="The caller places the field prime at the bottom. Returns both points on the curve with 3*b = 1."),
        script_fragment("secp256k1-scaled-add-with-field", (
            Parameter("left", "projective-point", "Three homogeneous coordinates on the scaled curve"),
            Parameter("right", "projective-point", "Three homogeneous coordinates on the scaled curve"),
        ), takes=("script", "cell"),
                        failure="Supply valid points on the scaled curve. Field placement 0 uses stack bottom and 1 uses the slot below the points."),
        script_fragment("secp256k1-scaled-add-affine-with-field", (
            Parameter("left", "projective-point", "Three homogeneous coordinates on the scaled curve"),
            Parameter("right", "affine-point", "Two affine coordinates on the scaled curve"),
        ), takes=("script", "cell"),
                        failure="Supply valid points on the scaled curve. Field placement 0 uses stack bottom and 1 uses the slot below the points."),
        script_fragment("secp256k1-scaled-double-with-field", (
            Parameter("point", "projective-point", "Three homogeneous coordinates on the scaled curve"),
        ), takes=("script", "cell"),
                        failure="Supply a valid point on the scaled curve. Field placement 0 uses stack bottom and 1 uses the slot below the point."),
        script_fragment("secp256k1-scaled-double-pair-with-field", (
            Parameter("point", "projective-point", "Three reduced homogeneous coordinates on the scaled curve"),
        ), takes=("script", "cell"),
                        failure="Supply a valid point on the scaled curve. Field placement 0 uses stack bottom and 1 uses the slot below the point."),
    ), WALLET_BACKEND),
    "std/bip340": Library(ROOT / "stdlib/bip340.fth", (
        script_fragment("bip340-verify", (
            Parameter("message", "bytes", "BIP340 message of any supported length"),
            Parameter("public-x", "bytes", "32-byte x-only public key"),
            Parameter("public-y", "bytes", "32-byte even public y coordinate"),
            Parameter("signature", "bytes", "64-byte BIP340 signature"),
            Parameter("nonce-y", "bytes", "32-byte even nonce y coordinate"),
        ), failure="An invalid witness or signature aborts. A valid signature leaves one true item."),
    ), WALLET_BACKEND),
    "std/groth16-bls12-381": Library(ROOT / library_resource("std/groth16-bls12-381"), (GROTH16_VERIFY,), "groth16-bls12-381"),
    "std/verify": Library(ROOT / "stdlib/verify.fth", declarations=("relation:",)),
    "std/wallet/r1": wallet_library("r1", ("r1-lock",), accumulator="script", parameters=(
        ("owner-hash", "20-byte P-256 public-key hash"), ("optimize", "Select the R1 doubling rewrite"),
    )),
    "std/wallet/p2pkh-r1-deferred": wallet_library("p2pkh-r1-deferred", ("deferred-lock",), parameters=(
        ("owner-and-value", "Owner hash and satoshi amount"),
        ("target-and-binding", "Computed R1 output commitments and R1 binding blocks"),
    )),
    "std/wallet/p2pkh-sm2": wallet_library("p2pkh-sm2", ("sm2-lock",), accumulator="script", parameters=(
        ("owner-hash", "20-byte SM2 public-key hash"), ("sm3", "ZA prefix and SM3 Script fragments"),
        ("signed-residues?", "Select signed intermediate point coordinates"),
        ("compiled-points?", "Select the supplied compiled point kernels"),
        ("signed-windows?", "Select signed five-bit scalar windows"),
        ("window-doubling?", "Select the supplied five-doubling window kernel"),
        ("affine-generator?", "Select the supplied affine generator kernel and compact byte reversal"),
    )),
    "std/wallet/lamport-ots": wallet_library("lamport-ots", ("lamport-full-key", "lamport-committed-key"), parameters=(
        ("key", "Lamport public-key commitment or full-key verifier fragment"),
        ("binding", "Transaction authorization and input-binding fragments"),
    )),
    "std/wallet/wots-plus": wallet_library("wots-plus", ("wots-plus-lock",), parameters=(
        ("verifier", "WOTS+ Script for the selected public key and cache profile"),
        ("binding", "Transaction authorization and input-binding fragments"),
    )),
    "std/wallet/ml-dsa": wallet_library("ml-dsa", ("ml-dsa-lock",), parameters=(
        ("verifier", "Pure ML-DSA-44 arithmetic and SHAKE fragments for the selected public key"),
        ("binding", "Transaction authorization and input-binding fragments"),
    )),
}


def read_library(name):
    if isinstance(__loader__, zipimporter):
        return __loader__.get_data(str(ROOT / library_resource(name)))
    return LIBRARIES[name].source.read_bytes()


def required_source(filename, directory):
    if filename.casefold() == "bsv":
        library = LIBRARIES["std/bsv"]
        return library.source.resolve(), "std/bsv", library
    libraries = {library.source.resolve(): (name, library) for name, library in LIBRARIES.items()}
    path = (directory / filename).resolve()
    if path in libraries or path.is_file():
        return path, *libraries.get(path, (None, None))
    if filename == "groth16-bls12-381/verifier.fth":
        filename = str(library_resource("std/groth16-bls12-381"))
    bundled = (ROOT / filename).resolve()
    if bundled in libraries:
        return bundled, *libraries[bundled]
    raise FileNotFoundError("file was not found relative to the source or in the bundled library")


@dataclass(frozen=True)
class LibraryImport:
    name: str
    sha256: str
    interface_sha256: str | None


def describe_export(module, export):
    return {"module": module, **asdict(export)}


def describe_library(name, library):
    return {"exports": tuple(export.name for export in library.exports),
            "interfaces": {export.name: describe_export(name, export) for export in library.exports},
            "backend": library.backend or "typed-forth", "declarations": library.declarations}


def interface_digest(name, library):
    manifest = json.dumps(describe_library(name, library), sort_keys=True, separators=(",", ":"))
    return sha256(manifest.encode()).hexdigest()


def capabilities():
    return {name: {**describe_library(name, library), "interface_sha256": interface_digest(name, library)}
            for name, library in sorted(LIBRARIES.items())}
