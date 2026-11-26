"""The bundled 4thGraph Forth library and its public interfaces."""

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from pathlib import Path
from zipimport import zipimporter

ROOT = Path(__file__).parent
GROTH16_ENTRY = "groth16-bls12-381-verify"
LEGACY_GROTH16_ENTRY = "groth16-verify"


def p256_vocabulary():
    from shared.script import asm, number

    if __package__:
        from .wordsets import Primitive, script_word
    else:
        from wordsets import Primitive, script_word

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


def library_resource(name):
    if name == "std/groth16-bls12-381":
        return Path("groth16-bls12-381/verifier.fth")
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
    "std/u32": Library(ROOT / "stdlib/u32.fth", (
        Export("u32-inc", ("u32",), ("u32",), ("host", "script", "circom"),
               (Parameter("value", "u32", "Unsigned 32-bit integer"),),
               "Returns value plus one modulo 2^32 for every u32 input.", failure_mode="total"),
    )),
    "std/p2pk": Library(ROOT / "stdlib/p2pk.fth", (
        lock_export("p2pk-lock", "compressed-public-key", 33),
    )),
    "std/p2pkh": Library(ROOT / "stdlib/p2pkh.fth", (
        lock_export("p2pkh-lock", "public-key-hash", 20),
    )),
    "std/p256": Library(ROOT / "stdlib/p256.fth", (
        p256_export("p256-add", ("p", "b3", "x1", "y1", "z1", "x2", "y2", "z2")),
        p256_export("p256-double", ("p", "b3", "x", "y", "z")),
    )),
    "std/groth16-bls12-381": Library(ROOT / "groth16-bls12-381/verifier.fth", (GROTH16_VERIFY,), "groth16-bls12-381"),
    "std/verify": Library(ROOT / "stdlib/verify.fth", declarations=("relation:",)),
}


def read_library(name):
    if isinstance(__loader__, zipimporter):
        return __loader__.get_data(str(ROOT / library_resource(name)))
    return LIBRARIES[name].source.read_bytes()


def required_source(filename, directory):
    libraries = {library.source.resolve(): (name, library) for name, library in LIBRARIES.items()}
    path = (directory / filename).resolve()
    if path in libraries or path.is_file():
        return path, *libraries.get(path, (None, None))
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
