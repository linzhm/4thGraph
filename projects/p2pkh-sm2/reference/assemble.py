"""Compile the Forth P2PKH-SM2 lock with generated SM3 fragments."""
from functools import partial
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))
from fourthgraph.bsv.script import push
from fourthgraph.compiler.script_builder import ScriptBuilder, build_word
from fourthgraph.stdlib import LIBRARIES, read_library
from byte_fields import BYTE_KERNEL_NAMES
from point_kernels import AFFINE_KERNEL_NAME, CARRIED_KERNEL_NAMES, KERNEL_NAMES, WINDOW_KERNEL_NAME, load_kernels
from sm2 import A,B,G,USER_ID,be32
from sm3_script import IV,compile_hash,compress,hash_script


TEMPLATE_VERSION = 1
SCHEDULED_TEMPLATE_VERSION = 2
SIGNED_RESIDUE_TEMPLATE_VERSION = 3
PACKED_SM3_TEMPLATE_VERSION = 4
COMPILED_POINT_TEMPLATE_VERSION = 5
SPLIT_ROTATION_TEMPLATE_VERSION = 6
SIGNED_WINDOW_TEMPLATE_VERSION = 7
WINDOW_DOUBLING_TEMPLATE_VERSION = 8
AFFINE_GENERATOR_TEMPLATE_VERSION = 9
CARRIED_FIELD_TEMPLATE_VERSION = 10
TEMPLATE_PROFILES = {
    TEMPLATE_VERSION: "v1.0.0",
    SCHEDULED_TEMPLATE_VERSION: "v1.2.0",
    SIGNED_RESIDUE_TEMPLATE_VERSION: "v1.3.0",
    PACKED_SM3_TEMPLATE_VERSION: "v1.4.0",
    COMPILED_POINT_TEMPLATE_VERSION: "v1.5.0",
    SPLIT_ROTATION_TEMPLATE_VERSION: "v1.6.0",
    SIGNED_WINDOW_TEMPLATE_VERSION: "v1.7.0",
    WINDOW_DOUBLING_TEMPLATE_VERSION: "v1.9.0",
    AFFINE_GENERATOR_TEMPLATE_VERSION: "v1.10.0",
    CARRIED_FIELD_TEMPLATE_VERSION: "v1.11.0",
}
TEMPLATE_VERSIONS = tuple(TEMPLATE_PROFILES)
FORTH_LIBRARY = "std/wallet/p2pkh-sm2"
VERSION_DIRECTORY = Path(__file__).resolve().parents[1] / "versions"
POINT_KERNEL_FILE = VERSION_DIRECTORY / "v1.5.0/point-kernels.json"
WINDOW_KERNEL_FILE = VERSION_DIRECTORY / "v1.9.0/window-kernel.json"
AFFINE_KERNEL_FILE = VERSION_DIRECTORY / "v1.10.0/affine-kernel.json"
CARRIED_KERNEL_FILE = VERSION_DIRECTORY / "v1.11.0/window-kernels.json"
BYTE_KERNEL_FILE = VERSION_DIRECTORY / "v1.11.0/byte-kernels.json"


def assemble(owner, version=TEMPLATE_VERSION):
    return forth_compiler(owner, version).emit("sm2-lock", b"")


def forth_compiler(owner, version=TEMPLATE_VERSION):
    if len(owner) != 20:
        raise ValueError("expected a 20-byte owner hash")
    blocks = sm3_blocks(version=version)
    compiled_points = version >= COMPILED_POINT_TEMPLATE_VERSION
    window_doubling = version >= WINDOW_DOUBLING_TEMPLATE_VERSION
    affine_generator = version >= AFFINE_GENERATOR_TEMPLATE_VERSION
    carried_field = version >= CARRIED_FIELD_TEMPLATE_VERSION
    vocabulary = {
        "owner-hash": build_word("", "bytes", lambda: owner),
        "signed-residues?": build_word("", "cell", lambda: -int(version >= SIGNED_RESIDUE_TEMPLATE_VERSION)),
        "compiled-points?": build_word("", "cell", lambda: -int(compiled_points)),
        "signed-windows?": build_word("", "cell", lambda: -int(version >= SIGNED_WINDOW_TEMPLATE_VERSION)),
        "window-doubling?": build_word("", "cell", lambda: -int(window_doubling)),
        "affine-generator?": build_word("", "cell", lambda: -int(affine_generator)),
        "carried-field?": build_word("", "cell", lambda: -int(carried_field)),
        "packed-fields?": build_word("", "cell", lambda: -int(carried_field)),
    }
    for name, code in blocks.items():
        vocabulary[name.lower().replace("_", "-")] = build_word("", "script", lambda code=code: code)
    kernels = load_kernels(POINT_KERNEL_FILE) if compiled_points else dict.fromkeys(KERNEL_NAMES, b"")
    if window_doubling:
        kernels.update(load_kernels(WINDOW_KERNEL_FILE, (WINDOW_KERNEL_NAME,)))
    else:
        kernels[WINDOW_KERNEL_NAME] = b""
    if affine_generator:
        kernels.update(load_kernels(AFFINE_KERNEL_FILE, (AFFINE_KERNEL_NAME,)))
    else:
        kernels[AFFINE_KERNEL_NAME] = b""
    kernels.update(load_kernels(CARRIED_KERNEL_FILE, CARRIED_KERNEL_NAMES) if carried_field else
                   dict.fromkeys(CARRIED_KERNEL_NAMES, b""))
    kernels.update(load_kernels(BYTE_KERNEL_FILE, BYTE_KERNEL_NAMES) if carried_field else
                   dict.fromkeys(BYTE_KERNEL_NAMES, b""))
    for name, code in kernels.items():
        vocabulary[name] = build_word("", "script", lambda code=code: code)
    return ScriptBuilder(read_library(FORTH_LIBRARY).decode("utf-8"),
                         source_path=LIBRARIES[FORTH_LIBRARY].source, vocabulary=vocabulary)


def sm3_blocks(*, version=TEMPLATE_VERSION, fragments=None):
    if version not in TEMPLATE_VERSIONS:
        raise ValueError("unsupported P2PKH-SM2 template version")
    scheduled = version != TEMPLATE_VERSION
    packed = version >= PACKED_SM3_TEMPLATE_VERSION
    split_rotations = version >= SPLIT_ROTATION_TEMPLATE_VERSION
    stream_schedule = version >= WINDOW_DOUBLING_TEMPLATE_VERSION
    prefix=(8*len(USER_ID)).to_bytes(2,'big')+USER_ID+be32(A)+be32(B)+be32(G[0])+be32(G[1])
    state=compress(compress(IV,prefix[:64]),prefix[64:128])
    emit_hash = hash_script if fragments is None else partial(compile_hash, fragments=fragments)
    return {
        'ZA_TAIL':push(prefix[128:]),
        'SM3_ZA':emit_hash(82,state,128,compact=True,scheduled=scheduled,packed=packed,
                          split_rotations=split_rotations,stream_schedule=stream_schedule),
        'SM3_MESSAGE':emit_hash(64,compact=True,scheduled=scheduled,packed=packed,
                               split_rotations=split_rotations,stream_schedule=stream_schedule),
    }
