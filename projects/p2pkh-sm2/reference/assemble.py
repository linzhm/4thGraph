"""Compile the Forth P2PKH-SM2 lock with generated SM3 fragments."""
from functools import partial
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))
from fourthgraph.bsv.script import push
from fourthgraph.compiler.script_builder import ScriptBuilder
from fourthgraph.compiler.wordsets import script_word
from fourthgraph.stdlib import LIBRARIES, read_library
from sm2 import A,B,G,USER_ID,be32
from sm3_script import IV,compile_hash,compress,hash_script


TEMPLATE_VERSION = 1
SCHEDULED_TEMPLATE_VERSION = 2
TEMPLATE_VERSIONS = (TEMPLATE_VERSION, SCHEDULED_TEMPLATE_VERSION)
FORTH_LIBRARY = "std/wallet/p2pkh-sm2"


def assemble(owner, version=TEMPLATE_VERSION):
    return forth_compiler(owner, version).emit("sm2-lock", b"")


def forth_compiler(owner, version=TEMPLATE_VERSION):
    if len(owner) != 20:
        raise ValueError("expected a 20-byte owner hash")
    blocks = sm3_blocks(version=version)
    vocabulary = {"owner-hash": script_word("", "bytes", b"", lambda: owner)}
    for name, code in blocks.items():
        vocabulary[name.lower().replace("_", "-")] = script_word("", "script", b"", lambda code=code: code)
    return ScriptBuilder(read_library(FORTH_LIBRARY).decode("utf-8"),
                         source_path=LIBRARIES[FORTH_LIBRARY].source, vocabulary=vocabulary)


def sm3_blocks(*, version=TEMPLATE_VERSION, fragments=None):
    if version not in TEMPLATE_VERSIONS:
        raise ValueError("unsupported P2PKH-SM2 template version")
    scheduled = version == SCHEDULED_TEMPLATE_VERSION
    prefix=(8*len(USER_ID)).to_bytes(2,'big')+USER_ID+be32(A)+be32(B)+be32(G[0])+be32(G[1])
    state=compress(compress(IV,prefix[:64]),prefix[64:128])
    emit_hash = hash_script if fragments is None else partial(compile_hash, fragments=fragments)
    return {
        'ZA_TAIL':push(prefix[128:]),
        'SM3_ZA':emit_hash(82,state,128,compact=True,scheduled=scheduled),
        'SM3_MESSAGE':emit_hash(64,compact=True,scheduled=scheduled),
    }
