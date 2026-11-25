"""Compile P2PKH-SM2 from literal group arithmetic and unrolled SM3."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[3]))
from shared.script import assemble as assemble_blocks, push
from sm2 import A,B,G,USER_ID,be32
from sm3_script import IV,compress,hash_script


TEMPLATE_VERSION = 1


def assemble(owner, version=TEMPLATE_VERSION):
    if version != TEMPLATE_VERSION:
        raise ValueError("unsupported P2PKH-SM2 template version")
    return assemble_blocks(Path(__file__).with_name('asm'), owner, sm3_blocks())


def sm3_blocks():
    prefix=(8*len(USER_ID)).to_bytes(2,'big')+USER_ID+be32(A)+be32(B)+be32(G[0])+be32(G[1])
    state=compress(compress(IV,prefix[:64]),prefix[64:128])
    return {
        'ZA_TAIL':push(prefix[128:]),
        'SM3_ZA':hash_script(82,state,128,compact=True),
        'SM3_MESSAGE':hash_script(64,compact=True),
    }
